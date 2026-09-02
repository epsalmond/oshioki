#!/usr/bin/env python3
"""Mock NATS subscriber for the oshioki container E2E test.

Speaks just enough of the NATS text protocol to subscribe to
`oshioki.request.>`, capture the JSON envelope published by the hook, unseal
it with the device box key (generated here so the hook can enroll us),
and write the plaintext approval request to the shared volume for the
test harness to assert on.

Protocol reference: https://docs.nats.io/reference/reference-protocols/nats-protocol
"""

import base64
import json
import os
import socket
import sys
import tempfile
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SHARE = os.environ["SHARE_DIR"]
NATS_HOST = os.environ["NATS_HOST"]
NATS_PORT = int(os.environ["NATS_PORT"])
TIMEOUT = int(os.environ.get("TIMEOUT", "120"))
ORIGIN = os.environ.get("OSHIOKI_ORIGIN", "https://sudo.test")
RP_ID = os.environ.get("OSHIOKI_RP_ID", "sudo.test")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def atomic_write(path: str, data: bytes, mode: int = 0o644) -> None:
    """Write data beside path, then publish it with an atomic rename."""
    fd, temporary = tempfile.mkstemp(dir=SHARE, prefix=f".{os.path.basename(path)}.")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


# --- Phase 1: generate the device keypair and publish the public half ---
# The hook side waits for subscriber.ready, which is published only after the
# server has processed our SUB and replied to the following PING.
priv = X25519PrivateKey.generate()
pub = priv.public_key()
pub_raw = pub.public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
atomic_write(f"{SHARE}/box_pub.hex", b64url(pub_raw).encode())
# Private key as PEM so a human could re-decrypt if debugging.
atomic_write(
    f"{SHARE}/box_priv.pem",
    priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ),
    mode=0o600,
)

credential_priv = ec.generate_private_key(ec.SECP256R1())
credential_numbers = credential_priv.public_key().public_numbers()
credential_cose = (
    b"\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20"
    + credential_numbers.x.to_bytes(32, "big")
    + b"\x22\x58\x20"
    + credential_numbers.y.to_bytes(32, "big")
)
atomic_write(
    f"{SHARE}/credential_pub.b64",
    b64url(credential_cose).encode(),
)
credential_id = b"\x01\x02\x03"
fingerprint_hash = hashes.Hash(hashes.SHA256())
fingerprint_hash.update(b"oshioki/fingerprint/v1\x00")
fingerprint_hash.update(len(credential_id).to_bytes(8, "big"))
fingerprint_hash.update(credential_id)
fingerprint_hash.update(len(credential_cose).to_bytes(8, "big"))
fingerprint_hash.update(credential_cose)
fingerprint_hash.update(pub_raw)
fingerprint = b64url(fingerprint_hash.finalize()[:16])
atomic_write(f"{SHARE}/fingerprint", fingerprint.encode())

# --- Phase 2: subscribe over raw TCP ---
# The test server requires the same disposable credentials used by the hook.
sock = socket.create_connection((NATS_HOST, NATS_PORT), timeout=TIMEOUT)
sock.settimeout(TIMEOUT)
conn = json.dumps(
    {
        "verbose": False,
        "pedantic": False,
        "lang": "python",
        "version": "0.1",
        "user": os.environ.get("NATS_USER", "test"),
        "pass": os.environ.get("NATS_PASS", "test"),
    }
)
sock.sendall(f"CONNECT {conn}\r\nSUB oshioki.request.> 1\r\nPING\r\n".encode())

# NATS processes a connection in order. Seeing this PONG proves that the SUB
# immediately before PING is active, so the harness may safely invoke sudo.
deadline = time.time() + TIMEOUT
buf = b""
while time.time() < deadline:
    end = buf.find(b"\r\n")
    if end < 0:
        chunk = sock.recv(65535)
        if not chunk:
            break
        buf += chunk
        continue
    line = buf[:end].decode("utf-8", errors="replace")
    buf = buf[end + 2 :]
    if line == "PONG":
        atomic_write(f"{SHARE}/subscriber.ready", b"ready\n")
        break
    if line == "PING":
        sock.sendall(b"PONG\r\n")
    elif line.startswith("-ERR"):
        raise RuntimeError(f"NATS rejected subscriber: {line}")
else:
    print("subscriber: timeout waiting for NATS PONG", file=sys.stderr)
    sys.exit(1)

if not os.path.exists(f"{SHARE}/subscriber.ready"):
    print("subscriber: connection closed before NATS PONG", file=sys.stderr)
    sys.exit(1)

# The server may send INFO, PING, or MSG frames. Read until an MSG for our
# subscription arrives, or the hook timeout expires.
subject = None
payload = None
while time.time() < deadline:
    # MSG frames look like: MSG <subject> <sid> <len>\r\n<payload>\r\n
    while True:
        end = buf.find(b"\r\n")
        if end < 0:
            break
        line = buf[:end].decode("utf-8", errors="replace")
        rest = buf[end + 2 :]
        if line.startswith("MSG "):
            parts = line.split(" ")
            # MSG subj sid len
            length = int(parts[3])
            if len(rest) < length + 2:
                break
            subject = parts[1]
            payload = rest[:length]
            buf = rest[length + 2 :]
            break
        if line == "PING":
            sock.sendall(b"PONG\r\n")
        elif line.startswith("-ERR"):
            raise RuntimeError(f"NATS subscriber error: {line}")
        buf = rest
    if payload is not None:
        break
    chunk = sock.recv(65535)
    if not chunk:
        break
    buf += chunk

if payload is None:
    print("subscriber: timeout waiting for oshioki.request MSG", file=sys.stderr)
    sys.exit(1)

# --- Phase 3: unseal and emit ---
envelope = json.loads(payload)
print(f"subscriber: got envelope for host {envelope['host']}", file=sys.stderr)

# Find the sealed body addressed to us.
mine = None
for body in envelope["sealed"]:
    if body["device_fingerprint"] == fingerprint:
        mine = body
        break
if mine is None:
    print("subscriber: no sealed body matches our fingerprint", file=sys.stderr)
    sys.exit(1)

ephemeral_pub = X25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(mine["ephemeral_pub"] + "=="))
shared = priv.exchange(ephemeral_pub)
cipher = ChaCha20Poly1305(shared)
plaintext = cipher.decrypt(
    base64.urlsafe_b64decode(mine["nonce"] + "=="),
    base64.urlsafe_b64decode(mine["ciphertext"] + "=="),
    None,
)
request = json.loads(plaintext)

challenge_digest = hashes.Hash(hashes.SHA256())
challenge_digest.update(b"oshioki/approve/v1\x00")
challenge_digest.update(plaintext)
challenge = base64.urlsafe_b64encode(challenge_digest.finalize()).rstrip(b"=").decode()
client_data_json = json.dumps(
    {
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": ORIGIN,
        "crossOrigin": False,
    },
    separators=(",", ":"),
)

rp_id_digest = hashes.Hash(hashes.SHA256())
rp_id_digest.update(RP_ID.encode())
authenticator_data = rp_id_digest.finalize() + b"\x05\x00\x00\x00\x01"
client_data_digest = hashes.Hash(hashes.SHA256())
client_data_digest.update(client_data_json.encode())
signed_message = authenticator_data + client_data_digest.finalize()
signature = credential_priv.sign(signed_message, ec.ECDSA(hashes.SHA256()))

verdict = json.dumps(
    {
        "action": "approve",
        "version": 1,
        "request_id": request["request_id"],
        "device_fingerprint": fingerprint,
        "credential_id": b64url(credential_id),
        "authenticator_data": b64url(authenticator_data),
        "client_data_json": b64url(client_data_json.encode()),
        "signature": b64url(signature),
    },
    separators=(",", ":"),
).encode()
verdict_subject = f"oshioki.verdict.{request['request_id']}"
sock.sendall(
    f"PUB {verdict_subject} {len(verdict)}\r\n".encode() + verdict + b"\r\n"
)
sock.sendall(b"PING\r\n")
while True:
    line = sock.recv(65535)
    if b"PONG\r\n" in line:
        break
print(f"subscriber: published immediate verdict for id={request['request_id']}", file=sys.stderr)

approved = json.dumps(
    {
        "command": request["command"],
        "argv": request["argv"],
        "user": request["user"],
        "uid": request["uid"],
        "cwd": request["cwd"],
    }
).encode()
atomic_write(f"{SHARE}/approved_request.json", approved)
print("subscriber: unsealed payload written", file=sys.stderr)
sys.exit(0)
