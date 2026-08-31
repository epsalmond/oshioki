#!/usr/bin/env python3
"""Mock NATS subscriber for the sudo-approve container E2E test.

Speaks just enough of the NATS text protocol to subscribe to
`sudo.request.>`, capture the JSON envelope published by the hook, unseal
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

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

SHARE = os.environ["SHARE_DIR"]
NATS_HOST = os.environ["NATS_HOST"]
NATS_PORT = int(os.environ["NATS_PORT"])
TIMEOUT = int(os.environ.get("TIMEOUT", "120"))


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
atomic_write(f"{SHARE}/box_pub.hex", pub_raw.hex().encode())
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
sock.sendall(f"CONNECT {conn}\r\nSUB sudo.request.> 1\r\nPING\r\n".encode())

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
    print("subscriber: timeout — no sudo.request MSG arrived", file=sys.stderr)
    sys.exit(1)

# --- Phase 3: unseal and emit ---
envelope = json.loads(payload)
print(f"subscriber: got envelope for host {envelope['header']['host']}", file=sys.stderr)

# Find the sealed body addressed to us.
mine = None
for body in envelope["sealed"]:
    # The hook fingerprint is the first 16 hex characters of box_pub,
    # corresponding to the first 8 raw key bytes.
    if body["device_fingerprint"] == pub_raw[:8].hex():
        mine = body
        break
if mine is None:
    print("subscriber: no sealed body matches our fingerprint", file=sys.stderr)
    sys.exit(1)

ephemeral_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(mine["ephemeral_pub"]))
shared = priv.exchange(ephemeral_pub)
cipher = ChaCha20Poly1305(shared)
plaintext = cipher.decrypt(
    bytes.fromhex(mine["nonce"]),
    bytes.fromhex(mine["ciphertext"]),
    None,
)
request = json.loads(plaintext)

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
print(f"subscriber: unsealed payload written for command={request['command']}", file=sys.stderr)
sys.exit(0)
