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
# Number of sudo invocations the harness will make against this subscriber
# before it exits. Defaults to 1 (the original single-request contract); the
# hostile-caller-environment case drives this subscriber through three sudo
# runs over one NATS connection and expects one output file per request.
REQUEST_COUNT = int(os.environ.get("REQUEST_COUNT", "1"))


def approved_request_path(index: int) -> str:
    """Output path for the index'th (1-based) approved request.

    The first request keeps the original filename so a single-request run
    (REQUEST_COUNT=1, the default) is byte-for-byte what it always was.
    """
    if index == 1:
        return f"{SHARE}/approved_request.json"
    return f"{SHARE}/approved_request.{index}.json"


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


# MSG frames (oshioki.request.> payloads) that arrived while we were reading
# for something else (a PONG, or a previous request's PONG) land here in
# order, so a later recv_one_request() call still sees them. With one
# sudo run per subscriber process this queue was never needed; with several
# runs sharing one NATS connection a second request's bytes can arrive
# interleaved with the first request's PING/PONG handshake.
pending_requests: list = []


def _pump_buffer():
    """Drain complete frames out of `buf`, queuing MSG payloads and
    answering PINGs, until no full line remains. Returns nothing; callers
    check `pending_requests` / send their own PONGs by watching `buf`
    themselves via the line they were looking for.
    """
    global buf
    while True:
        end = buf.find(b"\r\n")
        if end < 0:
            return
        line = buf[:end]
        rest = buf[end + 2 :]
        if line.startswith(b"MSG "):
            parts = line.decode("utf-8", errors="replace").split(" ")
            # MSG subj sid len
            length = int(parts[3])
            if len(rest) < length + 2:
                return  # incomplete frame; wait for more bytes
            pending_requests.append(rest[:length])
            buf = rest[length + 2 :]
            continue
        if line == b"PING":
            sock.sendall(b"PONG\r\n")
            buf = rest
            continue
        if line.startswith(b"-ERR"):
            raise RuntimeError(f"NATS subscriber error: {line.decode('utf-8', 'replace')}")
        if line == b"PONG":
            return  # let the PONG-waiter consume it; don't advance buf
        # Unrecognized line (e.g. +OK, INFO): skip it.
        buf = rest


def wait_for_pong():
    """Block until a PONG line arrives.

    Runs frames through `_pump_buffer` first so any MSG frame sitting ahead
    of the PONG in the stream is queued rather than dropped.
    """
    global buf
    while True:
        _pump_buffer()
        end = buf.find(b"\r\n")
        if end >= 0 and buf[:end] == b"PONG":
            buf = buf[end + 2 :]
            return
        chunk = sock.recv(65535)
        if not chunk:
            raise RuntimeError("connection closed while waiting for PONG")
        buf += chunk


def recv_one_request():
    """Block for the next oshioki.request MSG frame and return its payload.

    Shares `buf`/`pending_requests`/`deadline` across calls so a second or
    third sudo run on the same NATS connection is read correctly even if its
    bytes arrived while we were still processing a previous one.
    """
    global buf
    while time.time() < deadline:
        _pump_buffer()
        if pending_requests:
            return pending_requests.pop(0)
        chunk = sock.recv(65535)
        if not chunk:
            return None
        buf += chunk
    return None


def handle_one_request(index: int) -> None:
    """Receive, unseal, approve, and record request number `index` (1-based)."""
    payload = recv_one_request()
    if payload is None:
        print(
            f"subscriber: timeout waiting for oshioki.request MSG #{index}",
            file=sys.stderr,
        )
        sys.exit(1)

    envelope = json.loads(payload)
    print(
        f"subscriber: got envelope #{index} for host {envelope['host']}",
        file=sys.stderr,
    )

    # The acknowledgement is a liveness signal, not a verdict. Send it as
    # soon as the request is received, before unsealing or constructing the
    # approval.
    ack = json.dumps(
        {"type": "alive", "version": 1, "request_id": envelope["request_id"]},
        separators=(",", ":"),
    ).encode()
    ack_subject = f"oshioki.ack.{envelope['request_id']}"
    sock.sendall(f"PUB {ack_subject} {len(ack)}\r\n".encode() + ack + b"\r\nPING\r\n")
    wait_for_pong()

    # Find the sealed body addressed to us.
    mine = None
    for body in envelope["sealed"]:
        if body["device_fingerprint"] == fingerprint:
            mine = body
            break
    if mine is None:
        print(
            f"subscriber: no sealed body matches our fingerprint (request #{index})",
            file=sys.stderr,
        )
        sys.exit(1)

    ephemeral_pub = X25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(mine["ephemeral_pub"] + "==")
    )
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
    wait_for_pong()
    print(
        f"subscriber: published immediate verdict #{index} for id={request['request_id']}",
        file=sys.stderr,
    )

    # Surface the session label the same way the protocol documents it on
    # the wire (`session.OSHIOKI_SESSION=<value>`) rather than as a bare
    # JSON field, so the hostile-caller-environment case in
    # scripts/test-sudo-plugin-container can assert on it as plain text
    # alongside the "no junk bytes anywhere in the payload" check.
    session = request.get("session")
    approved = {
        "command": request["command"],
        "argv": request["argv"],
        "user": request["user"],
        "uid": request["uid"],
        "cwd": request["cwd"],
    }
    if session is not None:
        approved["session_line"] = f"session.OSHIOKI_SESSION={session}"
    atomic_write(approved_request_path(index), json.dumps(approved).encode())
    print(f"subscriber: unsealed payload #{index} written", file=sys.stderr)


for request_index in range(1, REQUEST_COUNT + 1):
    handle_one_request(request_index)

sys.exit(0)
