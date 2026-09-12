#!/usr/bin/env python3
"""A fake local agent that acknowledges a request and then fails to answer.

The hook's socket transport treats an AliveV1 acknowledgement as "an agent
owns this request" and then waits for a verdict until its own deadline. That
is the only way to hold the PAM helper in its wait long enough to interrupt
sudo from the terminal, so this listener speaks just enough of the socket
protocol to reach that state and then stops.

Two ways of stopping, one per scenario:

  default             hold the connection open and silent forever, so the
                      helper stays in its wait (scenario 10's ^C case);
  --close-after-ack   close the connection straight after the acknowledgement,
                      the agent-crash/restart shape (scenario 11).

It never approves anything: it has no key and sends no decision frame.
"""

import json
import os
import re
import socket
import struct
import sys
import threading
import time

ARGS = [argument for argument in sys.argv[1:] if argument != "--close-after-ack"]
CLOSE_AFTER_ACK = "--close-after-ack" in sys.argv[1:]
PATH = ARGS[0]
READY = ARGS[1] if len(ARGS) > 1 else None

try:
    os.unlink(PATH)
except FileNotFoundError:
    pass

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(PATH)
os.chmod(PATH, 0o666)
server.listen(8)
if READY:
    with open(READY, "w", encoding="utf-8") as handle:
        handle.write("listening\n")
print("stall agent listening", flush=True)


def serve(conn):
    try:
        header = b""
        while len(header) < 4:
            chunk = conn.recv(4 - len(header))
            if not chunk:
                return
            header += chunk
        (length,) = struct.unpack(">I", header)
        body = b""
        while len(body) < length:
            chunk = conn.recv(min(65536, length - len(body)))
            if not chunk:
                return
            body += chunk
        match = re.search(rb'"request_id"\s*:\s*"([^"]+)"', body)
        if not match:
            print("no request_id in envelope", flush=True)
            return
        request_id = match.group(1).decode("utf-8", "replace")
        alive = json.dumps(
            {"type": "alive", "version": 1, "request_id": request_id}
        ).encode("utf-8")
        conn.sendall(struct.pack(">I", len(alive)) + alive)
        print(f"acknowledged {request_id}; sending no verdict", flush=True)
        if CLOSE_AFTER_ACK:
            # An agent that took the request and then went away: a crash, a
            # restart, or a dropped connection. No decision bytes are ever
            # produced, so the hook must read this as a transport fault and
            # leave password fallback available.
            print(f"closing after acknowledging {request_id}", flush=True)
            return
        # Hold the connection open and silent, forever. The hook shuts down
        # its own write side as soon as the request is framed, so recv()
        # returns immediately at EOF; closing on that would end the wait this
        # scenario needs to keep open.
        while True:
            time.sleep(3600)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


while True:
    try:
        conn, _ = server.accept()
    except OSError:
        break
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
