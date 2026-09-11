#!/usr/bin/env python3
"""Run one fixture sudo command through a PTY without printing its password."""

import argparse
import os
import pty
import select
import signal
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--expect-prompt", choices=("yes", "no", "any"), required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command.pop(0)
    if not args.command:
        parser.error("missing command")

    with open(args.password_file, "rb") as handle:
        password = handle.read().rstrip(b"\r\n")

    child, fd = pty.fork()
    if child == 0:
        os.execvp(args.command[0], args.command)

    prompt = b"[sudo] password for"
    observed_prompt = False
    sent_password = False
    output = bytearray()
    started = time.monotonic()
    status = None
    try:
        while time.monotonic() - started < 15:
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                output.extend(chunk)
                if prompt in output:
                    observed_prompt = True
                    if not sent_password:
                        os.write(fd, password + b"\n")
                        sent_password = True
            waited, child_status = os.waitpid(child, os.WNOHANG)
            if waited == child:
                status = os.waitstatus_to_exitcode(child_status)
                break
        else:
            os.kill(child, signal.SIGTERM)
            _, child_status = os.waitpid(child, 0)
            status = os.waitstatus_to_exitcode(child_status)
            print("PTY_TIMEOUT=1")
            return 124

        if status is None:
            _, child_status = os.waitpid(child, 0)
            status = os.waitstatus_to_exitcode(child_status)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    expected_prompt = args.expect_prompt == "yes"
    print(f"PTY_RC={status}")
    print(f"PTY_PROMPT={int(observed_prompt)}")
    if args.expect_prompt != "any" and observed_prompt != expected_prompt:
        return 10
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
