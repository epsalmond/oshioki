#!/usr/bin/env python3
"""Drive one sudo invocation through a PTY for the PAM acceptance test.

The fixture password is read from a file and typed into the PTY after the
prompt appears. It is never an argument, an environment variable, or part of
this driver's own output beyond whatever sudo echoes (sudo does not echo it).

Emits, after the captured transcript:
    PTY_RC=<exit code of the driven command>
    PTY_PROMPT=<number of sudo password prompts observed>
    PTY_ELAPSED_MS=<wall time of the driven command>
"""

import argparse
import os
import pty
import re
import select
import signal
import sys
import time

PROMPT = b"[sudo] password for"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--expect-prompt", choices=("yes", "no", "any"), default="any")
    parser.add_argument("--timeout", type=float, default=30.0)
    # Number of deliberately wrong passwords to type before the correct one.
    parser.add_argument("--wrong-first", type=int, default=0)
    # Never type anything; used for sudo -n and NOPASSWD cases.
    parser.add_argument("--no-password", action="store_true")
    # Send ^C this many seconds after the child starts. Typing continues
    # afterwards unless --no-password was given, so a case can measure what an
    # ignored interrupt costs and still let the command finish.
    parser.add_argument("--sigint-after", type=float, default=None)
    # How many ^C to send, and how far apart. More than one is needed to end
    # sudo from inside a PAM module's wait: cancelling device authentication
    # yields PAM_AUTHINFO_UNAVAIL, which the stack is configured to ignore, so
    # the first interrupt lands in the module and the stock pam_unix prompt it
    # falls through to needs an interrupt of its own -- exactly what a person
    # at the terminal does.
    parser.add_argument("--sigint-count", type=int, default=1)
    parser.add_argument("--sigint-interval", type=float, default=1.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command.pop(0)
    if not args.command:
        parser.error("missing command")

    # The file is in chpasswd form ("account:password"), so the account name
    # is stripped here rather than anywhere it could reach a command line.
    with open(args.password_file, "rb") as handle:
        password = handle.read().split(b":", 1)[1].strip()
    # A literal, not a mutation of the real password. Deriving it would put the
    # real secret inside the bytes this driver types, so a stack that echoed a
    # rejected attempt would leak it and the redaction check below would not
    # match the echoed form.
    wrong = b"incorrect-attempt-for-the-pam-acceptance-suite"
    assert wrong != password

    child, fd = pty.fork()
    if child == 0:
        os.execvp(args.command[0], args.command)

    output = bytearray()
    prompts_seen = 0
    typed = 0
    interrupts_sent = 0
    next_interrupt = args.sigint_after
    started = time.monotonic()
    status = None
    timed_out = False

    while time.monotonic() - started < args.timeout:
        ready, _, _ = select.select([fd], [], [], 0.05)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b""
            if chunk:
                output.extend(chunk)
        count = output.count(PROMPT)
        if count > prompts_seen:
            prompts_seen = count
            if not args.no_password:
                reply = wrong if typed < args.wrong_first else password
                os.write(fd, reply + b"\n")
                typed += 1
        if (
            next_interrupt is not None
            and interrupts_sent < args.sigint_count
            and time.monotonic() - started >= next_interrupt
        ):
            try:
                os.write(fd, b"\x03")
            except OSError:
                # The child already went away; nothing left to interrupt.
                next_interrupt = None
            else:
                interrupts_sent += 1
                next_interrupt += args.sigint_interval
        try:
            waited, child_status = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            break
        if waited == child:
            status = os.waitstatus_to_exitcode(child_status)
            break
    else:
        timed_out = True
        os.kill(child, signal.SIGKILL)
        _, child_status = os.waitpid(child, 0)
        status = os.waitstatus_to_exitcode(child_status)

    elapsed_ms = int((time.monotonic() - started) * 1000)

    # Drain whatever the child left in the pty before it exited.
    if not timed_out:
        drain_until = time.monotonic() + 0.5
        while time.monotonic() < drain_until:
            ready, _, _ = select.select([fd], [], [], 0.05)
            if not ready:
                break
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
    try:
        os.close(fd)
    except OSError:
        pass
    if status is None:
        _, child_status = os.waitpid(child, 0)
        status = os.waitstatus_to_exitcode(child_status)

    text = bytes(output)
    # Belt and braces: the password must never leave this process, even if a
    # future PAM stack echoes it.
    if password and password in text:
        text = text.replace(password, b"[redacted]")
        sys.stdout.buffer.write(text)
        print("\nPTY_SECRET_LEAK=1")
        return 11
    sys.stdout.buffer.write(text)
    print()
    if timed_out:
        print("PTY_TIMEOUT=1")
    print(f"PTY_RC={status}")
    print(f"PTY_PROMPT={prompts_seen}")
    print(f"PTY_ELAPSED_MS={elapsed_ms}")
    print(f"PTY_INTERRUPTS={interrupts_sent}")
    if timed_out:
        return 124
    expected = args.expect_prompt
    if expected == "yes" and prompts_seen == 0:
        print("PTY_ERROR=expected a sudo password prompt and saw none")
        return 10
    if expected == "no" and prompts_seen != 0:
        print("PTY_ERROR=a sudo password prompt appeared and none was expected")
        return 10
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
