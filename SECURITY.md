# Security policy

Oshioki sits in the sudo approval path and handles keys and approvals.
Please treat it accordingly.

## Supported versions

Pre-1.0: only the current `main` branch receives security fixes. Once 1.0
ships, the two most recent minor releases will be supported.

## Reporting a vulnerability

Do **not** open a public issue or PR for a suspected vulnerability.

Use GitHub's private vulnerability reporting on this repository
(Security tab → Report a vulnerability). Include:

- What you think is affected (crate, endpoint, device kind).
- Steps to reproduce or a proof of concept.
- What an attacker gains and what they need (local user? enrolled device?
  network position?).

You will get an acknowledgement within 72 hours and a remediation plan once
the report is confirmed. Please give us a reasonable window to fix before any
public disclosure, and do not exfiltrate or retain other users' data while
investigating.

## Scope notes for reviewers

- Plaintext sudo commands must never enter SQLite, logs, notifications, or
  metrics. ntfy messages may carry host, user, request ID, and `/r/<id>` URL
  only.
- The server stores routing data and opaque ciphertext; it must never be able
  to produce an approval the hook accepts.
- Release agent builds must offer no prompt bypass: `run --auto` exists only
  under the `unattended` cargo feature.
- `unsafe` is confined to the `enclave` crate on macOS; new `unsafe`
  elsewhere will be rejected.
