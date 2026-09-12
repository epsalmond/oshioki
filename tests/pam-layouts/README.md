# `/etc/pam.d` layout fixtures

Stock and deliberately-broken PAM service files used by
`scripts/test-install-oshioki-hook` to exercise
`install-oshioki-hook --contextual-pam`, `--disable-contextual-pam` and
`--contextual-pam-status` without a real PAM stack. Each directory holds a
`pam.d/` tree that the test copies into a fake root.

Nothing here is loaded by PAM. These files exist so the installer's
fingerprint check, its exact post-edit bytes, and its refusals can be asserted
against the layouts real hosts actually ship.

## Provenance

| Fixture | Source |
| --- | --- |
| `ubuntu-24.04/` | `docker run --rm ubuntu:24.04` + `apt-get install -y sudo`, 2026-09-11, captured verbatim |
| `debian-12/` | `docker run --rm debian:12` + `apt-get install -y sudo`, 2026-09-11, captured verbatim |
| `debian-13/` | `docker run --rm debian:13` + `apt-get install -y sudo`, 2026-09-11, captured verbatim |
| `debian-13-sudo-i-include/` | `debian-13/` with a **synthetic** `sudo-i` that is `@include sudo` |
| `macos-14/` | `/etc/pam.d/sudo` and `sudo_local` checked byte-for-byte against macOS 15.7.5 (build 24G624) on 2026-09-12 UTC; fixture name retained for its macOS 14-era layout |
| `macos-15-no-sudo-local/`, `macos-15-pam-tid/` | **Synthetic**, based on the verified `macos-14/` pair; the missing-file and enabled-`pam_tid` variants were not captured from a Mac |
| `indented-include/`, `no-trailing-newline/`, `no-sudo-i/`, `refuse-indented-auth-*/`, `refuse-uppercase-auth/`, `refuse-continuation/` | **Synthetic**, derived from `ubuntu-24.04/` |
| `refuse-*/` | Derived from the stock fixture named in each section below |

Debian 12 and Debian 13 ship byte-identical `sudo` and `sudo-i`. Ubuntu 24.04
differs only by two `pam_env.so` session lines. On all three, `sudo-i` includes
`common-auth` directly rather than including `sudo`.

> **The base macOS pair is verified.** `macos-14/pam.d/sudo` and
> `macos-14/pam.d/sudo_local` are byte-identical to macOS 15.7.5 (build 24G624),
> checked on 2026-09-12 UTC (SHA-256
> `b1912a1ed6a83fb30136ac2a3c2ad856b597f079de591cf3d2a7dc0969cae86a` and
> `e6ed65e7629ca1d25eb1f5c2ddafe95dcb3fb100f901e8e5eba9a1555945534d`). The
> `macos-15-no-sudo-local` and `macos-15-pam-tid` variants remain synthetic;
> only their base layout is confirmed by that observation.

## Accept fixtures

- `ubuntu-24.04/`, `debian-12/`, `debian-13/` — stock Linux: zero `auth` lines
  and exactly one `@include common-auth` in each of `sudo` and `sudo-i`. The
  installer inserts its marker pair immediately above `@include common-auth` in
  both services.
- `debian-13-sudo-i-include/` — `sudo-i` is `@include sudo`, so it inherits the
  edit. The installer must skip it and say so in status, never edit it twice.
- `macos-14/` — stock `sudo` plus the stock (fully commented) `sudo_local`.
- `macos-15-no-sudo-local/` — `sudo_local` absent; the installer creates it.
- `macos-15-pam-tid/` — an administrator has enabled Touch ID. Our block is
  appended *after* the `pam_tid.so` line and that line is never rewritten.
- `indented-include/` — `  @include common-auth`. Linux-PAM strips leading
  whitespace, so this is the same directive; the insertion anchor must find it.
- `no-trailing-newline/` — `sudo` ends without a line terminator. Install and
  uninstall must round-trip it byte-identically rather than quietly adding one.
- `no-sudo-i/` — the host has no `sudo-i` service at all. Skipped with a note;
  an absent service file is not a customised one.

## Refusal fixtures

Each must leave every file byte-identical.

- `refuse-extra-auth/` — an extra `auth required pam_wheel.so` line in `sudo`.
  A stack with its own `auth` policy is not one we understand.
- `refuse-faillock/` — `pam_faillock.so preauth` in `sudo`. Inserting above
  `@include common-auth` would land after the preauth line and silently change
  lockout accounting.
- `refuse-two-common-auth/` — `sudo` includes `common-auth` twice. "Insert
  above the include" has no single answer.
- `refuse-foreign-module/` — a `liboshioki_pam.so` reference that is not inside
  our marker pair. Someone else owns that line; we do not adopt it.
- `refuse-macos-custom-sudo/` — an extra `pam_krb5.so` auth line in the macOS
  `sudo` stack, so the stock-`sudo` fingerprint no longer holds.
- `refuse-indented-auth-space/`, `refuse-indented-auth-tab/` — a
  space-indented `pam_faillock.so preauth` and a tab-indented
  `pam_wheel.so use_uid`. Both PAM implementations strip leading whitespace
  before parsing, so these are live second factors. A column-0 anchor would
  read the file as stock and insert our `success=done` block *after* them,
  disabling the factor on every sudo.
- `refuse-uppercase-auth/` — `AUTH required pam_wheel.so use_uid`. Linux-PAM
  compares the module type with `strcasecmp`, so this is a live auth line and
  a case-sensitive predicate would read the file as stock.
- `refuse-continuation/` — a comment ending in a backslash, which joins the
  `@include common-auth` line that follows it. Once a line is continued, the
  comment- and block-stripped view is no longer what PAM parses, so the
  installer refuses rather than guessing where the directive really is.
