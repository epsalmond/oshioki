# Oshioki

Oshioki (お仕置き): the sound of a keypress, and a pun on "punishment" for when
root misbehaves.

Oshioki asks an enrolled browser to approve one exact sudo request. The
hook encrypts the request for each enrolled browser. The server stores routing
data and ciphertext. A valid approval still requires the browser's WebAuthn
credential.

This repository owns the protocol, hook, sudo plugin, server, browser app, and
local test environment. Production deployment belongs to the consuming
infrastructure repository.

## Local loop

```bash
scripts/dev build
scripts/dev test --quick
scripts/dev test --browser
scripts/dev test
```

`scripts/dev test --quick` runs the Rust, browser-vector, and installer suites
on the host. `scripts/dev test --browser` runs the browser protocol against
local NATS and SQLite. `scripts/dev test` creates a disposable Compose project
and also invokes the real Linux sudo plugin path. Non-Linux hosts skip the
acceptance lifecycle test, which relies on Linux process identity.

The Compose browser test uses `https://sudo.test`. Chromium's virtual CTAP2
authenticator represents Touch ID or Face ID. It proves WebAuthn registration
and assertions, but it does not prove Apple hardware behavior.

Start a retained development server with:

```bash
scripts/dev up --state-dir ./tmp/dev-state
scripts/dev status
scripts/dev down
```

Without `--state-dir`, `up` creates disposable state and `down` removes it.
The server listens on `http://127.0.0.1:8443` in this development mode.
`scripts/dev` maps the server to the invoking user under rootful Docker and to
container UID 0 under rootless Docker. Direct Compose callers must set
`OSHIOKI_UID` to the host UID for rootful Docker or `0` for rootless
Docker.

Run a supervised Safari acceptance session on a Linux Tailscale host with:

```bash
scripts/dev-acceptance up
scripts/dev-acceptance enroll
scripts/dev-acceptance test
scripts/dev-acceptance status
scripts/dev-acceptance down
```

The command derives the WebAuthn origin from the host's Tailscale DNS name. It
runs isolated NATS and SQLite state on loopback and temporarily points
Tailscale Serve on HTTPS port 8443 at the local server, avoiding an existing
listener on 443. `up` requires an empty node-level Serve configuration because
the Tailscale service config commands cannot restore node routes. `down` resets
the acceptance route only when the live node config exactly matches what the
helper created. Otherwise it stops the services, retains the session, and asks
the operator to resolve the Serve state before retrying `down`. The acceptance
command does not install or enable the sudo plugin. Use `--state-dir PATH` with
`up` to retain browser enrollment across sessions. Serve mutations run through
`sudo`; Tailscale discovery, the server, NATS, and the hook remain under the
invoking user.

## Repository layout

- `protocol/` defines v1 messages, validation, sealing, and WebAuthn checks.
- `hook/` publishes requests and verifies enrollment and approval results.
- `plugin/` connects sudo's approval plugin ABI to the hook.
- `server/` contains the HTTP app, NATS relay, and SQLite state.
- `server/web/` contains the locally bundled browser UI and Playwright tests.
- `scripts/` contains the development loop, installer, and E2E runners.

SQLite is the server's local source of truth. It commits request ciphertext and
outbox work before the JetStream message is acknowledged. The expected runtime
is one active server with one persistent database file.

## Compatibility

The v1 cryptographic domain strings use `oshioki/...` values. Changing those
values would change the protocol and existing test vectors. The executable is
`oshioki`, and local hook state defaults to `/etc/oshioki`.

OCI publication and CI are outside the current iteration loop. Homebrew and
Debian packages will be designed after the protocol and local E2E stabilize.
