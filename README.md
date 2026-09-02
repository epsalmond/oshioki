# Oshioki

<p align="center"><img src="assets/oshioki.svg" alt="Oshioki logo" width="160"></p>

Oshioki (お仕置き): the sound of a keypress, and a pun on "punishment" for when
root misbehaves.

Oshioki asks an enrolled device to approve one exact sudo request. The hook
encrypts the request for each enrolled device. The server stores routing data
and ciphertext. A device is either a browser using WebAuthn or a native agent
signing directly with a Secure Enclave key.

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

- `protocol/` defines v1 messages, validation, sealing, WebAuthn checks, and
  native (Secure Enclave) checks.
- `hook/` publishes requests and verifies enrollment and approval results.
- `plugin/` connects sudo's approval plugin ABI to the hook.
- `agent/` is the native approval agent (`oshioki-agent`): pairs a device
  with a host and answers sudo requests over NATS with a P-256 signature.
- `server/` contains the HTTP app, NATS relay, and SQLite state.
- `server/web/` contains the locally bundled browser UI and Playwright tests.
- `scripts/` contains the development loop, installer, and E2E runners.

## Native agent

A native device signs approvals directly with a P-256 key instead of using a
browser and WebAuthn. Enroll one from the host:

```bash
oshioki enroll
```

`enroll` prints an enrollment URL and, below it, the `oshioki-agent` command
that consumes it. On the device:

```bash
oshioki-agent pair '<enrollment-url>' --label <label>
oshioki-agent run
```

`pair` creates a 0600 identity file (`agent.json`, under
`$OSHIOKI_AGENT_STATE` or `~/.config/oshioki` by default) on first use, then
submits the enrollment and waits for the host to activate it. `run` watches
for sudo requests and prompts on the terminal; `run --auto approve` and
`run --auto deny` decide every request without prompting, for tests only.
The agent needs the same `NATS_URL`, and optionally `NATS_USER` and
`NATS_PASS`, as the hook.

The current `oshioki-agent` binary uses a software P-256 key. It is the
Linux and test build of the macOS agent (issue #9), which will add a Secure
Enclave backend and a native prompt behind the same signing interface.

SQLite is the server's local source of truth. It commits request ciphertext and
outbox work before the JetStream message is acknowledged. The expected runtime
is one active server with one persistent database file.

## Compatibility

The v1 cryptographic domain strings use `oshioki/...` values. Changing those
values would change the protocol and existing test vectors. The executable is
`oshioki`, and local hook state defaults to `/etc/oshioki`.

No wire compatibility with records enrolled before the `secure-enclave`
device kind is kept. Upgrade the hook before the first native enrollment.

OCI publication and CI are outside the current iteration loop. Homebrew and
Debian packages will be designed after the protocol and local E2E stabilize.
