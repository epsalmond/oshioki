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

`scripts/dev-acceptance mac` is the same session for a Mac approver. It binds
NATS to the host's tailnet IPv4 address instead of loopback, so the Mac can
reach it, then runs `enroll` and prints one line to paste on the Mac. See the
RUNBOOK.

## Repository layout

- `protocol/` defines v1 messages, validation, sealing, WebAuthn checks, and
  native (Secure Enclave) checks.
- `hook/` publishes requests and verifies enrollment and approval results.
- `plugin/` connects sudo's approval plugin ABI to the hook.
- `agent/` is the native approval agent (`oshioki-agent`): pairs a device
  with a host and answers sudo requests over NATS with a P-256 signature.
- `enclave/` holds the macOS Secure Enclave signer and the Touch ID sheet.
  Every `unsafe` call in the workspace is in this crate, and only on macOS.
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
submits the enrollment and waits for the host to activate it. On a Mac the
signing key is created in the Secure Enclave; everywhere else it is a P-256
key in that file. `pair --signer software` forces the software key on a Mac
too, which is what the tests use.

One identity serves every host this device pairs with, so pairing again
reuses it. A `--signer` that disagrees with the identity already there is an
error rather than a flag that did nothing. `pair --force` replaces the
identity: the device gets a new fingerprint, every host it had paired with
needs a new enrollment, and their old records should be revoked. `show` prints the fingerprint and which of
the two backends this device has.

`run` watches for sudo requests and prompts. A release build has no way
to skip the prompt: `run --auto approve` and `run --auto deny`, which decide
every request without asking, exist only when the agent is built with
`--features unattended`, as the Compose E2E does.
The terminal prompt and the browser page render the same request: the host, the
invoking user with their uid, the target account the command would run as
(`root (uid 0)` for sudo's default, otherwise the bare uid), the command, its
arguments, the working directory, and the caller process chain. An argument
that is empty or holds anything but plainly printable characters is shown in
shell single quotes, so one argument holding a space never reads as two.
A prompt nobody answers before the request expires publishes no verdict at
all, and the hook fails closed on its own deadline. The terminal prompt needs
a terminal: with stdin closed nothing could answer, so `run` stops rather than
leaving every request to time out. A Mac with an enclave key reads no stdin
and does not check this.

`enroll` pins the device locally and then confirms the server stored it by
reading `GET /api/v1/devices/<fingerprint>` back over HTTPS for up to fifteen
seconds. If that confirmation times out, the device is still pinned and can
approve sudo on the host; only the server's copy is unknown. The error says
so, and the fix is another `oshioki enroll` for that device once the server
is reachable.

The agent needs the same `NATS_URL` as the hook, plus `NATS_USER` and
`NATS_PASS` together where the server wants credentials; setting only one of
the pair is an error.

SQLite is the server's local source of truth. It commits request ciphertext and
outbox work before the JetStream message is acknowledged. The expected runtime
is one active server with one persistent database file.

## Mac approvals

On a Mac the Touch ID sheet is the approval. The signing key lives in the
Secure Enclave behind `biometryCurrentSet`, so the signature cannot exist
without the fingerprint, and there is no second confirmation to give. The
sheet reads "Oshioki is trying to run `<command and arguments>` as
`<account>` on `<host>`. Touch ID to allow this." The arguments are there
because `rm` and `rm -rf /` are different requests, rendered the same way the
terminal prompt renders them. The working directory and the caller process
chain go to the log, where there is room for them.

```bash
scripts/mac/bundle-agent
oshioki-agent pair '<enrollment-url>' --label mbp
scripts/mac/install-agent
```

`bundle-agent` wraps the binary in an unsigned `Oshioki.app`. The sheet takes
its title and icon from the calling process's bundle, so without it the sheet
shows the binary's file name and a generic badge. `install-agent` writes
`~/Library/LaunchAgents/dev.oshioki.agent.plist` and loads it. It runs as the
user, needs no sudo, and logs to `~/Library/Logs/oshioki-agent.log`.

Pairing signs an enrollment proof, so it shows one Touch ID sheet of its own.

Three timing rules sit around the sheet. Only one sheet is up at a time, so
two requests at once cannot race for the sensor. A locked screen raises no
sheet: the enclave reports a dismissed sheet and an absent operator
identically, and a sheet nobody sees would turn into a denial nobody made.
The request's deadline tears down a waiting sheet and publishes nothing, the
same rule the terminal prompt follows. Dismissing the sheet denies at once.

A key is bound to the fingerprints enrolled when it was made. Adding or
removing a fingerprint invalidates it for good. The agent logs that and asks
for a re-pair; it is not something a retry fixes.

The X25519 key that opens sealed requests stays a software key in the same
0600 file. The enclave holds P-256 and nothing else. The login keychain was
the original plan, and the spike found the Data Protection keychain closed to
bare CLIs without a provisioned entitlement, which the agent cannot carry
until it ships as a signed app (#5).

## Compatibility

The v1 cryptographic domain strings use `oshioki/...` values. Changing those
values would change the protocol and existing test vectors. The executable is
`oshioki`, and local hook state defaults to `/etc/oshioki`.

Records enrolled before the `secure-enclave` device kind still load: a device
record with no `kind` field is a `webauthn` one, in `devices.json` on the host
and in the server database alike, and an enrollment submission with no `kind`
is read the same way, so a browser page cached from before the change still
enrolls.

OCI publication and CI are outside the current iteration loop. Homebrew and
Debian packages will be designed after the protocol and local E2E stabilize.
