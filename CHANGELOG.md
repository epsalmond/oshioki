# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The real sudo check now prints the browser approval URL on stderr, where the
  approval plugin forwards hook diagnostics, while keeping the command's
  stdout reserved for the approved command's output.
- `scripts/oshioki-phone-setup` generates NATS permission lists that now
  include `oshioki.ack.*` and `oshioki.delivery.*` for both the hook and
  server users. PR #57 (0.1.4) added the `oshioki.delivery.<request_id>`
  delivery receipt and its `oshioki.ack.<request_id>` companion, but this
  script's `_nats_config` still wrote the pre-#57 permission lists, so every
  phone/browser approval routed through a phone-setup NATS instance failed
  with `Permissions Violation for Publish to "oshioki.delivery.<id>"` on the
  server and a daemon delivery-receipt timeout on the hook.
  `docs/requirements.md`'s hand-written permission checklist is updated to
  match.

## [0.1.6] - 2026-09-10

### Added

- `scripts/test-sudo-plugin-container` now drives `sudo -n` through a
  deliberately hostile caller environment (a multi-line value, invalid
  UTF-8, an oversized entry, and a `BASH_FUNC_*` export) after the existing
  valid-verdict run, asserting that none of it reaches the approval payload
  the hook seals, and that a well-formed `OSHIOKI_SESSION` alongside the same
  junk still does. The previous real-sudo container test only ran sudo under
  `runuser` with a sterile environment, so it would never have caught #76.

### Fixed

- The approval plugin's `open()` callback no longer fails when the invoking
  user's environment holds a multi-line or non-UTF-8 variable. Since 0.1.5 it
  parsed `submit_envp` — the caller's whole pre-`env_reset` environment — with
  the strict parser used for the signed arrays, so a single unrelated entry
  (Woodpecker's multi-line `CI_COMMIT_MESSAGE`, for example) made `open()`
  return sudo's fatal result and every `sudo` from that environment died with
  `sudo: error initializing approval plugin approval_exec`. `submit_envp` is
  now walked leniently: entries that are not single-line valid UTF-8, or that
  carry no `=`, are skipped, and only `OSHIOKI_SESSION` is read out of it,
  still bounded by the same session-label validation as before. A malformed
  `OSHIOKI_SESSION` drops the label instead of denying the request. The strict
  parser is unchanged for `settings`, `user_info`, `command_info`, `run_argv`,
  and `run_envp`, which are signed and forwarded; nothing new is forwarded to
  the hook.

## [0.1.5] - 2026-09-10

### Added

- `RequestV1` carries an optional `session` field: the hook resolves the
  caller's session label on the host from an `OSHIOKI_SESSION` entry in
  the invoking user's own environment, and signs it as part of the
  request, rather than the agent guessing from `pid_chain` or the tty
  alone. The plugin reads `OSHIOKI_SESSION` from sudo's `open()` callback
  (the invoking user's environment before sudoers `env_reset` strips it),
  not from `check()`'s `run_envp` — `env_reset` (the sudoers default)
  removes it before the command executes, so a hook that only saw
  `run_envp` never saw the variable at all on a real host. The label
  crosses into the hook payload as `session.OSHIOKI_SESSION`, kept
  separate from the `env.*` entries that carry the post-`env_reset`
  execution environment. No agent-specific lookup ships in the product;
  `docs/configuration.md` documents `OSHIOKI_SESSION` as the one supported
  mechanism, with recipes (Claude Code, tmux, ssh) labelled as user-side
  shell configuration. Bounded to 64 printable, non-control characters.
  Compatibility: the field is `#[serde(default, skip_serializing_if =
  "Option::is_none")]`, so it serializes to nothing when absent and old
  signatures keep verifying unchanged; no type in this protocol sets
  `deny_unknown_fields`, so a 0.1.4 agent or server decoding a request from
  a 0.1.5 hook simply ignores the unknown field (it falls back to its
  existing `pid_chain`/tty resolution), and a 0.1.5 agent decoding a
  request from a 0.1.4 hook gets `None` and falls back the same way. Only
  the new label itself needs both the hook and the agent upgraded.

### Changed

- Touch ID sheet shows the session name and command again instead of the
  request id and hash. The session name prefers the request's resolved
  `session` field over the agent's own `pid_chain`/tty guesswork, and the
  `pid_chain` fallback now renders as `comm[pid]` (e.g. `claude[44930]`) so
  two concurrent agent sessions on the same host are distinguishable.
- The browser approval page (`/r/<id>`) shows a Session row when the
  request carries one.

### Removed

- The macOS pre-approval review dialog. It added a click before every Touch
  ID sheet, and the raw JSON it displayed was not useful to review in
  practice. Approval goes straight to Touch ID again.

## [0.1.4] - 2026-09-09

### Added

- `oshioki-phone-setup` configures phone enrollment. Tailscale Serve is the
  default for a local, supervised Oshioki server and NATS broker; users
  without Tailscale can point at an existing HTTPS server with host-role NATS
  credentials. Setup verifies readiness before touching host configuration
  and preserves existing devices and the local agent socket.
- macOS artifacts include the server and the phone setup helper; Debian
  packages include the helper.
- Browser requests receive a durable server delivery receipt after routing.
  The browser sends its authenticated opened receipt after decrypting and
  checking the request. Native agents send `AliveV1` before asking for a
  decision. Human browser opening time does not consume the short delivery
  wait.

### Changed

- `oshioki enroll` explains that it must run as root and checks its HTTPS
  endpoint before creating enrollment state. Localhost URLs give an
  actionable setup message; `--allow-localhost` permits local development.
- Phone services keep working across package upgrades, and macOS service
  bootstrap retries while a previous unload settles.
- The hook reports immediate progress on stderr: the command it is trying,
  transport failures, an unresponsive daemon, and the transition to waiting
  for approval. Socket and NATS connection, delivery, and receipt waits are
  bounded before the remaining approval deadline is used for the decision.
- On Linux, the sudo plugin races the hook with an interactive PAM password
  fallback. The installer’s `NOPASSWD` rule makes this fallback available
  when approval transport is unavailable; `sudo -n` skips password
  authentication and never reads a password terminal. Enter skips the
  password attempt without calling PAM.
- Upgrade the server, browser bundle, hook, and agent as one compatibility
  set. There is no rolling negotiation; mixed versions fail closed with an
  upgrade diagnostic. Existing request encryption and decision signatures
  remain compatible while native enrollment records now distinguish software
  keys from Secure Enclave keys.
- A socket agent that disconnects after acknowledging a request causes that
  sudo to be denied, including during an agent restart or laptop suspend.
  The hook does not retry that request through NATS.

### Fixed

- On macOS the audit trail reaches the unified log. The hook hands each
  record to logger(1); datagrams to the legacy syslog socket were accepted
  and then dropped, so nothing was kept.
- Explicit approval denials and invalid approval results fail closed even
  while the password attempt is running. Whichever branch wins cancels and
  reaps the other process, and restores terminal echo and pending input.
- The root-owned sudo plugin and hook now require a matching private framing
  handshake, including the complete environment attestation.

## [0.1.3] - 2026-09-07

### Changed

- The hook is quiet on an approved sudo. Approvals, denials, and a request
  left to NATS by the local agent go to the system log (`authpriv`, like
  sudo; `journalctl -t oshioki`), and only warnings and errors reach the
  terminal, on stderr. The sudo path takes its terminal level from
  `OSHIOKI_LOG` in `config.env`, never from the caller's environment;
  `OSHIOKI_LOG=info` restores the chatter for development and
  `OSHIOKI_LOG=audit=info` shows the audit trail there too.

### Fixed

- The agent keeps connecting to NATS in the background instead of giving up
  after one failed attempt at startup. After a reboot the VPN often comes up
  a minute after the LaunchAgent, which left every remote sudo timing out
  until the agent was restarted. Connection state is logged, and the default
  log level is now `info` so that log says so.

## [0.1.2] - 2026-09-06

Toward the 1.0 release. The v1 protocol and its three approval paths are
implemented and covered by the local end-to-end loop; production deployment
(OCI publication, CI, Homebrew/Debian packages) is deferred until the
protocol and local E2E stabilize.

### Added

- NATS JetStream request relay: the hook seals one exact sudo request per
  enrolled device, the server stores routing data plus opaque ciphertext in
  SQLite (WAL, single active server with one persistent database file) and
  relays verdicts, with idempotent redelivery and a transactional outbox
  that retries after restart.
- WebAuthn browser approvals: per-device sealed bodies served only to the
  device's own token, locally bundled browser UI, virtual-CTAP2 Playwright
  coverage, and HMAC-bound enrollment owned by the hook.
- Secure Enclave native approvals: `oshioki-agent` pairs with one enrollment
  URL, signs approvals directly with a P-256 key (Secure Enclave behind
  `biometryCurrentSet` on macOS, software key elsewhere), with Touch ID
  sheets, terminal prompts, fail-closed deadlines, and `run --auto` gated
  behind the `unattended` cargo feature for tests only.
- Sudo integration: `oshioki` hook binary plus `liboshioki_plugin.so` /
  `oshioki.dylib` approval plugin, with a prelaunch installer, supervised
  acceptance loops (`scripts/dev-acceptance`, including Mac approver over
  Tailscale), and production requirements for running it for real.
- Release packaging: amd64 `.deb` with systemd unit and postinst hooks, plus
  a Homebrew tap with bottles, published by CI from a version tag.
- Local agent socket: the hook can reach `oshioki-agent` over a Unix domain
  socket (`OSHIOKI_AGENT_SOCKET` in `config.env`) instead of NATS, so sudo
  approvals work with no network in the path. Socket-first with NATS fallback
  inside one shared approval deadline, and the agent starts without NATS to
  answer socket requests only. Verdicts stay signature-verified on both
  transports; only Secure Enclave approvals travel the socket.
- One-line laptop setup: `oshioki-laptop-setup` (shipped in the macOS
  artifact) writes `install.env`, applies the prelaunch install, enrolls and
  pairs the agent, installs the macOS LaunchAgent, and proves it with a real
  `sudo true`. On Linux it installs no unit — the agent approves through a
  terminal prompt, which a service manager cannot give it — and instead writes
  `agent.env` (shell-quoted, so a password holding spaces or shell
  metacharacters survives being sourced) and prints the one-liner that runs
  the agent on a terminal.
  Idempotent for post-upgrade re-runs; a unit left by an earlier version is
  disabled and removed. Without python3 the NATS reachability check uses
  `nc`, or bash's own TCP when there is no `nc` either.

### Changed

- Renamed to Oshioki with private identifiers scrubbed.
- Dual-licensed under MIT OR Apache-2.0.
