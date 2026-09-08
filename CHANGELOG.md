# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-09-08

### Added

- Browser requests receive a durable server delivery receipt after routing.
  The browser sends its authenticated opened receipt after decrypting and
  checking the request. Native agents send `AliveV1` before asking for a
  decision. Human browser opening time does not consume the short delivery
  wait.

### Changed

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
