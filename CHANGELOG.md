# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `oshioki-laptop-setup` now raises exactly one Touch ID sheet per run on the
  contextual PAM lane, with or without a controlling terminal. `sudo` keys its
  timestamp ticket by tty when it has one and by parent pid when it does not,
  so a run over ssh or under `launchctl asuser` used to authenticate once per
  forked parent: reading eight keys out of `/etc/oshioki/install.env` through
  `$($SUDO cat ... | awk ...)` alone cost eight extra sheets (eleven
  authentications in all on a live Mac). `install.env` is now copied once,
  through a single top-level `sudo`, into a private 0600 temp file that every
  key is read from unprivileged, and the remaining privileged calls — the
  `--privileged-phase` re-invocation, the `install.env` write, the hook
  `status` probe — no longer sit inside a command substitution or a pipeline.

### Security

- `oshioki-laptop-setup` keeps every temp file it writes -- the `install.env`
  snapshot, the staged `install.env`, the values block, the privileged phase's
  report -- in one 0700 run-private directory removed by an EXIT trap, so a
  denied or cancelled sudo, or a Ctrl-C at the Touch ID sheet, can no longer
  orphan a world-readable-directory file holding `NATS_PASS`. `install.env`
  itself is now written through a root-owned `install -m 0600` sibling and an
  atomic `mv` rather than a `cp` that truncates the live file first.

### Changed

- The closing proof in `oshioki-laptop-setup` only announces a Touch ID prompt
  when the `sudo` it is about to run really will be a fresh authentication.
  With the install's ticket still live it says the proof rides the approval
  already given, and a run with no terminal says the ticket dies with the run.
  On that warm-ticket path the sudo never reaches PAM, so the closing line now
  claims only what it proved -- sudo works and the agent socket is live -- and
  reserves "approved through the agent socket" for a sudo that really
  authenticated.

## [0.1.12] - 2026-09-13

### Added

- The macOS release tarball now ships `Oshioki.app` beside the flat binaries,
  and the Homebrew formula installs it in the keg root, so a `brew` install
  gets the native approver with its icon without building anything. The
  bundle's inner binary is a copy of the flat `oshioki-agent` from the same
  build, ad hoc signed so `codesign --verify --deep --strict` passes after a
  bottle pour, and hashed in `SHA256SUMS` under
  `Oshioki.app/Contents/MacOS/oshioki-agent`.

### Changed

- `oshioki-laptop-setup` prefers the keg's bundled agent when it is present
  and verifies against `SHA256SUMS`, falling back to the flat binary for
  kegs from older releases. The flat binary is verified against its own
  manifest entry too, and a mismatch now stops the run instead of installing
  an unverified agent.

### Fixed

- The LaunchAgent plist now names the upgrade-stable `opt` path rather than
  the versioned `Cellar` path, including when an existing plist's
  credentials are preserved. `brew upgrade` followed by `brew cleanup`
  deletes the versioned directory, which left the agent unable to spawn at
  the next login.

## [0.1.11] - 2026-09-13

### Fixed

- `oshioki-laptop-setup`'s Mac agent NATS verification could declare success
  even when the agent was authenticating with the wrong role's credentials:
  the agent logs `NATS connected` before it subscribes, and a `Permissions
  Violation` server error for that subscription can arrive one poll later.
  The verify step now keeps polling for the rest of its timeout budget after
  seeing `NATS connected`, so a violation that lands right after is still
  caught. A non-numeric `OSHIOKI_AGENT_NATS_VERIFY_TIMEOUT` now falls back
  to the default instead of aborting the step.
- An `install.env` written by 0.1.10 or earlier, with no agent NATS keys and
  no existing LaunchAgent plist, used to leave the Mac agent socket-only
  with no warning at all: the install looked complete, but approvals from
  other hosts could never arrive. `oshioki-laptop-setup` now warns loudly
  when this happens and names the fix.
- A LaunchAgent plist mistakenly carrying the hook's own `NATS_USER` (the
  0.1.10 bug) was treated as a real, working device configuration to
  preserve, so the run only failed later at the NATS violation check --
  after the hook was already installed -- with a message that named neither
  `--reconfigure` nor the `OSHIOKI_AGENT_NATS_*` variables. Such a plist is
  now detected as broken and rewritten with the agent's own role, and the
  violation failure now names both.
- The Mac agent's own NATS credentials are no longer hard-required:
  `--yes` with none staged, and the interactive prompt answered blank, both
  now leave the agent socket-only (with the warning above) instead of
  aborting the whole setup.

### Added

- `OSHIOKI_AGENT_NATS_URL`, `OSHIOKI_AGENT_NATS_USER`, and
  `OSHIOKI_AGENT_NATS_PASS` env vars for staging the Mac agent's own NATS
  role non-interactively (see `RUNBOOK.md`).

## [0.1.10] - 2026-09-12

### Fixed

- `install-oshioki-hook` finds the hook, the sudo plugin and the PAM module
  the same way it already finds `SHA256SUMS`. From a Homebrew keg a bare
  `sudo install-oshioki-hook --contextual-pam` died with
  `PAM_MODULE_BIN is required` and a bare `--prelaunch` with
  `missing or unsafe build artifact: <keg>/target/release/oshioki`, so the
  manual flow the tap caveats describe needed environment variables the
  caveats never mentioned. `HOOK_BIN`, `PLUGIN_BIN` and `PAM_MODULE_BIN` now
  probe `target/release` for a checkout, the directory beside the installer
  for the `.deb` and an unpacked release tarball, and the keg's `libexec`
  last. The plugin is probed under both its build name and its installed
  name, since the tarball renames it and verification is by file name. An
  explicit variable still wins, and an unbuilt checkout still fails by naming
  `target/release`.
- `install-oshioki-hook --prelaunch-status` names the contextual PAM lane
  instead of reporting `disabled` on a host that is on it. A lane host has no
  plugin block in `sudo.conf` by design, and `--prelaunch` says so as it
  installs; answering `disabled` was a true statement about the plugin and a
  false one about the install. It made `oshioki-laptop-setup
  --contextual-pam` fail its own final verify and exit before it ever reached
  the migration it was asked for. The lane is only reported when the module
  the PAM entry references is actually there as a root-owned regular file: an
  entry naming a module that is missing is a degraded host, and it now reports
  `FAIL contextual PAM lane: entry present but module missing at <path>` and
  exits non-zero. A half-written managed block in `sudo.conf` is still named
  on a lane host, since that check now runs before the lane is considered.
  Off the lane the answer is unchanged, and `oshioki-laptop-setup
  --contextual-pam` treats a failing verify as something the migration below
  repairs rather than a reason to stop.
- `oshioki enroll` bounds its wait on the approval transport, the way `check`
  and `authenticate` already did. It prints nothing until the enrollment
  intent has been published, so a NATS host that blackholes rather than
  refusing turned a misconfiguration into a silent hang that
  `oshioki-laptop-setup` could only report as `enrollment produced no URL`.
  The connect and the publish now time out after 20s and name the server and
  the file to fix.
- `oshioki-laptop-setup` on macOS stops with a named cause when the login
  keychain is not available to the session, instead of reading that as "no
  agent identity", enrolling a device nobody asked for, and then dying on a
  Security framework string. The agent keeps its box secret in the login
  keychain, which only a graphical login session has unlocked, so running the
  setup over ssh or from a job with no session cannot read or create an
  identity. The error says to run it from a Terminal window on that Mac, or
  to unlock the keychain first.
- `oshioki-laptop-setup` says which of the two enrollment failures it hit:
  `oshioki enroll` exited without printing a URL (its own explanation is
  above), or it was still running when the poll window closed. The window is
  `OSHIOKI_ENROLL_URL_TIMEOUT` seconds, 60 by default, deliberately longer
  than the hook's own transport timeouts so the hook reports first.

## [0.1.9] - 2026-09-12

### Fixed

- `oshioki-laptop-setup` and `install-oshioki-hook` now resolve their own
  path through symlinks before deriving anything from it. Homebrew puts both
  on `PATH` as `/opt/homebrew/bin/<name>`, a symlink into the Cellar; `pwd -P`
  on the dirname resolves symlinked *directories* only, so the scripts took
  `/opt/homebrew/bin` for their install directory, missed
  `../libexec/SHA256SUMS`, and the documented
  `brew install ... && oshioki-laptop-setup --contextual-pam` died on
  `missing or unsafe build artifact: /opt/homebrew/target/release/oshioki`.
  Running the same command by its keg path worked, which is what made this
  look like a Homebrew problem. The walk is a plain `readlink` loop, since
  macOS ships no `readlink -f`. (#91)
- `install-oshioki-hook --contextual-pam-status` finds the `SHA256SUMS`
  shipped in its own keg or package instead of reporting
  `no SHA256SUMS manifest was found to verify it against` until
  `OSHIOKI_CHECKSUMS` was passed by hand. Install and status now share one
  resolver: `target/release/SHA256SUMS` in a repo checkout, `libexec` beside
  `bin` in a Homebrew keg, and the file next to the installer for the `.deb`
  and an unpacked release tarball. An explicit `OSHIOKI_CHECKSUMS` still
  wins, and a manifest that cannot be found is still a `FAIL`, not a skipped
  check. (#91)

## [0.1.8] - 2026-09-12

### Fixed

- Homebrew no longer rewrites the macOS dylibs out of agreement with the
  `SHA256SUMS` shipped beside them. `Keg#fix_dynamic_linkage` sets every
  dylib's `LC_ID_DYLIB` to the keg's `opt` path and ad hoc re-signs each file
  it modified, so a bottled `liboshioki_pam.dylib` and `oshioki.dylib` failed
  the checksum the release recorded and `install-oshioki-hook` refused to
  install them. Both are now linked with that exact install name up front
  (`pam/build.rs`, `plugin/build.rs`, overridable with
  `OSHIOKI_PAM_INSTALL_NAME` / `OSHIOKI_PLUGIN_INSTALL_NAME` for a non-default
  Homebrew prefix), which makes the fixup a no-op and leaves the shipped bytes
  intact. Neither id is used at load time: sudo and OpenPAM both `dlopen` by
  absolute path. `scripts/build-darwin-artifact` asserts both ids with
  `otool -D`, so a build that loses them fails instead of shipping a bottle
  that cannot verify. (#87)
- `oshioki-laptop-setup` no longer mistakes an existing
  `/etc/oshioki/install.env` for a missing one. The directory is root-owned
  0700, so the unprivileged `[ -f ]` that guarded step 1 returned false for a
  file that was there; the run then prompted for values it already had and
  overwrote a good config, or died with "WebAuthn origin has no default" under
  `--yes`. The probe now goes through `sudo`, the same way the script already
  reads the file. (#88)

## [0.1.7] - 2026-09-12

### Added

- Contextual sudo authentication through PAM, as an opt-in alternative to the
  approval plugin and its blanket `NOPASSWD` sudoers rule: a new
  `oshioki-pam` module (`liboshioki_pam.so`, `liboshioki_pam.dylib`) that asks
  the enrolled device from inside sudo's own PAM stack, the hook's
  `authenticate` verb and the NATS authentication lane behind it, and
  `scripts/install-oshioki-hook` modes `--contextual-pam`,
  `--disable-contextual-pam` and `--contextual-pam-status` to migrate, roll
  back and inspect a host. The `.deb` ships the module and the multiarch
  triplet it was built for and migrates on `OSHIOKI_CONTEXTUAL_PAM=1` in
  `/etc/oshioki/install.env`; `oshioki-laptop-setup --contextual-pam` is the
  macOS equivalent. Once a host is on the PAM lane it stays there:
  `--prelaunch` refreshes the hook without re-enabling the approval plugin or
  the blanket rule, and `--contextual-pam` swaps in a newer module in place
  (staged, self-tested, renamed) while leaving the PAM entries untouched.
  `scripts/test-pam-acceptance` drives the lane end to end in a container,
  including the password fallback and the uninstall path.

### Fixed

- The real sudo check now prints the browser approval URL on stderr, where the
  approval plugin forwards hook diagnostics, while keeping the command's
  stdout reserved for the approved command's output (#81).
- `scripts/oshioki-phone-setup` generates NATS permission lists that now
  include `oshioki.ack.*` and `oshioki.delivery.*` for both the hook and
  server users. PR #57 (0.1.4) added the `oshioki.delivery.<request_id>`
  delivery receipt and its `oshioki.ack.<request_id>` companion, but this
  script's `_nats_config` still wrote the pre-#57 permission lists, so every
  phone/browser approval routed through a phone-setup NATS instance failed
  with `Permissions Violation for Publish to "oshioki.delivery.<id>"` on the
  server and a daemon delivery-receipt timeout on the hook.
  `docs/requirements.md`'s hand-written permission checklist is updated to
  match (#80).
- Release packaging ships the PAM module: the `.deb` and the macOS tarball now
  carry `liboshioki_pam.so` / `liboshioki_pam.dylib` and list it in their
  `SHA256SUMS`, so `--contextual-pam` has a module to install from a released
  artifact.
- Review fixes from the contextual-PAM work: the installer refuses a
  non-executable helper rather than wiring PAM to something it cannot run;
  `purge` keeps the helper while any PAM stack still references the module,
  so a purge cannot leave sudo pointing at a module whose helper is gone; the
  legacy approval plugin skips its own password lane when the contextual
  module is live, so a password is prompted for once and by one owner; and
  fault injection is off unless explicitly opted into, so a production host
  cannot be made to fail approvals by environment alone.

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
