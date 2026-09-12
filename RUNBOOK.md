# Oshioki runbook

The current workflow is local and prelaunch. It does not activate a production
service or a permanent sudo plugin.

Build, test, and retained dev servers are the contributor loop; see
[CONTRIBUTING.md](CONTRIBUTING.md). The notes below are operator tasks.

"Supervised" below means a person is watching: you answer the approval
prompts (Touch ID, terminal) while the loop runs.

The installer requires `target/release/SHA256SUMS`. Create it after a release
build:

```bash
cd target/release
sha256sum oshioki liboshioki_plugin.so > SHA256SUMS
```

## One-line laptop setup

```bash
brew install epsalmond/oshioki/oshioki && oshioki-laptop-setup
```

The setup script is idempotent. Re-running it after a `brew upgrade`
applies the new bottle and restarts the agent. It writes
`/etc/oshioki/install.env` (prompting for values on first run,
`--reconfigure` to redo), dry-runs then applies the prelaunch install
inside one sudo elevation, enrolls and pairs the agent when there is no
identity, installs a LaunchAgent for `oshioki-agent run` on Darwin, and
finishes with a real `sudo true` as proof. Linux has no autostart: the agent
approves through a terminal prompt there, so setup writes
`~/.config/oshioki/agent.env` and prints the one-liner that runs the agent on
a terminal you keep open. It finishes without the proof, and sudo works from
the moment the agent is running. Run it as yourself, never under sudo. A root run poisons user-owned files (the app
bundle loses its readable icon that way). Non-interactive with `--yes`
plus values in the environment. Setup costs two Touch ID approvals, the
elevation and the proof (plus the sudo password on a machine that has never
run setup). Day-to-day sudo with a hardware-backed device costs one device
approval: the installer couples a `sudoers.d` NOPASSWD drop-in to the plugin
block. A software native device keeps normal sudo password authentication
because its signing key is readable by the enrolled account. On Linux, an
interactive request also races the invoking account password through the
host's `sudo` PAM service. Press Enter to skip that fallback and wait for
device approval. The manual steps below remain for non-brew layouts.

## Prelaunch installer

Keep a second root shell open during supervised acceptance. Create a root-owned
installer configuration without putting the NATS password in command history:

```bash
sudo install -d -m 0750 /etc/oshioki
sudo install -m 0600 /dev/null /etc/oshioki/install.env
sudoedit /etc/oshioki/install.env
```

The file contains only these keys:

```text
OSHIOKI_ORIGIN=https://sudo.example.com
OSHIOKI_RP_ID=sudo.example.com
NATS_URL=tls://nats.example.com:4222
NATS_USER=oshioki-hook
NATS_PASS=<secret>
```

The hook refuses plaintext `nats://` past loopback: the NATS server needs
TLS with a certificate chaining to the system roots (hostname-verified), and
each role — hook, agent, server — gets its own NATS user. Testing without
server certificates sets `OSHIOKI_ALLOW_PLAINTEXT_NATS=1` instead; never do
that in production.

For socket mode (below), also add:

```text
OSHIOKI_AGENT_SOCKET=/Users/<you>/.config/oshioki/agent.sock
```

To have the `.deb` migrate this host to the contextual PAM lane instead of
leaving it on the approval plugin, add:

```text
OSHIOKI_CONTEXTUAL_PAM=1
```

Only the exact value `1` opts in; any other value, or no key at all, leaves
the host on the plugin lane. The key is safe to pre-seed before any device
exists: each `configure` runs `--prelaunch` first (it writes the hook binary,
its configuration and the device registry that the migration needs) and
`--contextual-pam` last, and the migration exits 0 with a "no active
hardware-backed approval device yet" note until a hardware-backed device is
pinned. The migration then happens at the first `configure` after that —
`apt install --reinstall oshioki`, the next upgrade, or by hand:

```bash
sudo /usr/share/oshioki/install-oshioki-hook --contextual-pam \
  --config-file /etc/oshioki/install.env
```

A migration that cannot complete never fails the package configuration; it
prints the command to re-run. Once a host is on the PAM lane it stays there:
`configure` reads the lane from the host (any PAM service file naming the
module), so a later `--prelaunch` refreshes the hook and the module without
re-enabling the approval plugin or the blanket `NOPASSWD` rule, even if the
key is later removed from `install.env`. An upgrade that ships a new module
swaps it in place — staged beside the live file, self-tested, then renamed —
leaving the PAM entries untouched.

On macOS the same opt-in is `oshioki-laptop-setup --contextual-pam` (or
`OSHIOKI_CONTEXTUAL_PAM=1` in its environment), which runs the migration
after the normal install and pairing. A Homebrew install needs no environment
at all: the whole macOS flow is

```bash
brew install epsalmond/oshioki/oshioki
oshioki-laptop-setup --contextual-pam
```

`oshioki-laptop-setup` resolves its own keg — the hook beside it in `bin`,
and `oshioki.dylib`, `liboshioki_pam.dylib` and `SHA256SUMS` one level up in
`libexec` — and passes all four to the installer. Run it as yourself; it
elevates once by itself.

Both dylibs are linked with the keg's own `opt` path as their install name
(`/opt/homebrew/opt/oshioki/libexec/<name>`, `plugin/build.rs` and
`pam/build.rs`, overridable with `OSHIOKI_PLUGIN_INSTALL_NAME` /
`OSHIOKI_PAM_INSTALL_NAME`). That is load-bearing for checksum verification,
not cosmetic: Homebrew's `Keg#fix_dynamic_linkage` rewrites `LC_ID_DYLIB` to
exactly that path and ad hoc re-signs every file it modified, which used to
leave the bottled copies failing the `SHA256SUMS` the release recorded
(issue #87). Presetting the id makes `change_dylib_id` return early and the
shipped bytes survive. `otool -D` on either file must print its own
`libexec` path; if it prints anything else the next bottle will fail
verification again.

That id travels with the release tarball, so a module installed from it at
`/usr/local/lib/pam/liboshioki_pam.dylib` also reports the Homebrew `opt`
path under `otool -D`. Expected, and inert: sudo and OpenPAM both `dlopen`
by the absolute path they were given, and `LC_ID_DYLIB` only names a library
for things that link against it. Nothing links against a PAM module.

Never run the migration without a recovery path already open: a second root
shell (`sudo -i`) held for the whole run, and a verified console or `pkexec`
fallback, both established *before* the first `--contextual-pam`. Inspect and
roll back with:

```bash
sudo /usr/share/oshioki/install-oshioki-hook --contextual-pam-status
sudo /usr/share/oshioki/install-oshioki-hook --disable-contextual-pam
```

`--contextual-pam-status` exits non-zero unless every line reads `OK`.
`--disable-contextual-pam` removes the PAM entries, re-proves `sudo -V`, and
only then unlinks the module; it refuses to unlink a module any file under
`/etc/pam.d` still names. `prerm` runs the same command during package
removal — before it touches the plugin block or the sudoers drop-in, and it
stops the removal if that command fails, so a host whose module is still live
keeps the legacy artifacts it may need to reach `sudo`. `prerm` decides by
looking for the marker or an `auth` line naming the module in any PAM service
file under `/etc/pam.d`, so a hand-damaged entry is still cleaned up.

Run the dry run and install against that file:

```bash
sudo scripts/install-oshioki-hook --prelaunch --dry-run --config-file /etc/oshioki/install.env
sudo scripts/install-oshioki-hook --prelaunch --config-file /etc/oshioki/install.env
sudo scripts/install-oshioki-hook --prelaunch-status
```

The installer rejects unknown config keys, symlinks, non-root ownership, and
modes other than 0600. `--prelaunch` preserves an existing `devices.json`.
With an active device it also writes `/etc/sudoers.d/oshioki`
(`<user> ALL=(ALL) NOSETENV: NOPASSWD: ALL`, visudo-checked), so Touch ID is
the only authorization step for a hardware-backed device and sudo stops asking
for a password. The user comes from
`OSHIOKI_SUDO_USER` (else `SUDO_USER`); without either, or without a
`sudoers.d` include in the main sudoers file, the installer warns and keeps
password authentication. The block and the drop-in go away together with
`--disable-prelaunch`, and a re-run with no active devices removes both as
well, so an enabled plugin never fails every sudo closed on an empty
registry. `--prelaunch-status` checks both files.
On Linux, the plugin races an interactive password fallback with device
approval from the start of each request. It authenticates the invoking user
through the host's `sudo` PAM service, then runs account management. Press
Enter at `[sudo/oshioki] password for <user>:` to skip the password branch.
An explicit approval denial or invalid approval fails closed. `sudo -n` never
opens the plugin password prompt. The hook's 90-second approval deadline is
authoritative; the plugin keeps a five-second cleanup margin. Darwin ships
device approval only and never opens this password branch.
Linux uses `/usr/local/libexec/sudo/oshioki.so`. Darwin uses
`oshioki.dylib` in the same directory.

Outside a repo checkout the installer needs its inputs pointed at the
installed files: set `HOOK_BIN` and `PLUGIN_BIN` to the installed hook and
plugin and `OSHIOKI_CHECKSUMS` to the shipped `SHA256SUMS`, whose entries
are keyed by file name. For a Homebrew install at `$(brew --prefix oshioki)`:

```bash
sudo HOOK_BIN="$(brew --prefix oshioki)/bin/oshioki" \
  PLUGIN_BIN="$(brew --prefix oshioki)/libexec/oshioki.dylib" \
  OSHIOKI_CHECKSUMS="$(brew --prefix oshioki)/libexec/SHA256SUMS" \
  "$(brew --prefix oshioki)/bin/install-oshioki-hook" --prelaunch \
  --config-file /etc/oshioki/install.env
```

After the install, confirm `--prelaunch-status`, inspect the enrolled devices,
and run `sudo -V`.

### Local agent socket (no network in the sudo path)

The hook reaches the agent over NATS by default, which puts the network in
every sudo. For a laptop, point the hook at the agent's Unix socket instead:

1. Run the agent as your user. It listens at `agent.sock` in its state
   directory (`~/.config/oshioki` by default, `OSHIOKI_AGENT_SOCKET`
   overrides it):

   ```bash
   oshioki-agent run
   ```

2. Put that socket path in `/etc/oshioki/install.env` as
   `OSHIOKI_AGENT_SOCKET` (see above) and re-run the installer, dry-run
   first. The installer copies the key into `/etc/oshioki/config.env`.

The hook tries the socket first and falls back to NATS while the approval
deadline allows, so a stopped agent degrades to the network path instead of
hanging sudo. Verdicts are signature-checked on both transports. The agent
itself starts without NATS and answers socket requests only until it is
restarted with the network back. Only Secure Enclave (Touch ID) approvals
travel the socket; browser WebAuthn still needs the server. Native pairing
can be done offline (below), so one agent serves local sudo over the socket
and remote requests over NATS at the same time.

Omit `NATS_URL` from `config.env` for a socket-only host: the hook then
never touches NATS, a silent agent denies at once, and a config naming
neither transport fails before any request is built. Fallback failures name
the server and the failed step (`NATS fallback to nats://host:port failed:
connect: ...`) with credentials redacted. `oshioki-laptop-setup --local`
writes this shape unless a NATS is staged, and probes a staged NATS before
writing it. A stale install carrying the old `local`/`local` placeholder
credentials migrates with `oshioki-laptop-setup --local --reconfigure`;
a plain re-run against a stale `install.env` refuses with the same advice
instead of reinstalling it.

Revocation still needs a NATS: `oshioki revoke` publishes to the server
and waits for its confirmation, so on a socket-only host it fails with
`NATS_URL not set`. The revocation itself is server-side — the local
registry is only edited after the server confirms — so point the hook at
any reachable server NATS just for the command (sudo scrubs the
environment, hence `env`):

```bash
sudo env NATS_URL=tls://sudo.example.com:4222 NATS_USER=<hook-user> NATS_PASS=<secret> \
  oshioki revoke <fingerprint>
```

The fingerprint must still be pinned locally; the command removes it there
once the server confirms.

For phone enrollment, first run `oshioki-phone-setup` as the logged-in
user. It prefers a local server reached through Tailscale Serve; an existing
HTTPS server is supported with `--server-url` and `--nats-config`.
See [phone enrollment](docs/phone-enrollment.md). The phone needs to be on
the same tailnet only when using the Tailscale option.

Each browser profile enrolls separately. Run these host commands with sudo
because they read or update the root-owned registry:

```bash
sudo oshioki enroll
sudo oshioki enroll --resume <enrollment-id>
sudo oshioki status
sudo oshioki revoke <fingerprint>
sudo oshioki pin <fingerprint>
sudo oshioki pin-record <path>
```

A host the server never sees pairs offline with one command. It builds
if needed, creates the identity, pins it, and starts the agent. No server.
One sudo elevation and no typing: the fingerprint confirmation is piped,
and `--yes` skips the apply prompt.

```bash
oshioki-laptop-setup --local
```

On Linux this leaves the agent to you. Start it on a terminal you keep open:

```bash
set -a; . ~/.config/oshioki/agent.env; set +a; oshioki-agent run
```

Every sudo prompts there, and answering the prompt is what approves the
request. Closing that terminal stops approvals.

The steps, spelled out for when something needs a hand: the device exports
its own record and the host pins it with the same fingerprint confirmation
as `pin`, no NATS or server involved.

```bash
oshioki-agent init
oshioki-agent device-record --label <label> > /tmp/record.json
sudo oshioki pin-record /tmp/record.json
rm /tmp/record.json
sudo oshioki status
```

The record carries only public material (fingerprint, public keys, label),
so plain `rm` is enough. The installer leaves the sudo plugin disabled
until a device is active: enabling it on an empty registry would lock every
sudo out, including the one that would pin the first device.

The pinned device approves exactly like an enrolled one. Pairing the same
device with the server later (plain `enroll`/`pair`) keeps the fingerprint,
so nothing pinned needs redoing.

`enroll` prints an enrollment URL, and below it the `oshioki-agent pair`
command a native device runs to consume the same URL. `status` prints each
device's `kind` (`webauthn`, `software`, or `secure-enclave`) next to its
fingerprint.

`test` publishes a synthetic request and waits for approve or deny.

## Mac approver

Acceptance is two commands. On the host:

```bash
scripts/dev-acceptance mac
```

That starts the acceptance stack with NATS bound to this node's tailnet IPv4
address, runs `oshioki enroll`, and prints one line to paste on the Mac. The
line carries the NATS URL, the credentials, and the enrollment URL. On the Mac
it pulls the checkout, builds the agent, wraps it in `Oshioki.app`, pairs it
with one Touch ID sheet, and then runs the bundled agent in the foreground. The
bundle is what makes the request sheets say Oshioki with the logo. Use
`--label NAME` to name the device. The default is `mbp`.

The host stays blocked until the Mac pairs. It then prints the activation
result and the next step. Run one of these per request:

```bash
scripts/dev-acceptance test
```

Each `test` publishes one synthetic request. The Mac's sheet answers it.
Approve with Touch ID. Cancel the sheet to exercise deny. Ignore the sheet to
exercise the timeout. Stop the stack with `scripts/dev-acceptance down`.

`pair` creates the Secure Enclave key and shows one Touch ID sheet for the
enrollment proof.

### Running the agent as a LaunchAgent

The foreground run above is enough for acceptance. For a Mac that should
approve after a reboot, install the LaunchAgent instead. It runs the same
bundled binary:

```bash
NATS_URL=tls://nats.example.com:4222 NATS_USER=oshioki-agent NATS_PASS=<secret> \
  scripts/mac/install-agent
```

Without server certificates yet, prefix `OSHIOKI_ALLOW_PLAINTEXT_NATS=1`
(testing only) — `install-agent` carries it into the LaunchAgent plist, and
the agent refuses the plaintext URL otherwise.

`install-agent` writes the LaunchAgent plist 0600, because it holds the NATS
password, and loads it into the GUI domain. Add `--dry-run` to see the plist
without writing it; the password is masked. `--uninstall` boots the agent out
and removes the plist.

Check what is loaded and what it has been doing:

```bash
launchctl print gui/$(id -u)/dev.oshioki.agent | head -20
target/release/oshioki-agent show
tail -f ~/Library/Logs/oshioki-agent.log
```

`show` prints the fingerprint and the signing backend. Re-run
`scripts/mac/install-agent` after rebuilding the binary; it boots out the old
agent first.

### Re-pairing

Adding or removing a fingerprint in Touch ID invalidates the enclave key for
good. The log says `the Secure Enclave would not sign` and asks for a
re-pair. Recover with a new enrollment, which mints a new key and a new
fingerprint for the host to pin:

```bash
rm ~/.config/oshioki/agent.json      # on the Mac
scripts/dev-acceptance mac           # on the host, then paste on the Mac
sudo oshioki revoke <old-fingerprint>     # on the host
```

Remove the `# BEGIN oshioki` … `# END oshioki` section the installer added
to `sudo.conf` before stopping a supervised stack:

```bash
sudo scripts/install-oshioki-hook --disable-prelaunch
sudo -V
```

The installer restores the prior `sudo.conf` automatically if validation
fails. Production integration must also stop its server and NATS resources,
restore routing, and confirm ordinary sudo behavior.

## Authentication lane upgrade

Contextual sudo authentication (`oshioki authenticate`, the PAM helper verb)
publishes on `oshioki.auth.<host>`, a separate subject tree from command
approval's `oshioki.request.<host>`. Two things in a NATS deployment predate
it and are **not** updated automatically:

1. The `OSHIOKI` stream's subject list. A stream created for
   `oshioki.request.>` alone silently discards everything published on
   `oshioki.auth.>`.
2. The durable `oshioki-server-v1` consumer's filter. `get_or_create_consumer`
   returns an existing durable exactly as it is and never rewrites its
   configuration, so a consumer created before this lane existed keeps its old
   single filter no matter what the binary asks for.

The server logs a warning at startup naming this section when the running consumer's
filters do not match the build. To fix a deployment (NATS 2.10 or newer):

```sh
nats stream update OSHIOKI --subjects 'oshioki.request.>,oshioki.auth.>'
# The durable's filter cannot be widened in place; recreate it. Do this while
# no request is in flight: pending deliveries are lost with the consumer.
nats consumer rm OSHIOKI oshioki-server-v1
# The server recreates it with both filters on its next start.
systemctl restart oshioki-server
```

Verify with `nats consumer info OSHIOKI oshioki-server-v1`: the filter list
must show both `oshioki.request.>` and `oshioki.auth.>`.

This widening is required, not preparatory: the server already consumes
`oshioki.auth.>`. Its JetStream handler routes on the envelope's own `type`
tag (`server/src/main.rs`, the `envelope_type` match), hands an
`AUTH_ENVELOPE_TYPE` envelope to `ingest_auth_envelope`, and serves the
stored request to a `WebAuthn` browser at the `/a/:id` route
(`authentication_page`). A consumer whose filters still list only
`oshioki.request.>` therefore never delivers an authentication request, and
every contextual sudo falls back to a password.

## Logs

The hook writes approval progress, warnings, and errors to stderr. It sends
the audit trail (every approval,
denial, and a request left to NATS by the local agent) to the system log
under the `authpriv` facility, the one sudo uses:

```bash
journalctl -t oshioki                                                   # Linux
sudo log show --info --last 1h --predicate 'eventMessage BEGINSWITH "oshioki["'   # macOS
```

On macOS the hook hands each record to logger(1), which is what the unified
log keeps; approvals are info level, so `log show` needs `--info`.

To see more on the terminal, put `OSHIOKI_LOG=info` (the hook's own
chatter) or `OSHIOKI_LOG=audit=info` (the audit trail) in
`/etc/oshioki/config.env`; both together also work. The sudo path reads its terminal level from
that root-owned file and ignores `RUST_LOG`, so a caller cannot change what
root prints. The other `oshioki` verbs, run by a person, honour `RUST_LOG`.
The system log keeps its own level regardless.

If a browser delivery receipt times out while NATS and the server are healthy,
check that the browser device is active in both the hook's pinned registry and
the server's device records. A device revoked only on the server cannot receive
a delivery receipt even when the hook still lists it as active.
