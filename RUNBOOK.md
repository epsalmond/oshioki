# Oshioki runbook

The current workflow is local and prelaunch. It does not activate a production
service or a permanent sudo plugin.

## Build and test

```bash
scripts/dev build
scripts/dev test --quick
scripts/dev test --browser
scripts/dev test
```

The full test creates fresh NATS and SQLite state. It runs browser enrollment
and approval with two isolated Chromium profiles. It then installs the hook and
plugin inside the E2E container and invokes real sudo. Failed runs retain their
state path and scrubbed Compose logs.

The installer requires `target/release/SHA256SUMS`. Create it after a release
build:

```bash
cd target/release
sha256sum oshioki liboshioki_plugin.so > SHA256SUMS
```

## Retained development state

```bash
scripts/dev up --state-dir ./tmp/dev-state
scripts/dev status
scripts/dev down
```

The development server uses the local test origin only when the caller supplies
matching configuration. Production origin, RP ID, NATS credentials, storage,
and routing are consumer-owned settings.

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
NATS_URL=nats://nats.example.com:4222
NATS_USER=oshioki
NATS_PASS=<secret>
```

Run the dry run and install against that file:

```bash
sudo scripts/install-oshioki-hook --prelaunch --dry-run --config-file /etc/oshioki/install.env
sudo scripts/install-oshioki-hook --prelaunch --config-file /etc/oshioki/install.env
sudo scripts/install-oshioki-hook --prelaunch-status
```

The installer rejects unknown config keys, symlinks, non-root ownership, and
modes other than 0600. `--prelaunch` preserves an existing `devices.json`.
Linux uses `/usr/local/libexec/sudo/oshioki.so`. Darwin uses
`oshioki.dylib` in the same directory.

After the install, confirm `--prelaunch-status`, inspect the enrolled devices,
and run `sudo -V`.

Each browser profile enrolls separately:

```bash
oshioki enroll
oshioki enroll --resume <enrollment-id>
oshioki status
oshioki revoke <fingerprint>
oshioki pin <fingerprint>
```

`enroll` prints an enrollment URL, and below it the `oshioki-agent pair`
command a native device runs to consume the same URL. `status` prints each
device's `kind` (`webauthn` or `secure-enclave`) next to its fingerprint.

`test` publishes a synthetic request and waits for approve or deny. `watch`
opens each request URL on Darwin without a shell.

## Mac approver

On the Mac, from a checkout:

```bash
cargo build --release -p oshioki-agent
scripts/mac/bundle-agent
target/release/oshioki-agent pair '<enrollment-url>' --label mbp
NATS_URL=nats://nats.example.com:4222 NATS_USER=oshioki NATS_PASS=<secret> \
  scripts/mac/install-agent
```

`pair` creates the Secure Enclave key and shows one Touch ID sheet for the
enrollment proof. `install-agent` writes the LaunchAgent plist 0600, because
it holds the NATS password, and loads it into the GUI domain. Add
`--dry-run` to see the plist without writing it; the password is masked.
`--uninstall` boots the agent out and removes the plist.

Check what is loaded and what it has been doing:

```bash
launchctl print gui/$(id -u)/dev.oshioki.agent | head -20
target/release/oshioki-agent show
tail -f ~/Library/Logs/oshioki-agent.log
```

`show` prints the fingerprint and the signing backend. Re-run
`scripts/mac/install-agent` after rebuilding the binary; it boots out the old
agent first.

Adding or removing a fingerprint in Touch ID invalidates the enclave key for
good. The log says `the Secure Enclave would not sign` and asks for a
re-pair. Recover with a new enrollment, which mints a new key and a new
fingerprint for the host to pin:

```bash
oshioki enroll                       # on the host
rm ~/.config/oshioki/agent.json      # on the Mac
target/release/oshioki-agent pair '<enrollment-url>' --label mbp
oshioki revoke <old-fingerprint>     # on the host
```

Disable the managed block before stopping a supervised stack:

```bash
sudo scripts/install-oshioki-hook --disable-prelaunch
sudo -V
```

The installer restores the prior `sudo.conf` automatically if validation
fails. Production integration must also stop its server and NATS resources,
restore routing, and confirm ordinary sudo behavior.
