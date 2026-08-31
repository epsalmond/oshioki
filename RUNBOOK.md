# Sudo approve runbook

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
sha256sum sudo-approve libplugin.so > SHA256SUMS
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

Keep a second root shell open during supervised acceptance. Run the dry run
before installation:

```bash
scripts/install-sudo-hook --prelaunch --dry-run
sudo scripts/install-sudo-hook --prelaunch
sudo scripts/install-sudo-hook --prelaunch-status
```

The installer requires `SUDO_APPROVE_ORIGIN`, `SUDO_APPROVE_RP_ID`, `NATS_URL`,
and `NATS_PASS`. `--prelaunch` preserves an existing `devices.json`. Linux uses
`/usr/local/libexec/sudo/approval_exec.so`. Darwin uses
`approval_exec.dylib` in the same directory.

Each browser profile enrolls separately:

```bash
sudo-approve enroll
sudo-approve enroll --resume <enrollment-id>
sudo-approve status
sudo-approve revoke <fingerprint>
sudo-approve pin <fingerprint>
```

`test` publishes a synthetic request and waits for approve or deny. `watch`
opens each request URL on Darwin without a shell.

Disable the managed block before stopping a supervised stack:

```bash
sudo scripts/install-sudo-hook --disable-prelaunch
sudo -V
```

The installer restores the prior `sudo.conf` automatically if validation
fails. Production integration must also stop its server and NATS resources,
restore routing, and confirm ordinary sudo behavior.
