# Sudo approval runbook

This service is prelaunch software. Issue #867 builds and tests the protocol,
hook, browser, server, installer, and artifacts. It does not activate a
production service or permanent sudo plugin.

## Build and test

```bash
cd services/sudo-approve
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --release
./scripts/test-install-sudo-hook
./scripts/test-sudo-plugin-container
```

The installer requires `target/release/SHA256SUMS`. Create it after a local
release build:

```bash
cd services/sudo-approve/target/release
sha256sum management-plane-sudo-approve libplugin.so > SHA256SUMS
```

## Temporary acceptance setup

Keep a second root shell open during acceptance. Snapshot Tailscale Serve
before changing it. Use a disposable NATS JetStream stream and SQLite file.
The hook and server must use the exact temporary HTTPS origin and RP ID.

Run the installer only after its dry run:

```bash
services/sudo-approve/scripts/install-sudo-hook --prelaunch --dry-run
sudo services/sudo-approve/scripts/install-sudo-hook --prelaunch
sudo services/sudo-approve/scripts/install-sudo-hook --prelaunch-status
```

`--prelaunch` installs and enables the plugin. It preserves an existing
`devices.json`. The Linux plugin path is
`/usr/local/libexec/sudo/approval_exec.so`. Darwin uses
`approval_exec.dylib` in the same directory.

## Enroll and manage devices

Each browser profile enrolls separately. The URL fragment contains the
five-minute enrollment secret and never reaches the server.

```bash
management-plane-sudo-approve enroll
management-plane-sudo-approve enroll --resume <enrollment-id>
management-plane-sudo-approve status
management-plane-sudo-approve revoke <fingerprint>
management-plane-sudo-approve pin <fingerprint>
```

`pin` fetches one active public record. It recomputes the full-record
fingerprint and requires the full fingerprint as operator confirmation.

`test` publishes a synthetic request and waits for approve or deny. `watch`
opens each request URL on Darwin without a shell.

## Disable and restore

Disable the managed block before stopping the temporary stack:

```bash
sudo services/sudo-approve/scripts/install-sudo-hook --disable-prelaunch
sudo -V
```

Restore the saved Tailscale Serve configuration. Stop the disposable NATS and
server processes. Confirm ordinary sudo behavior. The installer restores the
prior `sudo.conf` automatically if `sudo -V` fails.

Issue #868 owns production NATS permissions, JetStream creation, ntfy,
Compose, DNS, TLS, promotion, exemptions, alerts, and activation on `nas`.
Issue #869 owns the durable `mbp` installer, watcher credential, LaunchAgent,
`pam_tid`, and laptop rollback.
