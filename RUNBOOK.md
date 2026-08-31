# sudo approve runbook

## Setup

**Prerequisites:**
- Secrets seeded: NATS user/pass, NATS cert, step CA root
- Hook binaries built: `cargo build --release --manifest-path services/sudo-approve/Cargo.toml`
- Server image built: `cargo build --release --manifest-path services/sudo-approve/server/Cargo.toml`

**Prelaunch host setup:**

This installs the hook, plugin, state files, and `/etc/sudo.conf` block. It
doesn't install sudoers policy. It also clears hook exemptions and removes the
obsolete `/etc/sudoers.d/management-plane-sudo-approve` duplicate if present.

```bash
# 1. Install the sudo hook and plugin with no exemptions
./services/sudo-approve/scripts/install-sudo-hook --prelaunch

# 2. Configure NATS credentials
echo "NATS_URL=nats://management-plane:4222
NATS_USER=sudo_hook
NATS_PASS=..." > /etc/management-plane/sudo-approve/config.env

# 3. Install devices.json (empty)
echo "[]" > /etc/management-plane/sudo-approve/devices.json

# 4. Verify sudo is happy
sudo -k
sudo true  # should run hook instead
```

Launch promotion will own the production sudoers policy and argv-aware hook
exemptions. Prelaunch installation doesn't derive exemptions from sudoers.

### Disposable container test

`--standalone-e2e` is only for the container E2E. It installs no sudoers
policy. The harness creates and removes an exact policy for its test user and
`/usr/bin/echo` command.

```bash
./services/sudo-approve/scripts/test-sudo-plugin-container
```

Don't use `--standalone-e2e` as a host installation path.

## Enroll a device

The first enrollment generates a one-time URL for an Apple/iPhone:

```bash
# On nas (where requests originate):
management-plane-sudo-approve enroll

# This prints: https://sudo.internal.psalmond.com/enroll/<token>
# Send this URL to the device owner
```

On the device, open the URL. The browser will:
1. Generate X25519 keypair for encrypted requests
2. Generate P-256 WebAuthn credential for biometric approval
3. POST keys to the enrollment endpoint
4. Print fingerprint for pinning

Then pin the device fingerprint:

```bash
# 4-digit code shown on nas after enrollment
management-plane-sudo-approve pin a1b2c3d4
```

## Test

Test the whole flow without triggering actual sudo:

```bash
management-plane-sudo-approve test
```

## Debugging

### Hook logs
```bash
journalctl -u management-plane-sudo-approve
```

### NATS subjects
```bash
# See requests being published
nats -s nats://management-plane:4222 sub 'sudo.>' --user sudo_hook --pass ...
```

### Verify plugin is loaded
```bash
sudo -V | grep approval  # should show approval-plugin
```

## Rollback

The approval plugin denies everything if misconfigured. To rollback:

```bash
# Remove the approval-plugin line from /etc/sudo.conf
sudoedit /etc/sudo.conf
# Delete lines between:
#   # BEGIN management-plane sudo approve
#   # END management-plane sudo approve
```

## Security decisions

- All requests encrypted with requestor's box secret
- Biometric approval required for finger/Touch ID
- Prelaunch has no hook exemptions
- Launch promotion will own argv-aware production exemptions
- NATS over tailscale only (no public exposure)
- Fail closed: any verification error denies the command
