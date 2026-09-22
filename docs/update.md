# Update and restore

Update matching components together: hook/plugin/PAM module, hook/local agent,
and server/browser bundle/hooks. Remote browser relay peers should also use
the same release. An update should preserve enrolled devices and fingerprints.

## Before updating

Keep the previous package and a second root shell available. Back up
`/etc/oshioki`, the agent state directory, and server state, preserving ownership
and private permissions. Stop the server for a filesystem copy of its SQLite
database; copying only a live SQLite file can miss WAL contents. Retain the
VAPID key beside it so phone subscriptions keep their server identity.

Do not regenerate identities or enroll devices as a routine update step.

## Homebrew

```sh
brew update
brew upgrade epsalmond/oshioki/oshioki
oshioki-laptop-setup --local
```

Use the setup mode you originally chose: omit `--local` for server-backed
laptop setup. An existing PAM installation stays on PAM. Ordinary re-runs
preserve the agent's configured NATS credentials; `--reconfigure` replaces them.

If this Mac only runs browser ceremonies, the package upgrade is enough.
Restart any running `oshioki-browser-relay serve` process after upgrading.

## Debian or Ubuntu

Install the new release package:

```sh
sudo apt install ./oshioki_X.Y.Z_amd64.deb
```

Package configuration refreshes the hook when `/etc/oshioki/install.env`
exists and restarts an already running packaged server. An existing PAM
installation stays on PAM even if its original opt-in setting was removed.
Read the output: a deferred PAM migration is not an active PAM installation.

Phone setup's user services are separate from the packaged system service.
Re-run `oshioki-phone-setup` for an owned Tailscale setup to refresh them;
for external HTTPS, restart the server in its own deployment.

For source installs, rebuild the same components, regenerate the installer
manifest, and repeat the [installation](install.md) using the existing state.

## Verify

Use the appropriate installer path from [installation](install.md):

```sh
sudo oshioki status
sudo install-oshioki-hook --prelaunch-status
# On PAM installations:
sudo install-oshioki-hook --contextual-pam-status
sudo -k
sudo true
```

Complete the approval on an already enrolled device. For phone setups, also
check request-triggered notification delivery. For remote setups, request from
the remote host. A running service or healthy endpoint alone does not prove
either journey.

## Restore

If sudo is unavailable, use the retained root shell and
[restore ordinary sudo](../RUNBOOK.md#restore-ordinary-sudo) first.

Reinstall the previous matching binaries. If a schema upgrade prevents the old
server from opening its database, stop the server and restore the verified
`<stem>.pre-v<from>.sqlite3` snapshot for that upgrade. Preserve the failed
database and its WAL/SHM files separately; do not combine a restored database
with the failed database's sidecars. Restore ownership before restarting.
Data created after the snapshot will be lost.

If an older agent cannot read a migrated identity, stop it and restore
`agent.json.prev` to `agent.json` with mode 0600. On macOS, retain the
login keychain as well as the identity file.

The [compatibility contract](compatibility.md) defines supported version
combinations, snapshot naming, and the automated upgrade/restore checks.
