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

Homebrew automatically refreshes an already running `com.oshioki.agent` in your
GUI login session when its configured executable exactly matches the formula's
stable `opt/oshioki/Oshioki.app/Contents/MacOS/oshioki-agent` path. It validates
the new bundle's executable, identity, version, icon, and signature, then checks
for a replacement process running that bundled executable within ten seconds.
The existing launchd configuration, identities, enrollment, and credentials are
preserved. Absent, stopped, disabled, and custom installations remain unchanged;
a custom path produces instructions to re-run your original setup command.

Read Homebrew's output. If a refresh fails or the upgrade runs outside your GUI
login session, retry from a logged-in Terminal:

```sh
brew postinstall epsalmond/oshioki/oshioki
```

Retry any approval interrupted by the restart. Automated bundle validation does
not verify the Touch ID sheet's visual appearance on a real Mac.

Privileged hook, plugin, and PAM updates still require the setup step above;
automating those components is tracked in [#48](https://github.com/epsalmond/oshioki/issues/48).
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
