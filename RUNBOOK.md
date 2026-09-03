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
NATS_URL=nats://nats.example.com:4222 NATS_USER=oshioki NATS_PASS=<secret> \
  scripts/mac/install-agent
```

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
oshioki revoke <old-fingerprint>     # on the host
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
