# Diagnose and recover Oshioki

For first-time setup, use [installation](docs/install.md),
[local sudo](docs/local-sudo.md), [remote sudo](docs/remote-sudo.md), or
[phone enrollment](docs/phone-enrollment.md).
For an upgrade, use [update and restore](docs/update.md).

## Inspect the installation

Host commands read root-owned state under `/etc/oshioki`:

```sh
sudo oshioki status
sudo oshioki test
```

`status` reports authentication mode and enrolled devices. `test` sends a
synthetic command-approval request; it does not exercise the PAM stack.

The installer is `install-oshioki-hook` on Homebrew,
`/usr/share/oshioki/install-oshioki-hook` on Debian, and
`scripts/install-oshioki-hook` in a checkout:

```sh
sudo install-oshioki-hook --prelaunch-status
sudo install-oshioki-hook --contextual-pam-status
```

Use the check for the installed mode. PAM status must report every check as
OK, including the installed module's checksum. A PAM entry without its module
is a broken installation. Missing checksums are a failure, not a skipped check.

## No approval arrives

| Symptom | Check or recovery |
| --- | --- |
| Local Mac shows no prompt | Verify the graphical session, agent service, socket path, and log; see [Mac approvals](docs/mac-approvals.md). |
| `Permissions Violation for Subscription` | Give the agent its own NATS role, not the hook's credentials. |
| Socket-only configuration cannot reach remote requests | Configure the agent's NATS environment and restart it. |
| TLS connection refused | Use `tls://` outside loopback with a trusted, hostname-matched certificate. |
| Phone cannot enroll or receive push | Use the [phone troubleshooting table](docs/phone-enrollment.md#keep-it-working). |
| Browser delivery receipt times out | Check that the device is active in both the host registry and server records. |
| `User interaction is not allowed` | Run Mac setup in a logged-in graphical session with its login keychain unlocked. |
| Old `local/local` NATS placeholder credentials | Re-run `oshioki-laptop-setup --local --reconfigure`. |

The hook can try a configured Unix socket before NATS. A socket-only host omits
`NATS_URL`. A socket answer that fails signature/protocol validation is not a
reason to retry through another transport; see [transports](docs/transports.md).

## Logs

The hook writes progress and errors to stderr and audit events to `authpriv`:

```sh
# Linux
journalctl -t oshioki

# macOS
sudo log show --info --last 1h --predicate 'eventMessage BEGINSWITH "oshioki["'
```

For hook terminal diagnostics, set `OSHIOKI_LOG=info` or
`OSHIOKI_LOG=audit=info` in `/etc/oshioki/config.env`.
The sudo path ignores caller-controlled `RUST_LOG`.

Laptop setup logs the agent to `~/.config/oshioki/agent.log`; the source
Mac installer uses `~/Library/Logs/oshioki-agent.log`. Phone server logs and
state are under `~/.local/share/oshioki/phone-server`.

## Re-pairing

Use this only for a lost or invalid identity, such as a Touch ID fingerprint
change. Re-pairing changes the device fingerprint on **every** host it serves.

Keep a root recovery shell on affected hosts and stop the agent before replacing
its identity. For a server-paired Mac, start a fresh `sudo oshioki enroll` on the
host, then on the Mac:

```sh
oshioki-agent pair '<enrollment-url>' --label my-mac --force
```

Use ordinary `pair` (without `--force`) for each remaining host. Restart the
agent, verify the new device, and revoke the old fingerprint on each host.

For a socket-only Mac, use `oshioki-agent init --force`, then re-run
`oshioki-laptop-setup --local` to pin the replacement.
Do not delete `agent.json` as an upgrade step.

## Device management

| Host command | Purpose |
| --- | --- |
| `sudo oshioki enroll` | Start enrollment. |
| `sudo oshioki enroll --resume <id>` | Resume pending enrollment. |
| `sudo oshioki pin <fingerprint>` | Fetch a public device record from the server and pin it. |
| `sudo oshioki pin-record <path>` | Pin an offline public record. |
| `sudo oshioki revoke <fingerprint>` | Revoke on the server, then update the local registry. |
| `sudo oshioki watch` | Open browser pages for incoming requests. |

Revocation needs a reachable server and hook-role NATS credentials, even on a
socket-only host. Configure those in the private root-owned hook configuration
for the operation. If there is no server, there is no serverless revoke command;
disable sudo integration while resolving a lost or compromised pinned device.

## Restore ordinary sudo

Use the root shell retained before installation if normal sudo is unavailable.
Run only the command for the mode being removed, using your installer path:

```sh
# Contextual PAM:
sudo install-oshioki-hook --disable-contextual-pam

# Approval plugin:
sudo install-oshioki-hook --disable-prelaunch

sudo -V
sudo -k
sudo true
```

In an existing root shell, omit `sudo`. Verify normal password authentication
before closing that shell. The PAM removal checks that no service still names
the module before unlinking it. Plugin removal also removes its coupled
sudoers rule. These operations retain identity and enrollment state.

## Authentication subject upgrade

The server repairs an existing `OSHIOKI` stream and durable consumer when
adding `oshioki.auth.>` to an older command-only deployment. It cannot start
without the stream or permission to repair it.

If startup repair fails, pause requests and inspect the stream and durable:

```sh
nats stream info OSHIOKI
nats consumer info OSHIOKI oshioki-server-v1
```

The stream must cover `oshioki.request.>` and `oshioki.auth.>`; a broader
`oshioki.>` already covers both. Preserve unrelated subjects. For a stream
that previously held only command requests, the repair is:

```sh
nats stream update OSHIOKI --subjects 'oshioki.request.>,oshioki.auth.>'
nats consumer rm OSHIOKI oshioki-server-v1
systemctl restart oshioki-server
```

Use the deployment's administrative NATS credentials. Deleting the durable
can lose in-flight deliveries; perform it with requests paused. Verify both
consumer filters after restart. See the [compatibility contract](docs/compatibility.md).
