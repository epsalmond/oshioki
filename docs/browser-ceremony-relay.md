# Google Cloud CLI login

After you install Oshioki's opt-in wrapper, the exact command `gcloud auth
login` uses the browser relay. Other gcloud commands and login commands with
flags run the pinned Google Cloud CLI directly. There is no adapter for other
providers.

The relay reuses usable cached credentials. When Google requires sign-in or
reauthentication, complete its checks in the browser; gcloud receives the
result automatically. Gcloud keeps credentials in its usual profile. For a
remote login, that profile is on the requester. Google may require account
selection, consent, a password, or a passkey. With account approval configured,
Touch ID authorizes the configured account. It does not replace Google's
authentication.

## Install and opt in

Install [Oshioki](install.md) and Google Cloud CLI on the machine that runs
gcloud. The Mac approver also needs Oshioki. The setup tools require Python 3.9
or newer; release packages declare it as a runtime dependency. Google Cloud
CLI is separate.

For a source checkout, build the binaries and add them and the setup scripts to
`PATH`:

```sh
cargo build --locked --release -p oshioki-agent -p oshioki-browser-relay
export PATH="$PWD/scripts:$PWD/target/release:$PATH"
```

Create the local or requester config described below before installing the
gcloud wrapper. Resolve the real gcloud executable first; the wrapper pins it
to delegate other commands safely:

```sh
real_gcloud="$(command -v gcloud)"
oshioki-google-login-setup install \
  --mode requester \
  --config "$HOME/.config/oshioki/browser-relay/requester.json" \
  --gcloud "$real_gcloud"
```

Use `--mode local` with `local.json` on the Mac that runs gcloud. Use
`--mode requester` with `requester.json` on the remote host. If the relay is not
on `PATH`, pass its absolute path with `--relay`.

The wrapper goes in `~/.local/bin` by default. That directory must belong to
you and cannot be writable by group or others. Parent directories cannot be
writable by group or others unless they have the sticky bit. If these checks
fail, create a private directory and pass it with `--bin-dir`:

```sh
mkdir -p "$HOME/.oshioki/bin"
chmod 700 "$HOME/.oshioki" "$HOME/.oshioki/bin"
oshioki-google-login-setup install \
  --mode requester \
  --config "$HOME/.config/oshioki/browser-relay/requester.json" \
  --gcloud "$real_gcloud" \
  --bin-dir "$HOME/.oshioki/bin"
export PATH="$HOME/.oshioki/bin:$PATH"
```

Put the wrapper directory before the real gcloud path. Refresh the shell's
command lookup with `hash -r` in Bash or `rehash` in zsh. To remove the wrapper,
run `oshioki-google-login-setup uninstall`; pass the same `--bin-dir` if you
used a custom directory.

## Local login

Local approval requires macOS, Touch ID, Secure Enclave, and a graphical login
session. It needs no server, NATS, SSH, or sudo installation.

Create a separate approval identity as the user who owns the gcloud profile:

```sh
mkdir -p ~/.config/oshioki/browser-relay
chmod 700 ~/.config/oshioki/browser-relay
oshioki-agent init --signer enclave --state ~/.config/oshioki/browser-relay
oshioki-agent device-record --state ~/.config/oshioki/browser-relay --label browser-relay
```

Copy its public `credential_public_key` into `approval_public_key`. Do not use
the sudo agent identity. Create `~/.config/oshioki/browser-relay/local.json`:

```json
{
  "google_account": "you@example.com",
  "approval_identity": "/Users/you/.config/oshioki/browser-relay/agent.json",
  "approval_public_key": "IDENTITY_CREDENTIAL_PUBLIC_KEY",
  "local_label": "this Mac"
}
```

JSON paths must be absolute; `~` is not expanded. Set the config permissions
and request login:

```sh
chmod 600 ~/.config/oshioki/browser-relay/local.json
oshioki-browser-relay local-login --config ~/.config/oshioki/browser-relay/local.json
```

Approve the named account with Touch ID. If cached credentials are usable,
gcloud may finish without opening a browser. Otherwise, complete Google's
browser flow; gcloud handles its localhost callback. The helper checks
credential usability without printing the token. Success exits zero. Denial
or expired approval starts no gcloud process. Interrupting an active attempt
stops its helper processes.

## Remote login

The requester runs gcloud and stores its credentials. The Mac shows Touch ID
and opens Google's browser when required. Install the relay on both machines
and create the Mac approval identity described above.

The connection needs a private NATS broker reachable from both machines. Use
separate NATS users and core NATS; no Oshioki server or JetStream stream is
needed. A TLS broker can serve both directly. For loopback NATS, use the SSH
tunnel below. Both configs use the same canonical lowercase UUID for `lane`.

The Mac must have noninteractive SSH access to the requester through a pinned
host key, with permission for `-W localhost:<callback-port>` forwarding. The
relay uses `BatchMode=yes` and `StrictHostKeyChecking=yes`.

NATS carries the browser launch request and ceremony status. Google returns the
authorization code through the requester's localhost callback, which SSH
forwards from the Mac. Authorization codes and tokens never enter NATS.

Grant the NATS users only these subjects:

| Role | Publish | Subscribe |
| --- | --- | --- |
| Requester | `oshioki.browser.v1.<lane>` | `oshioki.browser.v1.<lane>.reply.*` |
| Mac | `oshioki.browser.v1.<lane>.reply.*` | `oshioki.browser.v1.<lane>` |

Create a relay signing key on each machine, then exchange the public keys over
a trusted channel. These keys authenticate the relay peers; they are separate
from the Mac's Touch ID approval key.

```sh
mkdir -p ~/.config/oshioki/browser-relay
chmod 700 ~/.config/oshioki/browser-relay
oshioki-browser-relay keygen ~/.config/oshioki/browser-relay/signing.key
```

Save both JSON configs with mode 0600. Requester config at
`~/.config/oshioki/browser-relay/requester.json`:

```json
{
  "nats_url": "tls://requester-user:PASSWORD@nats.example.com:4222",
  "lane": "REPLACE_WITH_SHARED_LOWERCASE_UUID",
  "private_key": "/home/you/.config/oshioki/browser-relay/signing.key",
  "peer_public_key": "MAC_RELAY_PUBLIC_KEY",
  "google_account": "you@example.com",
  "approval_public_key": "MAC_IDENTITY_CREDENTIAL_PUBLIC_KEY"
}
```

Mac config at `~/.config/oshioki/browser-relay/approver.json`:

```json
{
  "nats_url": "tls://approver-user:PASSWORD@nats.example.com:4222",
  "lane": "REPLACE_WITH_SHARED_LOWERCASE_UUID",
  "private_key": "/Users/you/.config/oshioki/browser-relay/signing.key",
  "peer_public_key": "REQUESTER_RELAY_PUBLIC_KEY",
  "google_account": "you@example.com",
  "approval_identity": "/Users/you/.config/oshioki/browser-relay/agent.json",
  "ssh_destination": "requester-ssh-alias"
}
```

Both configs must name the same Google account. The requester pins the Mac's
approval public key; the Mac config names the matching identity. Older configs
that omit the account fields use the browser relay without account-bound Touch
ID approval. Percent-encode special characters in NATS URL credentials. Keep
passwords in the private files, not command arguments.

Start the approver on the Mac in a foreground session:

```sh
oshioki-browser-relay serve --config ~/.config/oshioki/browser-relay/approver.json
```

Adding or removing a Touch ID fingerprint invalidates the approval identity.
Replace the ceremony identity and update its public key in each config that
uses it. See [Mac approval recovery](mac-approvals.md#prompts-and-recovery).

### Optional services

`oshioki-browser-service` installs services for existing configs; it does not
create keys, identities, or NATS config. Without `--start`, it writes the
service definition only. Install a receiver service instead of running the
foreground `serve` command. For a direct TLS broker, install it in the Mac's
logged-in GUI session. This is the only service needed for direct TLS:

```sh
oshioki-browser-service install receiver \
  --config "$HOME/.config/oshioki/browser-relay/approver.json" \
  --relay "$(command -v oshioki-browser-relay)" \
  --start
```

The LaunchAgent runs while you are logged in. Check its status and log with:

```sh
launchctl print gui/$(id -u)/io.oshioki.browser-relay.receiver
tail -f ~/Library/Logs/Oshioki/browser-relay/receiver.err.log
```

Remove it with `oshioki-browser-service uninstall receiver`.

### Loopback NATS over SSH

For a broker on the requester, bind NATS to loopback and forward it to the Mac
through the pinned SSH alias. Install `nats-server` separately on the requester.
Save this as `nats.conf` with mode 0600, replacing the lane UUID and passwords
with your own. Choose another port if 4222 is occupied, and use it in both
configs and the tunnel endpoints.

```conf
host: 127.0.0.1
port: 4222
authorization {
  users = [
    { user: "requester", password: "RANDOM_REQUESTER_PASSWORD", permissions: {
      publish: ["oshioki.browser.v1.LANE_UUID"],
      subscribe: ["oshioki.browser.v1.LANE_UUID.reply.*"]
    } },
    { user: "approver", password: "RANDOM_APPROVER_PASSWORD", permissions: {
      publish: ["oshioki.browser.v1.LANE_UUID.reply.*"],
      subscribe: ["oshioki.browser.v1.LANE_UUID"]
    } }
  ]
}
```

Set each `nats_url` to its local user at
`nats://USER:PASSWORD@127.0.0.1:4222`, percent-encoding password characters.
Keep both JSON configs private. On the Linux requester, start the broker service:

```sh
oshioki-browser-service install broker \
  --config "$HOME/.config/oshioki/browser-relay/nats.conf" \
  --nats-server "$(command -v nats-server)" \
  --start
```

On the Mac, start the SSH tunnel and receiver:

```sh
oshioki-browser-service install tunnel \
  --ssh-destination requester \
  --local-port 4222 --remote-port 4222 --start
oshioki-browser-service install receiver \
  --config "$HOME/.config/oshioki/browser-relay/approver.json" \
  --relay "$(command -v oshioki-browser-relay)" \
  --start
```

Check tunnel status and logs on the Mac, and broker status and logs on the
requester:

```sh
launchctl print gui/$(id -u)/io.oshioki.browser-relay.tunnel
tail -f ~/Library/Logs/Oshioki/browser-relay/tunnel.err.log
systemctl --user status oshioki-browser-relay-nats.service
journalctl --user -u oshioki-browser-relay-nats.service -f
```

Remove them with `oshioki-browser-service uninstall tunnel` on the Mac and
`oshioki-browser-service uninstall broker` on the requester.

After the Mac receiver is running, run `gcloud auth login` on the requester.
The wrapper starts the remote flow. Keep both relay peers on the same release.
After updating, restart any running `serve` process; see [update and restore](update.md).
