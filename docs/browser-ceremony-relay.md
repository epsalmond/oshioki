# Google Cloud CLI login

Oshioki can route the exact command `gcloud auth login` through the browser
relay after you opt in with `oshioki-google-login-setup`. The wrapper leaves
every other gcloud command alone, including `gcloud auth login` with extra
flags. It supports a login on the same Mac or on a remote requester approved
from the Mac.

The relay reuses usable cached credentials and invokes Google's browser flow
when Google requires sign-in or reauthentication. Complete any Google account
checks in the browser; the routed flow returns the result to gcloud
automatically. Gcloud credentials stay in the normal gcloud profile. In
account-bound mode, Touch ID authorizes the configured account before gcloud
proceeds.

| Journey | Command |
| --- | --- |
| Google login through the opt-in wrapper | `gcloud auth login` |
| Google login on this Mac | `oshioki-browser-relay local-login --config …` |
| Google login on a server or VM | `oshioki-browser-relay login --config …` on the host, with `serve` on the Mac |
| `vercel login` or another provider | Not implemented; there is no generic browser adapter. |

Bare `gcloud auth login` invokes Oshioki only after you install its opt-in
wrapper below. Before installation, the command behaves as Google Cloud CLI
documents it. After sign-in, gcloud owns the credentials and routine commands
can refresh them normally. Google may still require account selection,
consent, a password, or a passkey; Touch ID does not replace Google's
authentication.

## Install

[Install Oshioki](install.md) and install Google Cloud CLI separately on the
machine that will run gcloud. The release carrying these changes includes the
relay, the opt-in gcloud wrapper setup tool, and the background service setup
tool in both Homebrew's Mac archive and the Debian package. These setup tools
need Python 3.9 or newer; the packages declare that runtime dependency. Google
Cloud CLI remains separate.

For an earlier release or a source checkout:

```sh
cargo build --locked --release -p oshioki-agent -p oshioki-browser-relay
export PATH="$PWD/scripts:$PWD/target/release:$PATH"
```

The setup tools in `scripts/` require Python 3.9 or newer.

Confirm that the required commands are available:

```sh
oshioki-browser-relay --help
gcloud --version
```

### Connect plain `gcloud auth login`

Create the local or requester config described below before installing the
wrapper. Resolve the real gcloud executable **before** installing it. The
setup command pins that path so the wrapper can safely delegate other gcloud
commands without calling itself:

```sh
real_gcloud="$(command -v gcloud)"
oshioki-google-login-setup install \
  --mode requester \
  --config "$HOME/.config/oshioki/browser-relay/requester.json" \
  --gcloud "$real_gcloud"
```

Use `--mode local` with `local.json` on the Mac that runs gcloud. Use
`--mode requester` with `requester.json` on the remote host that stores the
gcloud credentials. If the relay binary is not on `PATH`, pass its absolute
path with `--relay`. The wrapper is installed in `~/.local/bin` by default;
that directory must be owned by your user and not writable by group or
others. Its parent directories must not be group- or world-writable unless
they have the sticky bit. If the default path fails those checks, create a
private bin directory and pass it explicitly. Put the selected bin directory
before the real gcloud path on `PATH`, then refresh the shell's command lookup
(`hash -r` in Bash or `rehash` in zsh). For a private alternative:

```sh
mkdir -p "$HOME/.oshioki/bin"
chmod 700 "$HOME/.oshioki" "$HOME/.oshioki/bin"
oshioki-google-login-setup install \
  --mode requester \
  --config "$HOME/.config/oshioki/browser-relay/requester.json" \
  --gcloud "$real_gcloud" \
  --bin-dir "$HOME/.oshioki/bin"
export PATH="$HOME/.oshioki/bin:$PATH"
hash -r
gcloud auth login
```

Only the no-argument form above is routed through Oshioki. Other gcloud
commands and login forms with flags go directly to the pinned gcloud
executable. Remove the opt-in wrapper with:

```sh
oshioki-google-login-setup uninstall
```

If you installed to a custom `--bin-dir`, pass the same directory when
uninstalling, for example:

```sh
oshioki-google-login-setup uninstall --bin-dir "$HOME/.oshioki/bin"
```

Local approval requires macOS, Touch ID, Secure Enclave, and a graphical login
session. Sudo installation, a server, NATS, and SSH are unnecessary for a
local login.

## Local login

### Create the approval identity once

Run as the user who owns the gcloud profile:

```sh
mkdir -p ~/.config/oshioki/browser-relay
chmod 700 ~/.config/oshioki/browser-relay
oshioki-agent init --signer enclave --state ~/.config/oshioki/browser-relay
oshioki-agent device-record --state ~/.config/oshioki/browser-relay --label browser-relay
```

Use a separate identity from the sudo agent. Copy its public
`credential_public_key` into `approval_public_key` below.

Create `~/.config/oshioki/browser-relay/local.json` with mode 0600 and this
content, substituting your account, absolute identity path, and public key:

```json
{
  "google_account": "you@example.com",
  "approval_identity": "/Users/you/.config/oshioki/browser-relay/agent.json",
  "approval_public_key": "IDENTITY_CREDENTIAL_PUBLIC_KEY",
  "local_label": "this Mac"
}
```

JSON paths must be absolute; `~` is not expanded inside the file.

### Request a login

```sh
chmod 600 ~/.config/oshioki/browser-relay/local.json
oshioki-browser-relay local-login --config ~/.config/oshioki/browser-relay/local.json
```

Approve the named account with Touch ID. If stored credentials are usable,
gcloud can finish without opening a browser. Otherwise, complete Google's
browser flow; gcloud handles its own localhost callback. The helper checks
credential usability without printing the token.

Success is the helper exiting zero. Denying or letting approval expire starts
no gcloud process. Interrupting an active attempt stops its helper processes.

## Remote login

Here the **requester** runs gcloud and stores its credentials; the **Mac**
shows Touch ID and, when needed, opens the browser.

### Prepare the connection

Install the relay on both machines and create the Mac approval identity above.
You also need:

- A private NATS broker reachable by both machines, with separate users. It
  can use TLS directly or an authenticated loopback listener reached through
  an SSH tunnel, as described below. This relay uses core NATS; it needs no
  Oshioki server or JetStream stream.
- A shared canonical UUID for `lane` (lowercase).
- Noninteractive SSH from the Mac to the requester, with a pinned host key
  and permission for `-W localhost:<callback-port>` forwarding.
  The relay uses `BatchMode=yes` and `StrictHostKeyChecking=yes`.

Give each NATS user only these subjects:

| Role | Publish | Subscribe |
| --- | --- | --- |
| Requester | `oshioki.browser.v1.<lane>` | `oshioki.browser.v1.<lane>.reply.*` |
| Mac | `oshioki.browser.v1.<lane>.reply.*` | `oshioki.browser.v1.<lane>` |

On **each** machine, create its relay signing key:

```sh
mkdir -p ~/.config/oshioki/browser-relay
chmod 700 ~/.config/oshioki/browser-relay
oshioki-browser-relay keygen ~/.config/oshioki/browser-relay/signing.key
```

Exchange the printed public keys over a trusted channel. These authenticate
the relay peers; they are separate from the Mac's Touch ID approval key.

### Configure each machine

Save each JSON file with mode 0600. Requester
(`~/.config/oshioki/browser-relay/requester.json`):

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

Mac (`~/.config/oshioki/browser-relay/approver.json`):

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

Percent-encode special characters in URL credentials. Keep passwords in these
private files, not command arguments. Both configurations must name the same
Google account. Keep the account approval fields: legacy configurations that
omit all of them use a browser-only relay without the account approval step.

### Optional background services

`oshioki-browser-service` installs per-user services for an existing config;
it does not create relay keys, identities, or NATS config. Without `--start`
it only writes the service definition. On the Mac, install the receiver in
your logged-in GUI session:

```sh
oshioki-browser-service install receiver \
  --config "$HOME/.config/oshioki/browser-relay/approver.json" \
  --relay "$(command -v oshioki-browser-relay)" \
  --start
```

The LaunchAgent keeps the receiver running while you are logged in. For a
direct TLS NATS broker, this is the only service required. Remove it with
`oshioki-browser-service uninstall receiver`.

### Optional loopback NATS over SSH

For a broker on the requester host, keep NATS bound to loopback and let SSH
carry its traffic to the Mac. The NATS ACL should match the table above; give
the two users separate random passwords and substitute the same lane UUID in
both subject lists:

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

Replace the sample lane and passwords with your own values. Save the NATS
configuration as `nats.conf` with mode 0600 and install `nats-server`
separately on the requester. Choose an unused port if 4222 is occupied, and
use that same port in the listener, both configs, and the tunnel endpoints.
Set the requester and Mac `nats_url` values to their respective users at
`nats://USER:PASSWORD@127.0.0.1:4222`, percent-encoding password characters
as needed. Keep both JSON configs private. On the requester, install the
broker service:

```sh
oshioki-browser-service install broker \
  --config "$HOME/.config/oshioki/browser-relay/nats.conf" \
  --nats-server "$(command -v nats-server)" \
  --start
```

On the Mac, forward the same loopback port through a pinned SSH alias to the
requester, then start the receiver:

```sh
oshioki-browser-service install tunnel \
  --ssh-destination requester \
  --local-port 4222 --remote-port 4222 --start
oshioki-browser-service install receiver \
  --config "$HOME/.config/oshioki/browser-relay/approver.json" \
  --relay "$(command -v oshioki-browser-relay)" \
  --start
```

The tunnel and receiver are LaunchAgents; the broker is a systemd user
service. The SSH tunnel encrypts the loopback NATS traffic. Do not bind this
broker to a network interface. Check Mac service state with
`launchctl print gui/$(id -u)/io.oshioki.browser-relay.receiver` and
`launchctl print gui/$(id -u)/io.oshioki.browser-relay.tunnel`; private logs
are under `~/Library/Logs/Oshioki/browser-relay/`. Check the broker with
`systemctl --user status oshioki-browser-relay-nats.service` and
`journalctl --user -u oshioki-browser-relay-nats.service`. Remove roles on
their host with `oshioki-browser-service uninstall ROLE`.

### Run

After installing the opt-in wrapper on the requester and starting the Mac
receiver, run the unmodified command on the requester:

```sh
gcloud auth login
```

Approve on the Mac when prompted. If Google requires a browser, gcloud opens
it and receives the localhost callback through a short-lived SSH connection;
credentials remain on the requester. Callback codes and tokens do not cross
NATS. The explicit command remains available for troubleshooting:

```sh
oshioki-browser-relay login --config ~/.config/oshioki/browser-relay/requester.json
```

## Update or troubleshoot

Upgrade both peers together and restart `serve`. Preserve the configuration
and keys; a routine package update needs no new identity or enrollment.

| Symptom | Check |
| --- | --- |
| Command not found | Package must include the relay; older releases need the source build. |
| Private-file error | Config and signing key must be regular private files, normally mode 0600. |
| No Touch ID | Use the graphical Mac session and a Secure Enclave identity; software keys cannot approve. |
| Remote receiver never becomes ready | NATS authentication, subject permissions, matching lane and peer keys, and the TLS connection or SSH tunnel. |
| Approval succeeds but browser login fails | SSH access to the requester and Google's browser flow. |
| Identity key invalid after changing Touch ID fingerprints | Create a replacement ceremony identity and update its public key in the local/requester config. |

Automated tests use fake Google and Mac boundaries. They verify orchestration,
signatures, broker authentication, callback forwarding, and cleanup; they do
not replace a real Google/Touch ID acceptance run.
