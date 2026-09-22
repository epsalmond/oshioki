# Approve a browser login

Oshioki can require one Touch ID approval before establishing or renewing
Google CLI access. It supports a login on the same Mac or a login on a remote
host approved from that Mac.

| Journey | Command |
| --- | --- |
| Google login on this Mac | `oshioki-browser-relay local-login --config …` |
| Google login on a server or VM | `oshioki-browser-relay login --config …` on the host, with `serve` on the Mac |
| `vercel login` or another provider | Not implemented; there is no generic browser adapter. |

Use the helper explicitly. Running bare `gcloud auth login` does not invoke
Oshioki. After approval, gcloud owns the credentials and routine commands can
refresh them normally. Google may still require account selection, consent,
a password, or a passkey; Touch ID does not replace Google's authentication.

## Install

[Install Oshioki](install.md) and install Google Cloud CLI separately on the
machine that will run gcloud. The relay is included in the next release after
0.1.15, in both Homebrew's Mac package and the Debian package. The Mac package
also includes the agent used to create the approval identity.

For an earlier release or a source checkout:

```sh
cargo build --locked --release -p oshioki-agent -p oshioki-browser-relay
export PATH="$PWD/target/release:$PATH"
```

Confirm that the required commands are available:

```sh
oshioki-browser-relay --help
gcloud --version
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

- A private TLS NATS broker reachable by both machines, with separate users.
  This relay uses core NATS; it needs no Oshioki server or JetStream stream.
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

### Run

On the Mac, leave this foreground receiver running:

```sh
oshioki-browser-relay serve --config ~/.config/oshioki/browser-relay/approver.json
```

On the requester:

```sh
oshioki-browser-relay login --config ~/.config/oshioki/browser-relay/requester.json
```

Approve on the Mac. When Google requires a browser, the relay forwards the
localhost callback over short-lived SSH connections; credentials remain on
the requester. Callback codes and tokens do not cross NATS.

## Update or troubleshoot

Upgrade both peers together and restart `serve`. Preserve the configuration
and keys; a routine package update needs no new identity or enrollment.

| Symptom | Check |
| --- | --- |
| Command not found | Package must include the relay; older releases need the source build. |
| Private-file error | Config and signing key must be regular private files, normally mode 0600. |
| No Touch ID | Use the graphical Mac session and a Secure Enclave identity; software keys cannot approve. |
| Remote receiver never becomes ready | NATS TLS/authentication, subject permissions, matching lane and peer keys. |
| Approval succeeds but browser login fails | SSH access to the requester and Google's browser flow. |
| Identity key invalid after changing Touch ID fingerprints | Create a replacement ceremony identity and update its public key in the local/requester config. |

Automated tests use fake Google and Mac boundaries. They verify orchestration,
signatures, broker authentication, callback forwarding, and cleanup; they do
not replace a real Google/Touch ID acceptance run.
