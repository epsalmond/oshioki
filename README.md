# Oshioki

<p align="center"><img src="assets/oshioki.svg" alt="Oshioki logo" width="160"></p>

Oshioki (お仕置き) adds Touch ID, WebAuthn, or native device approval to
`sudo`.
WebAuthn runs in a phone browser. Native approvals use `oshioki-agent`.

Requests are encrypted and approvals are signed. A local Unix socket is
available for native approvals. NATS with JetStream connects hosts, servers,
and approval devices.

Licensed under MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).

## Install

Debian or Ubuntu (amd64), from the
[latest release](https://github.com/epsalmond/oshioki/releases):

```bash
sudo apt install ./oshioki_X.Y.Z_amd64.deb
```

macOS (Apple Silicon):

```bash
brew install epsalmond/oshioki/oshioki
```

From a source checkout:

```bash
cargo build --locked --release --workspace
```

Follow the [runbook](RUNBOOK.md) to install the hook from a source build.

## Choose a setup

### Local Mac with Touch ID

Run setup as your logged-in user:

```bash
oshioki-laptop-setup --local
```

On macOS, this creates a Secure Enclave identity, uses Touch ID for each
approval, and starts the agent with a LaunchAgent. The local setup needs no
server. On Linux, it creates a software native identity, writes the agent
environment, and prints the command to run it in a terminal; normal sudo
password authentication remains required.

See [Mac approvals](docs/mac-approvals.md) and the [runbook](RUNBOOK.md) for
manual setup and recovery.

### Phone

Run setup on the host as your normal user, then enroll the phone:

```bash
oshioki-phone-setup
sudo oshioki enroll
```

The default uses a local Oshioki server, NATS with JetStream, and Tailscale
Serve. Open the printed URL in a browser on a phone connected to the same
tailnet. An existing HTTPS server is supported too:

```bash
oshioki-phone-setup \
  --server-url https://sudo.example.com \
  --nats-config /path/to/hook-nats.env
sudo oshioki enroll
```

See [phone enrollment](docs/phone-enrollment.md) for prerequisites, service
management, and the HTTPS server option.

### Native device

Start enrollment on the host:

```bash
sudo oshioki enroll
```

On the device, run the command printed by `enroll`, then start the agent:

```bash
oshioki-agent pair '<enrollment-url>' --label <label>
oshioki-agent run
```

macOS uses the Secure Enclave by default. Other platforms use a software
key. Software native identities still require the normal sudo password.
See [native agent](docs/native-agent.md) for identity state, offline pairing,
and the macOS LaunchAgent.

For a host that cannot reach the server, export the public device record on
the approval device, copy it to the host, and pin it there:

```bash
oshioki-agent init
oshioki-agent device-record --label <label> > /tmp/oshioki-device.json
# Copy /tmp/oshioki-device.json to the host.
sudo oshioki pin-record /tmp/oshioki-device.json
```

### Remote host

Install the hook on each host that needs approval. Run an Oshioki server with
NATS and JetStream, then give the hook and each native agent separate NATS
credentials. NATS connections outside loopback require TLS with a trusted,
hostname-matched certificate. The plaintext opt-out is for local testing
only.

See [production requirements](docs/requirements.md),
[configuration](docs/configuration.md), and the [runbook](RUNBOOK.md).

## Command reference

Run host commands as root because they read or update `/etc/oshioki`.

| Command | Purpose |
| --- | --- |
| `sudo oshioki enroll` | Create an enrollment URL and wait for a device. |
| `sudo oshioki enroll --resume <enrollment-id>` | Resume an enrollment. |
| `sudo oshioki pin <fingerprint>` | Fetch and pin a device from the server. |
| `sudo oshioki pin-record <path>` | Pin a JSON device record from a file. |
| `sudo oshioki revoke <fingerprint>` | Revoke a device on the server and host. |
| `sudo oshioki status` | Show sudo authentication and enrolled devices. |
| `sudo oshioki watch` | Open browser approval pages for incoming requests. |
| `sudo oshioki test` | Send a synthetic request through the approval flow. |

Use `oshioki --help` for the public command list and
`oshioki-agent --help` for the native agent. In Kitty-compatible terminals,
including WezTerm and Ghostty, either top-level help command also shows the
embedded Oshioki logo. Pipes and tmux or screen sessions stay plain text.

The native agent has separate commands for pairing, running, inspecting, and
exporting an identity:

```bash
oshioki-agent --help
oshioki-agent pair '<enrollment-url>' --label <label>
oshioki-agent run
oshioki-agent show
```

## Configure

The hook reads its state from `/etc/oshioki` by default. The native agent uses
`~/.config/oshioki` unless `OSHIOKI_AGENT_STATE` or `--state` changes it.

The hook can try a native agent Unix socket before falling back to NATS. A
socket-only host omits `NATS_URL` from its hook configuration. Browser
WebAuthn approval still needs the Oshioki server.

Use `tls://` for NATS outside loopback. Set
`OSHIOKI_ALLOW_PLAINTEXT_NATS=1` only in the component's development
configuration. Keep hook, agent, and server credentials separate.

See [configuration](docs/configuration.md) for environment variables,
[architecture](docs/architecture.md) for the request flow, and
[security](SECURITY.md) for reporting vulnerabilities.

## Develop it

Start with [CONTRIBUTING.md](CONTRIBUTING.md):

```bash
scripts/dev build
scripts/dev test --quick
```

The [runbook](RUNBOOK.md) covers supervised acceptance sessions and host
installation details. [CHANGELOG.md](CHANGELOG.md) records release changes.
