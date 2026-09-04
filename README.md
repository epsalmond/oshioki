# Oshioki

<p align="center"><img src="assets/oshioki.svg" alt="Oshioki logo" width="160"></p>

Oshioki (お仕置き): the sound of a keypress, and a pun for "punishment."

TouchID or WebAuthn approval (from your phone) for sudo requests. Works for
agents, remote servers, VMs, containers or anywhere that has network access to
your approval device.

Requests are encrypted, and approvals are signed, so forging an approval is
difficult. gpt-5.6-daybreak was used to look for vulnerabilities.

NATS is used as the transport, because it's cool. A local socket is also
supported (but isn't as cool.)

Licensed under MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).

## Install

Debian/Ubuntu (amd64), from the
[latest release](https://github.com/epsalmond/oshioki/releases):

```bash
sudo apt install ./oshioki_X.Y.Z_amd64.deb
```

macOS (Apple Silicon):

```bash
brew install epsalmond/oshioki/oshioki
```

From source (any platform with Rust):

```bash
cargo build --locked --release -p oshioki-hook -p oshioki-server
```

then wire up the hook with `scripts/install-oshioki-hook` — see the
[runbook](RUNBOOK.md).

## Configure

You need a reachable NATS server with JetStream alongside the Oshioki server
(for now) — see [docs/configuration.md](docs/configuration.md).

NATS connections past your own machine require TLS: use `tls://` URLs, with
the server presenting a certificate your system trusts (hostname-verified
against the system roots). Plaintext `nats://` works only for loopback
hosts — anything else is refused at startup. For testing without server
certificates (Compose, the dev scripts), set `OSHIOKI_ALLOW_PLAINTEXT_NATS=1`
in the component's own config channel: the process environment for the
server and the agent, `config.env` for the hook (sudo scrubs its
environment). Never set it in production. Give each component role — hook,
agent, server — its own NATS user, so one leaked credential does not open
the whole control plane.

Enroll a device from the host:

```bash
oshioki enroll
```

That prints an enrollment URL. Open it in a browser to enroll WebAuthn, or run
this from your terminal:

```bash
oshioki-agent pair '<enrollment-url>' --label <label>
oshioki-agent run
```

From then on, sudo requests will ask for your fingerprint to approve. Details in
[docs/native-agent.md](docs/native-agent.md) and
[docs/mac-approvals.md](docs/mac-approvals.md).

```bash
oshioki status               # enrolled devices
oshioki revoke <fingerprint> # remove one
```

Installing the hook and running acceptance sessions is covered in the
[runbook](RUNBOOK.md).

### Server

If you are running on remote servers, NATS with JetStream is needed to reach
your laptop. See [docs/requirements.md](docs/requirements.md) and
[docs/configuration.md](docs/configuration.md). Either install the `.deb` and
create `/etc/oshioki/server.env`, then `systemctl enable --now oshioki-server`,
or build from source with `cargo build --locked --release -p oshioki-server`.

## Develop it

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Internals live in
[docs/architecture.md](docs/architecture.md),
[docs/configuration.md](docs/configuration.md), and
[docs/requirements.md](docs/requirements.md). [CHANGELOG.md](CHANGELOG.md)
tracks the road to 1.0; report vulnerabilities per [SECURITY.md](SECURITY.md).
