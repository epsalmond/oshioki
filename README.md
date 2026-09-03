# Oshioki

<p align="center"><img src="assets/oshioki.svg" alt="Oshioki logo" width="160"></p>

Oshioki (お仕置き): the sound of a keypress, and a pun on "punishment" for when
root misbehaves.

Touch ID or WebAuthn approval for sudo requests.

NATS is used as the transport, because it's cool. Requests are encrypted, and
approvals are signed.

Licensed under MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).

Prelaunch: local use only.

## Use it

You need a reachable NATS server with JetStream alongside the Oshioki server
(for now) — see [docs/configuration.md](docs/configuration.md).

Enroll a device from the host:

```bash
oshioki enroll
```

That prints an enrollment URL. Open it in a browser to enroll WebAuthn, or hand
it to a native device:

```bash
oshioki-agent pair '<enrollment-url>' --label <label>
oshioki-agent run
```

From then on, each sudo request asks that device: a Touch ID sheet on a Mac, a
terminal prompt elsewhere. Details in
[docs/native-agent.md](docs/native-agent.md) and
[docs/mac-approvals.md](docs/mac-approvals.md).

```bash
oshioki status               # enrolled devices
oshioki revoke <fingerprint> # remove one
```

Installing the hook and running acceptance sessions is covered in the
[runbook](RUNBOOK.md).

### Run your own server

The server needs NATS with JetStream next to it. Everything production must
provide is in [docs/requirements.md](docs/requirements.md); every variable is
in [docs/configuration.md](docs/configuration.md). Either install the `.deb`
and create `/etc/oshioki/server.env`, then
`systemctl enable --now oshioki-server`, or build from source with
`cargo build --locked --release -p oshioki-server`.

## Develop it

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Internals live in
[docs/architecture.md](docs/architecture.md),
[docs/configuration.md](docs/configuration.md), and
[docs/requirements.md](docs/requirements.md). [CHANGELOG.md](CHANGELOG.md)
tracks the road to 1.0; report vulnerabilities per [SECURITY.md](SECURITY.md).
