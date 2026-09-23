# Oshioki

<p align="center"><img src="assets/oshioki.svg" alt="Oshioki logo" width="160"></p>

Oshioki (お仕置き) puts the pun in punishment.

Adds Touch ID, WebAuthn, or native device approval to `sudo`.

WebAuthn runs in a WebAuthn-compatible browser. Native approvals use
`oshioki-agent`.

Requests are encrypted and approvals are signed. A local Unix socket is
available for native approvals. NATS with JetStream connects your servers, VMs,
etc to your phone or laptop.

## Install

macOS (Apple Silicon):

```sh
brew install epsalmond/oshioki/oshioki
oshioki-laptop-setup --local
```

Debian or Ubuntu (amd64), from the
[latest release](https://github.com/epsalmond/oshioki/releases):

```sh
sudo apt install ./oshioki_X.Y.Z_amd64.deb
```

The Mac setup creates a Touch ID identity and starts the agent; no server is
needed. On Linux, install the package, then choose an approval device below.
See [installation](docs/install.md) for source builds and host activation.

## Choose your task

| I want to… | Guide |
| --- | --- |
| Approve sudo on this Mac | [Local sudo](docs/local-sudo.md) |
| Approve a server or VM's sudo from my Mac | [Remote sudo](docs/remote-sudo.md) |
| Approve sudo from my phone | [Phone enrollment](docs/phone-enrollment.md) |
| Approve a Google CLI login with Touch ID, locally or remotely | [Browser ceremonies](docs/browser-ceremony-relay.md) |
| Update an existing installation | [Update and restore](docs/update.md) |
| Build, change, or test Oshioki | [Contributing](CONTRIBUTING.md) |
| Diagnose an approval or recover sudo | [Runbook](RUNBOOK.md) |

An opt-in setup helper can route the exact `gcloud auth login` command through
the browser relay; other gcloud commands and login forms with flags pass
through unchanged. Vercel login is not supported yet. See the
[Google Cloud CLI login guide](docs/browser-ceremony-relay.md).

## Reference

[Configuration](docs/configuration.md) ·
[Native identity and pairing](docs/native-agent.md) ·
[Mac approval behavior](docs/mac-approvals.md) ·
[Server requirements](docs/requirements.md) ·
[Architecture](docs/architecture.md) ·
[Transport contract](docs/transports.md) ·
[Compatibility contract](docs/compatibility.md)

[Security policy](SECURITY.md) · [Changelog](CHANGELOG.md) ·
Licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).
