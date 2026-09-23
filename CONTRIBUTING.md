# Develop Oshioki

Use Rust through rustup (the checkout pins its toolchain), Node.js/npm for
browser tests, and Python 3 for setup tests. Linux needs `libpam0g-dev`.
Docker with Compose is required for the full end-to-end suite; `nats-server`
is required for the browser relay suite.

## Everyday loop

```sh
scripts/dev build
scripts/dev test --quick
```

`build` builds the workspace and runs browser unit tests. `--quick` runs
Rust tests, Clippy, browser vectors, and installer/setup checks on the host.
Linux-only checks report a skip elsewhere. On macOS, use `TMPDIR=/tmp` if
Unix-socket tests exceed the platform's socket path limit.

Choose additional checks for the behavior changed:

| Command | Exercises |
| --- | --- |
| `scripts/dev test --browser` | Browser protocol against local NATS and SQLite |
| `scripts/dev test` | Quick checks plus disposable Compose and real Linux sudo integration |
| `scripts/test-browser-relay` | Google ceremony orchestration, authenticated NATS, and subprocess cleanup with fake provider/device boundaries |
| `scripts/test-pam-acceptance` | PAM integration in a disposable container |
| `scripts/test-oshioki-phone-setup` | Phone setup with service and privilege boundaries replaced |

The automated sudo tests run in containers; they do not install a plugin on
your host. Failed full-suite runs retain their state path and Compose logs.

## Keep a development server running

```sh
scripts/dev up --state-dir /path/to/dev-state
scripts/dev status
scripts/dev down
```

The server is at `http://127.0.0.1:8443`. An explicit state directory survives
`down`; without one, setup creates temporary state and removes it on shutdown.
The wrapper handles rootful/rootless Docker UID mapping. Direct Compose users
must set `OSHIOKI_UID` themselves (host UID for rootful Docker, 0 for rootless).

## Before a PR

Run `cargo fmt --check` and `scripts/dev test --quick`, plus the relevant checks
above. Update the affected journey or reference when behavior changes.

Public protocol and persistence changes follow the
[compatibility contract](docs/compatibility.md): additive wire fields need a
golden and a matrix entry; incompatible semantics need a version and restore
plan. Keep existing v1 cryptographic domains and test vectors unchanged.

Unsafe code is limited to the existing enclave, sudo plugin, and PAM boundaries.
Read [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## Package verification

`scripts/build-darwin-artifact OUTPUT_DIR` builds the Mac release, including
the browser relay, setup tools, and agent app bundle. It checks architecture,
signing, framework linkage, manifest entries, and checksums.
`CARGO_TARGET_DIR` selects an isolated build directory. `packaging/build-deb`
assembles Linux release binaries and setup tools and checks their architecture
and runtime dependencies.

The release workflow extracts each package and runs:

```sh
scripts/test-browser-relay-package /path/to/oshioki-browser-relay /path/to/SHA256SUMS --with-installers
```

This checks the shipped helper's hash, commands, private key creation, and
the extracted gcloud/service setup tools' hashes and CLI help without
contacting Google or asking for Touch ID. The separate Homebrew tap installs
the setup tools when the release archive contains them; its formula test
requires their manifest entries and checks their hashes and CLI help.

## Supervised acceptance

Automated provider/device substitutes do not prove physical Touch ID, Google
policy, or phone notification delivery. Use a test host with a retained root
shell for these sessions.

For a Linux Tailscale host and Mac approver:

```sh
# On the host:
scripts/dev-acceptance mac
# Follow its printed pairing command on the Mac, then on the host:
scripts/dev-acceptance test
scripts/dev-acceptance down
```

Each test sends one synthetic request. Check approval, cancellation, and expiry
separately. If you installed a real host plugin during the session,
[disable it](RUNBOOK.md#restore-ordinary-sudo) before stopping its services.

Use the [phone](docs/phone-enrollment.md) and
[Google login](docs/browser-ceremony-relay.md) guides for those acceptance
journeys. Record the build, what the person observed, and any untested path.
