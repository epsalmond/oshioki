# Contributing to Oshioki

## Prerequisites

- Rust via rustup (pinned toolchain in `rust-toolchain.toml`; `cargo` picks it
  up automatically).
- Docker (rootful or rootless) for the Compose-based tests and dev server.
- Node.js for the browser UI tests (`server/web`, Playwright + libsodium).
- Tailscale only for the Safari/Mac acceptance loops.

## Development loop

All entry points go through `scripts/dev`:

```bash
scripts/dev build          # workspace build + browser unit tests
scripts/dev test --quick   # Rust suite, browser vectors, installer checks (host only)
scripts/dev test --browser # browser protocol against local NATS + SQLite
scripts/dev test           # full E2E: disposable Compose project + real sudo plugin path
scripts/dev up [--state-dir PATH]  # retained dev server on http://127.0.0.1:8443
scripts/dev status
scripts/dev down
```

`--quick` runs on the host. The full `test` creates a disposable Compose
project and also invokes the real Linux sudo plugin path; non-Linux hosts skip
the acceptance lifecycle test, which relies on Linux process identity. Failed
runs retain their state path and scrubbed Compose logs.

Without `--state-dir`, `up` creates disposable state and `down` removes it.
Direct Compose callers (not going through `scripts/dev`) must set
`OSHIOKI_UID` to the host UID for rootful Docker or `0` for rootless Docker;
`scripts/dev` derives this automatically.

Supervised acceptance sessions (Linux Tailscale host, Safari, Mac approver)
use `scripts/dev-acceptance`; see the [runbook](RUNBOOK.md).

## Expectations

- `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, and
  `scripts/dev test --quick` pass before opening a PR.
- The workspace denies warnings and `unsafe_code`, with the only exceptions
  documented in the root `Cargo.toml`. Every `unsafe` call lives in the
  `enclave` crate, macOS only.
- Protocol changes require a new version and a compatibility decision: see
  [docs/architecture.md](docs/architecture.md). The v1 cryptographic domain
  strings (`oshioki/...`) and existing test vectors must not change.
- Add or update tests with behavior changes; update this file and the
  affected `docs/` page when the workflow changes.
- Security-sensitive change? Read [SECURITY.md](SECURITY.md) first and
  report vulnerabilities privately, never in a public issue or PR.
