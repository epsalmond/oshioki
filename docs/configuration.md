# Configuration

Values shown are the local development defaults from `compose.yaml`. Production
values are for production to choose; see [requirements.md](requirements.md).

## Server

| Variable | Dev default | Notes |
|---|---|---|
| `OSHIOKI_ORIGIN` | `https://sudo.test` | WebAuthn origin the hook enrolls and verifies against. |
| `OSHIOKI_RP_ID` | `sudo.test` | WebAuthn relying-party ID. |
| `OSHIOKI_LISTEN` | `0.0.0.0:8443` | Bind address; the binary defaults to `127.0.0.1:8443`. |
| `OSHIOKI_STATE_PATH` | `/state/state.sqlite3` | Writable SQLite path; one active server per database file. |
| `OSHIOKI_DARWIN_DIST` | unset | Optional directory of Darwin packages served as immutable artifacts. |
| `OSHIOKI_NTFY_URL` | unset | Optional ntfy broker URL. Messages carry host, user, request ID, and `/r/<id>` URL only — never request plaintext. |
| `OSHIOKI_TRANSPORT` | `nats` | Transport backend; the only value today. |
| `NATS_URL` | `nats://nats:4222` | JetStream server. Production uses `tls://` to any non-loopback host: plaintext `nats://` is refused past `localhost`, `127.0.0.0/8`, and `::1` unless the opt-out below is set. TLS validates against the system roots with hostname verification, so the server needs a publicly trusted certificate (on a tailnet, the node's MagicDNS certificate works). |
| `NATS_USER` / `NATS_PASS` | `oshioki` / `test-only` | Set both together or neither. Production gives each role its own user — e.g. `oshioki-server` here, `oshioki-hook` on hosts, `oshioki-agent` on devices — so one leaked credential does not open the whole control plane. Per-role publish/subscribe restrictions on the NATS server itself are planned (#20). |
| `OSHIOKI_ALLOW_PLAINTEXT_NATS` | unset | Testing opt-out for plaintext `nats://` past loopback: `1`, `true`, or `yes`. Honors Compose hostnames and tailnet addresses without certificates. Never set in production. |

## Hook (`oshioki` binary)

| Variable | Notes |
|---|---|
| `OSHIOKI_CONFIG_DIR` | Local hook state; defaults to `/etc/oshioki`. `config.env` accepts `OSHIOKI_TRANSPORT=nats` (default; the only value today). The hook reads NATS settings from `config.env` there (sudo scrubs its environment): `NATS_URL` follows the server's TLS rule, `NATS_USER` should be the host role's own user (e.g. `oshioki-hook`), and `OSHIOKI_ALLOW_PLAINTEXT_NATS` is the testing opt-out in file form. |
| `OSHIOKI_OPENER` | Test-only override: one executable path followed by one URL argument. Used by `watch` (defaults to `/usr/bin/open` on Darwin). |
| `OSHIOKI_AGENT_SOCKET` (in `config.env`) | Optional path to the agent's Unix socket. When set, the hook tries the socket first (short connect timeout) and falls back to NATS within the same approval deadline. Unset in dev, where the Compose NATS carries everything. |
| `NATS_URL` (in `config.env`) | Optional: absent means socket-only. The hook then never touches NATS — a silent agent denies at once instead of waiting out the deadline, and an empty transport set (no socket either) fails before any request is built. Installers verify a staged NATS before writing it and write no `NATS_*` keys otherwise, never placeholders. |

## Native agent (`oshioki-agent` binary)

| Variable | Notes |
|---|---|
| `OSHIOKI_AGENT_STATE` | Directory holding the 0600 `agent.json` identity; defaults to `~/.config/oshioki`. The agent also listens at `agent.sock` in this directory unless overridden below. |
| `OSHIOKI_AGENT_SOCKET` | Explicit socket path. A live socket there refuses a second agent; a stale file from a dead agent is reclaimed; a non-socket file is never deleted. |
| `NATS_URL` | Same host as the hook, `tls://` outside loopback. Optional at runtime: without NATS the agent answers socket requests only until restart. |
| `NATS_USER` / `NATS_PASS` | The device role's own user (e.g. `oshioki-agent`), not the hook's; setting only one of the pair is an error. |
| `OSHIOKI_ALLOW_PLAINTEXT_NATS` | Testing opt-out, same meaning as the server's. |

## Dev tooling (`scripts/dev`)

| Variable | Notes |
|---|---|
| `OSHIOKI_UID` / `OSHIOKI_HOST_UID` | Container/host UID mapping. `scripts/dev` derives these (host UID, or `0` under rootless Docker); set them manually only when invoking Compose directly. |
| `OSHIOKI_STATE_ROOT` / `OSHIOKI_HTTP_PORT` | State directory and host port for the Compose project; managed by `scripts/dev`. |

Test-only variables (`OSHIOKI_TEST_CONFIG_DIR`, `OSHIOKI_SERVER_HTTP`,
`OSHIOKI_E2E_*`) are set by the Compose E2E project; operators never need to
set them.
