# Run an approval server

Local Mac sudo and local Google login need no server.
For a phone on your tailnet, [phone setup](phone-enrollment.md) provisions the
server and broker. This page is for operating a shared deployment.

## Runtime

Provide:

- NATS 2.10 or newer with JetStream, reachable by hooks, server, and native agents.
- An existing `OSHIOKI` stream covering `oshioki.request.>` and `oshioki.auth.>`.
  The server repairs an older stream's subjects, but does not create a missing one.
- One active Oshioki server per SQLite database, with a persistent writable
  `OSHIOKI_STATE_PATH` and persistent VAPID key for Web Push.
- A trusted HTTPS origin reachable from enrolled browsers and hooks.
  Set `OSHIOKI_ORIGIN=https://sudo.example.com` and
  `OSHIOKI_RP_ID=sudo.example.com`.
- Service supervision, backups, health monitoring, and a previous release for restore.

The Debian package includes `oshioki-server.service`, running as user
`oshioki` with `/etc/oshioki/server.env`. Start it after provisioning its
environment and broker. A fresh package install enables the unit but does not
start it. An example environment ships under
`/usr/share/doc/oshioki/examples/server.env.example`.

Homebrew includes the server binary. Manage it through phone setup or your
own service supervisor. The repository also has a Compose development stack;
its credentials and plaintext networking are for tests.

## Network and roles

Use TLS for NATS outside loopback, with a certificate trusted by the client
and matching its hostname. Give the hook, agent, and server separate users.
The plaintext override is for development only.

Configure permissions for the traffic each role handles:

| Subjects/resources | Use |
| --- | --- |
| `oshioki.request.>`, `oshioki.auth.>` | Encrypted requests from hooks; native agent subscriptions and server consumption |
| `oshioki.verdict.*` | Decisions sent back to hooks |
| `oshioki.ack.*` | Device liveness acknowledgements |
| `oshioki.delivery.*` | Server delivery receipts for browser recipients |
| `oshioki.enrollment.*` | Pairing submissions and activation |
| `oshioki.device.>` | Device revocation and confirmation |
| JetStream stream and durable `oshioki-server-v1` | Server consumption and startup repair |

This is a traffic inventory, not a ready-to-paste NATS permission file.
Include the JetStream API and reply permissions required by the server's role.
Native agents receive requests over NATS; they do not need browser HTTP APIs.

Web Push is built in; ntfy is optional. Neither notifications nor infrastructure
logs may contain decrypted command/environment data. Web Push carries only
request identifiers; ntfy may also carry host, user, and the request URL.

## Verify and maintain

Check `/healthz`, enroll a device, then complete an approval from each host.
For phones, verify actual notification receipt and approval; health metadata
does not prove delivery.

Use [configuration](configuration.md) for runtime variables,
[update and restore](update.md) for rollout, and
[the runbook](../RUNBOOK.md#authentication-subject-upgrade) for stale NATS filters.
