# Transport contract

NATS/JetStream is the only configured `oshioki-transport` backend.
The native agent's local Unix socket is an additional hook-to-device path.
Browser approvals need NATS and the server.

## Delivery and decisions

| Property | Implementation |
| --- | --- |
| Idempotent server commit | SQLite deduplicates by request ID; request commit precedes JetStream acknowledgement. Conflicting bytes are rejected. |
| First decision wins | The server commits the first accepted action and outbox row together; later actions receive `410`. |
| Durable publication | The server outbox retries after restart until NATS publication and flush succeed. |
| Bounded waiting | The hook owns the approval deadline; unavailable transports report the underlying error. |
| Liveness before a human decision | Native `AliveV1` acknowledgement, or browser `DeliveryV1` followed by browser `AliveV1`. Neither authorizes execution. |

Exactly-once commit refers to server state, not exactly-once network delivery.
The hook waits live for a decision; its wait is not a durable outbox.

## Socket fallback

With `OSHIOKI_AGENT_SOCKET` configured, the hook tries the socket first.

| Socket outcome | Command approval behavior |
| --- | --- |
| Unavailable, closes, or silent before acknowledgement | Try NATS if configured, within the same deadline. |
| Valid decision | Finish with that result. |
| Malformed reply or failure after valid acknowledgement | Fail closed; no transport retry. |

Omitting `NATS_URL` makes the hook socket-only. Omitting both transports is
a configuration error. An agent without NATS settings serves the local socket.

The authentication operation distinguishes an unanswered connection from a
malformed assertion: a clean hangup can leave password fallback available,
whereas truncated or invalid decision bytes are a hard failure.
See [PAM results](../pam/README.md#results-and-cancellation).

## Control messages and upgrades

`AliveV1` has `type: "alive"`, version 1, and a request ID. Socket agents send
it as the first response frame; NATS agents publish it on
`oshioki.ack.<request-id>`.

`DeliveryV1` has `type: "delivery"`, version 1, and a request ID. The server
commits it with the routed browser request and publishes it on
`oshioki.delivery.<request-id>`. Only an authenticated browser post after
decryption causes the server to relay browser liveness.

These control protocols require coordinated updates: hook/agent for the socket,
and server/browser bundle/hook for browser delivery. Additive public JSON remains
backward-readable; see [compatibility](compatibility.md).

Server startup repairs stale stream subjects and durable consumer filters. A
missing stream is an operator configuration error.
[The runbook](../RUNBOOK.md#authentication-subject-upgrade) covers repair.
