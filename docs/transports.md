# Transports

`oshioki-transport` is the seam the hook and the server implement against. The wire format is unchanged: the subjects and v1 JSON payloads below are byte-identical to what shipped before the seam existed.

## Guarantees

Every transport must provide the guarantees below.

- Exactly-once request commit. The `nats` transport provides it with JetStream explicit ack and the commit-before-ack outbox: the server writes the envelope to SQLite and marks the row sent only after the message acknowledges.
- First decision wins. The `nats` transport provides it with the durable consumer replay: redelivered requests dedup at `Store::ingest_request` on `request_id`.
- A deny fails fast. The `nats` transport provides it with a direct verdict publish+flush: the denial is not routed through the request outbox.
- A timeout fires at the deadline. The `nats` transport provides it with the hook-side deadline timer: the hook keeps the approval timer and fails the request on expiry regardless of what the transport does.
- A request is acknowledged before the agent asks for a decision. The socket transport sends an `AliveV1` frame. NATS uses `oshioki.ack.<request-id>`. The browser posts the same message after it decrypts and checks the request. The server relays that explicit browser message and never acknowledges a request during ingestion.
- An unavailable transport is reported with its underlying error and ends that attempt quickly. A connected transport that sends no acknowledgement is reported as a nonresponsive daemon. Neither message is an approval.

The outbox wording matters because the hook's verdict wait is a live hold, not an outbox. The outbox row lives server-side, and the verdict lane drains it, so `nats` provides exactly-once *server-side* commit. Request redelivery after a consumer restart is idempotent because `Store::ingest_request` dedups on `request_id`. A transport holding a live connection can depart from the outbox only when its reply ordering preserves first-decision-wins on the hook.

## Transports

`nats` is the only transport this issue ships. Device-side delivery is out of scope here: the agent keeps talking to NATS directly until a device-side transport lands in #6/#7.

The existing v1 request and decision JSON stays unchanged. `AliveV1` is a new versioned control message with `type: "alive"`, `version: 1`, and the request ID. Socket peers exchange it as the first response frame. NATS and the browser use the dedicated acknowledgement subject. The hook never treats an acknowledgement as a signed decision. An old agent that sends only a verdict fails the new liveness check and must be upgraded; the hook does not infer liveness from a verdict.

See [configuration.md](configuration.md) for `OSHIOKI_TRANSPORT`.
