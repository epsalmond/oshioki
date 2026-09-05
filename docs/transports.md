# Transports

`oshioki-transport` is the seam the hook and the server implement against. The wire format is unchanged: the subjects and v1 JSON payloads below are byte-identical to what shipped before the seam existed.

## Guarantees

Every transport must provide the guarantees below.

- Exactly-once request commit. The `nats` transport provides it with JetStream explicit ack and the commit-before-ack outbox: the server writes the envelope to SQLite and marks the row sent only after the message acknowledges.
- First decision wins. The `nats` transport provides it with the durable consumer replay: redelivered requests dedup at `Store::ingest_request` on `request_id`.
- A deny fails fast. The `nats` transport provides it with a direct verdict publish+flush: the denial is not routed through the request outbox.
- A timeout fires at the deadline. The `nats` transport provides it with the hook-side deadline timer: the hook keeps the approval timer and fails the request on expiry regardless of what the transport does.

The outbox wording matters because the hook's verdict wait is a live hold, not an outbox. The outbox row lives server-side, and the verdict lane drains it, so `nats` provides exactly-once *server-side* commit. Request redelivery after a consumer restart is idempotent because `Store::ingest_request` dedups on `request_id`. A transport holding a live connection can depart from the outbox only when its reply ordering preserves first-decision-wins on the hook.

## Transports

`nats` is the only transport this issue ships. Device-side delivery is out of scope here: the agent keeps talking to NATS directly until a device-side transport lands in #6/#7.

See [configuration.md](configuration.md) for `OSHIOKI_TRANSPORT`.
