# Transports

`oshioki-transport` is the seam the hook and the server implement against. The wire format is unchanged: the subjects and v1 JSON payloads below are byte-identical to what shipped before the seam existed.

## Guarantees

Every transport must provide the guarantees below.

- Exactly-once request commit. The `nats` transport provides it with JetStream explicit ack and the commit-before-ack outbox: the server writes the envelope to SQLite and marks the row sent only after the message acknowledges.
- First decision wins. The `nats` transport provides it with the durable consumer replay: redelivered requests dedup at `Store::ingest_request` on `request_id`.
- A deny fails fast. The `nats` transport provides it with a direct verdict publish+flush: the denial is not routed through the request outbox.
- A timeout fires at the deadline. The `nats` transport provides it with the hook-side deadline timer: the hook keeps the approval timer and fails the request on expiry regardless of what the transport does.
- A request is acknowledged before the agent asks for a decision. A native-only socket or NATS request requires an `AliveV1` from the agent within three seconds. For a request with an active pinned WebAuthn recipient, the server adds a `DeliveryV1` row to the same durable transaction as the request after routing it to that recipient; the hook accepts that receipt on `oshioki.delivery.<request-id>` and reports that the request was delivered while it waits for the browser. The browser posts `AliveV1` on `oshioki.ack.<request-id>` only after authenticating, decrypting, and checking the request. The server never uses ingestion itself as evidence that a browser opened it.
- An unavailable transport is reported with its underlying error and ends that attempt quickly. A connected transport that sends no acknowledgement is reported as a nonresponsive daemon. Neither message is an approval.

The outbox wording matters because the hook's verdict wait is a live hold, not an outbox. The outbox row lives server-side, and the approval lane drains delivery receipts and verdicts, so `nats` provides exactly-once *server-side* commit. Request redelivery after a consumer restart is idempotent because `Store::ingest_request` dedups on `request_id`. A transport holding a live connection can depart from the outbox only when its reply ordering preserves first-decision-wins on the hook.

## Transports

`OSHIOKI_TRANSPORT=nats` is the only configured transport backend. It selects
NATS and JetStream for hook and server traffic. Native agents also serve local
hook requests over a Unix socket, which sits beside this transport seam.

When `OSHIOKI_AGENT_SOCKET` is configured, the hook tries that socket first.
If it is unavailable, or closes or stays silent before its `AliveV1`
acknowledgement, the hook can fall back to NATS when `NATS_URL` is set. A
malformed protocol reply, a socket decision, or any failure after a valid
acknowledgement is final and never falls back. Without `NATS_URL` in the hook
configuration, that hook uses the socket only. An agent with no `NATS_URL` in
its own runtime environment answers socket requests only. Browser approval
still uses the server and NATS path.

The existing v1 request and decision JSON fields stay unchanged. Native enrollment records additionally distinguish software keys from Secure Enclave keys. `AliveV1` is a versioned control message with `type: "alive"`, `version: 1`, and the request ID. `DeliveryV1` has `type: "delivery"` with the same version and ID and is published only on the server delivery subject. Socket peers exchange `AliveV1` as the first response frame; NATS and the browser use the dedicated acknowledgement subject. The hook never treats either receipt as a signed decision. Native socket control requires a coordinated hook and agent upgrade: either old side can reject the new first frame, and the diagnostic names `oshioki-agent` so an operator can repair the pair. Browser-capable NATS approval additionally requires the upgraded server and browser bundle, because an older server does not publish `DeliveryV1`; deploy those components as one compatibility set rather than relying on rolling negotiation.

See [configuration.md](configuration.md) for `OSHIOKI_TRANSPORT`.
