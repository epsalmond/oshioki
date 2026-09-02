# Oshioki server architecture

The server stores routing data and opaque ciphertext. It cannot produce an
approval accepted by the hook.

## Request path

The hook serializes `RequestV1` once. It computes the WebAuthn challenge from
those bytes and seals the same bytes for each active device. The server writes
the exact envelope and one sealed body per device before acknowledging the
JetStream message.

Identical redelivery is idempotent. Reuse of a request ID with different bytes
is terminated and recorded. Malformed and expired messages are terminated.

The browser token identifies one device. The request API returns only that
device's sealed body. Plaintext commands never enter SQLite, logs,
notifications, or metrics.

## Decisions

Approve and deny are terminal decisions. SQLite commits the first accepted
action and an outbox record in one transaction. Later actions receive `410`.
The outbox retries after restart until NATS publication and flush succeed.

The hook accepts an approval only when its request ID, fingerprint, credential
ID, origin, RP ID, challenge, flags, COSE key, P-256 point, and signature
match. It validates the retained raw request bytes. Explicit deny ends the
request immediately. An invalid approval fails closed.

## Enrollment

The hook owns the enrollment secret. The server stores its SHA-256 hash and
relays the HMAC-bound browser transcript. The hook verifies registration,
the immediate proof assertion, origin, RP ID, UP, UV, and the ES256 key before
atomically replacing its local registry.

Activation is idempotent. A resumed hook updates the reply subject and causes
an already stored submission to be relayed again. The server exposes a device
only after activation confirmation.

## Persistence

SQLite uses WAL, foreign keys, a five-second busy timeout, and embedded schema
version 1. Tables cover devices, enrollments, requests, sealed bodies,
tombstones, and outbox work. Cleanup expires pending enrollment state and
removes old resolved work.

`GET /healthz` checks the schema, durable request consumer progress, and
outbox progress. Every browser response uses `Cache-Control: no-store`,
`Referrer-Policy: no-referrer`, MIME sniffing protection, and a CSP that allows
only local scripts, styles, and API calls. Optional distribution artifacts use
immutable cache headers.

## Local verification

Compose runs NATS, the server, and an ephemeral E2E runner. Playwright uses a
virtual internal CTAP2 authenticator for registration and assertions. The same
runner installs the Linux plugin and invokes real sudo without touching the
host's sudo configuration.

The browser bundle vendors libsodium.js 0.7.15. Its WebAssembly payload is
embedded in the reviewed browser file. `server/web/vendor/SHA256SUMS` records
the source files included in the browser application.

Package publication remains deferred. A future server container may be a
deployment choice. It will not transport Darwin packages.
