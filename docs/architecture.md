# Oshioki architecture

The server stores routing data and opaque ciphertext. It cannot produce an
approval accepted by the hook.

For what production must provide, see [requirements.md](requirements.md).
For configuration reference, see [configuration.md](configuration.md).

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

The request also carries the curated execution environment — loader,
resolution, shell, interpreter, pager, and trust variables. Approvals sign
those bytes alongside the command, so a different environment is a different
approval; the environment travels only inside the sealed bodies.

The hook and the server route through `oshioki-transport`. The hook holds a `HookTransport`; the server holds a `ServerTransport`. `OSHIOKI_TRANSPORT=nats` is the default and the only transport this issue lands. The wire format (SMTP-style subjects and v1 JSON payloads) is identical to what shipped before the seam. The agent keeps talking to NATS directly until a device-side transport ships (#6/#7).

## Device kinds

A device record carries a `kind`: `webauthn` or `secure-enclave`.

A `secure-enclave` record holds a 65-byte SEC1 uncompressed P-256 point as
`credential_public_key`. `credential_id` is the SHA-256 hash of that point
(32 bytes). `sign_count` is always 0. `api_token_hash` is still 32 random
bytes, but the server does not use them for a native device; they exist only
to keep the server's UNIQUE column honest. The fingerprint formula is
unchanged for both kinds.

## Decisions

Approve and deny are terminal decisions. SQLite commits the first accepted
action and an outbox record in one transaction. Later actions receive `410`.
The outbox retries after restart until NATS publication and flush succeed.

The hook accepts a WebAuthn approval only when its request ID, fingerprint,
credential ID, origin, RP ID, challenge, flags, COSE key, P-256 point, and
signature match. It validates the retained raw request bytes.

An `approve_native` decision carries a DER ECDSA P-256 signature, with SHA-256
as the message hash, over the same 32-byte challenge WebAuthn signs. It
carries no authenticator data, client data, origin, or RP ID: the native
agent signs the challenge directly.

The hook applies the same rules to both kinds. The first decision it receives
wins. An explicit deny ends the request immediately. An invalid approval
fails closed. The hook gives up after 90 seconds. A decision must name a
device whose kind and fingerprint both match a pinned record.

Each approval path reports liveness before it waits for a human decision. A
native socket agent sends an `AliveV1` frame first. A native NATS agent sends
the same message on `oshioki.ack.<request-id>`. For a request that includes an
active pinned WebAuthn recipient, the server records a `DeliveryV1` outbox row
in the request ingestion transaction after joining the sealed body to the
active device record, then publishes it on `oshioki.delivery.<request-id>`.
That receipt proves durable relay routing and lets the hook wait for the
browser beyond the native three-second liveness bound. The browser posts
`AliveV1` only after it authenticates, decrypts, and checks the sealed request;
the server relays that browser message only after the authenticated post, so
request ingestion cannot impersonate a live browser. The acknowledgement and
delivery receipt carry no authorization.

The delivery control message has no rolling negotiation. Browser-capable
deployments must update the server, its browser bundle, and the hook together;
native socket deployments must update the hook and agent together. An older
server or peer leaves the corresponding receipt unavailable and the hook
reports the required upgrade while failing closed.

The sudo plugin starts the hook and, for an interactive Linux invocation, a
separate PAM password attempt at the same time. The installer normally adds a
`NOPASSWD` sudoers entry, so this is the plugin's fallback path rather than a
second sudo policy prompt. PAM authenticates the invoking user through the
system `sudo` service and runs account management before it can approve.
`sudo -n` skips the password child and never reads `/dev/tty`. An explicit
denial or invalid hook result wins over a password. A transport failure or an
unanswered request leaves password authentication available. Both children
are canceled and reaped when one wins, and the plugin restores terminal echo
and pending input. The race is bounded by the same 90-second deadline.

## Enrollment

The hook owns the enrollment secret. The server stores its SHA-256 hash and
relays the HMAC-bound browser transcript. The hook verifies registration,
the immediate proof assertion, origin, RP ID, UP, UV, and the ES256 key before
atomically replacing its local registry.

A native enrollment submission carries `credential_public_key`,
`box_public_key`, `api_token_hash`, `label`, `proof_signature`, and
`transcript_hmac`. The proof is a DER ECDSA P-256 signature over an HMAC of
the domain `oshioki/enroll/native-proof/v1\0` and, in order, the credential ID
(derived from the public key), the public key, the box key, the API token
hash, and the label. The transcript HMAC covers the enrollment ID, the
literal kind tag `secure-enclave`, and every submission field including the
proof signature, in that same order. The native agent publishes its
submission straight to `oshioki.enrollment.submission.<id>` and waits on
`oshioki.enrollment.activation.<id>`. It never calls the server's HTTP
submission route, which accepts the `webauthn` kind only.

The X25519 box key is always a software key, even on a secure-enclave device:
the enclave only holds P-256. On macOS it will live in the Keychain (issue
#9). Today the software agent keeps it in the same 0600 identity file as the
signing key.

Activation is idempotent. A resumed hook updates the reply subject and causes
an already stored submission to be relayed again. The server exposes a device
only after activation and acknowledges nothing on NATS. `enroll` confirms the
activation by reading the device back from `GET /api/v1/devices/<fingerprint>`
over HTTPS, polling for up to fifteen seconds until the served record matches
the one it just enrolled, so a server that cannot store the record fails the
enrollment instead of dropping it. The read-back, not a message, is the
confirmation: every consumer can publish on the device subjects, so a NATS
acknowledgement could come from the device being enrolled rather than from the
server.

A confirmation that times out is not a rejection. The device is pinned on the
host and can approve sudo there; what is unknown is the server's copy. `enroll`
says so and names the recovery, which is a fresh `oshioki enroll` for that
device once the server is healthy.

## Persistence

SQLite uses WAL, foreign keys, a five-second busy timeout, and embedded schema
version 1. Tables cover devices, enrollments, requests, sealed bodies,
tombstones, and outbox work. Cleanup expires pending enrollment state and
removes old resolved work. The expected runtime is one active server with one
persistent database file.

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

Package publication remains deferred. There is no server container yet.
When there is one, it will not include Darwin packages.
