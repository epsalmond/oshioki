# Architecture

Oshioki's server routes encrypted requests and stores ciphertext. The host
verifies the device's signature before accepting approval; the server cannot
manufacture that signature.

For operating instructions, start with [the README](../README.md).
[Configuration](configuration.md) and [server requirements](requirements.md)
describe deployment settings.

## Three distinct operations

| Operation | What approval authorizes | Components |
| --- | --- | --- |
| Command approval | Exact sudo command and effective environment | Sudo approval plugin, hook, native agent or browser |
| Contextual authentication | Sudo authentication with advisory invocation context | PAM module, hook, hardware-backed native agent or browser |
| Google browser ceremony | Establishing or renewing the configured Google account through the helper | Browser relay, Mac Secure Enclave; optional NATS and SSH |

These use distinct signed purposes. A ceremony approval is not a sudo approval,
and neither substitutes for Google's own authentication.

## Command approval

The hook serializes `RequestV1` once, derives its challenge from those bytes,
and seals the same bytes to each active pinned device. It includes the complete
effective environment in original order, including duplicate names.
Unrepresentable private-protocol input is rejected.

The plugin's private payload carries an environment-complete marker and count.
The hook checks both, so an older plugin cannot silently omit environment data.
Display emphasis and truncated prompt summaries do not limit signature coverage.

Locally the hook can send the envelope over the agent's Unix socket. Remotely
it publishes through NATS/JetStream. The server commits the envelope and each
recipient's sealed body to SQLite before acknowledging delivery. Repeated
identical request IDs are idempotent; different bytes under the same ID are
rejected.

A browser bearer token selects one recipient's encrypted body. Decryption
happens on the device. Plaintext commands and environments do not enter server
storage, notifications, or logs.

## Decisions and liveness

The hook verifies WebAuthn request ID, fingerprint, credential ID, origin,
RP ID, challenge, flags, public key, and signature against retained request
bytes. Native approvals sign the corresponding challenge with P-256.

The first valid decision wins; a signed denial ends command approval.
An invalid approval fails closed. The hook's command-approval deadline is
90 seconds. Server decisions and outbox records commit together; the outbox
retries publication after restart.

Liveness is separate from approval:

| Message | What it proves |
| --- | --- |
| `AliveV1` | The native agent received a request, or the browser authenticated, decrypted, and checked it. |
| `DeliveryV1` | The server durably routed a request to an active browser recipient. It does not prove the browser opened it. |
| Signed decision | An enrolled device made the bound decision. |

Native attempts require an acknowledgement within three seconds. A browser
delivery receipt permits waiting for the browser within the overall deadline.
See [transport rules](transports.md) for fallback behavior.

On Linux, the command plugin also races an interactive password attempt through
the system sudo PAM service. An explicit denial or invalid approval defeats that
fallback. `sudo -n` never opens this plugin password prompt. Darwin has no
plugin password branch.

## Contextual PAM

The opt-in PAM installation removes the Oshioki approval plugin and its
passwordless sudoers rule. A service-specific PAM entry invokes the hook's
`authenticate` command; sudo retains its own policy, timestamps, and password
path.

Authentication requests use `oshioki.auth.<host>` and browser route `/a/<id>`,
separate from command requests and `/r/<id>`. Their trusted principal/service
context is distinct from the advisory invocation. Software native identities
cannot authenticate sudo.

There is no signed Deny action on this operation. Unavailability and cancellation
allow password fallback; malformed assertions remain failures. The installed
Linux and macOS PAM controls differ for hard failures.
The [PAM contract](../pam/README.md) defines exact results, cancellation,
and process cleanup.

## Enrollment and identity

The host owns an enrollment secret; the server stores its hash. Enrollment
binds registration and proof of key possession with an HMAC transcript.
For a browser, the hook verifies origin, RP ID, user presence and verification,
and the ES256 key before atomically pinning the record.

Native pairing publishes its signed proof through NATS. Native agents do not
use the HTTP submission endpoint. After pinning, the host confirms server
activation by reading the matching public device record over HTTPS, for up to
15 seconds. A timeout leaves the local pin intact but server activation uncertain.

| Device kind | Signing key | Use |
| --- | --- | --- |
| `webauthn` | Browser authenticator | Browser approval and authentication |
| `secure-enclave` | Mac Secure Enclave P-256 | Touch ID approval and authentication |
| `software` | P-256 secret in the agent file | Native command approval with normal sudo password retained |

The X25519 decryption key is software material even on a Mac. macOS stores it in
the login keychain; other platforms keep it in private identity state. One
identity can pair with multiple hosts. See [native identities](native-agent.md).

## Persistence and notifications

SQLite uses WAL, foreign keys, a busy timeout, and versioned migrations. One
active server owns each database. Unsupported schema versions prevent startup;
breaking migrations first write a verified restore snapshot.
[Compatibility](compatibility.md) specifies migration and rollback rules.

Web Push stores device-owned subscriptions and uses leased outbox work with
bounded delivery attempts. Revocation disables subscriptions and abandons
pending work. Preserve the private VAPID key across restarts and updates.

Push payloads contain only version, operation type, and request ID. The service
worker opens a same-origin request route; approval still requires local
decryption and WebAuthn. Delivery validates public destination addresses,
disables redirects, and bounds timeouts. Duplicate notifications can coalesce.

Browser responses use no-store caching, no-referrer, MIME sniffing protection,
and a CSP restricting scripts, styles, and API calls to local resources.
`/healthz` checks schema, request consumption, outbox progress, and push readiness.

## Browser ceremony relay

Local mode asks the Secure Enclave to approve the configured Google account,
then invokes gcloud and lets it own the browser and callback.

Remote mode signs peer messages with separate relay keys. Account approval
binds the lane, attempt, expiry, receiver nonce, and account. The requester
verifies the Mac's approval before starting gcloud. When a browser is needed,
the Mac validates the Google authorization URL and forwards the callback over
short-lived SSH connections. Codes and tokens never enter NATS.

The [ceremony guide](browser-ceremony-relay.md) documents configuration and the
current Google-only scope. [Contributing](../CONTRIBUTING.md) describes automated
and supervised verification.
