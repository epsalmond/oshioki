# Server Implementation Plan

## What the server does

Single binary with two concurrent responsibilities:

1. **NATS consumer** on `sudo.request.>`: buffers pending requests and decrypts
   sealed bodies to publish verdicts to NATS.
2. **HTTPS server** on 8443: serves approval/enrollment pages and handles
   WebAuthn assertions.

## HTTP Routes

### GET / (approval page)

Serves an HTML page with embedded JavaScript. The page:
- Fetches pending requests from GET /api/pending (JSON list)
- For each request, decrypts the body's payload using the device's box secret
- Displays decrypted request details (user, command, host, cwd, pid chain)
- Builds a WebAuthn assertion ceremony with the displayed request hash as challenge
- Prompts for biometric confirmation
- POSTs the signed assertion to POST /assertion/:id

### GET /api/pending

Returns JSON list of pending requests with:
- request_id
- host
- user
- expires_at (unix)
- encrypted_body (base64)
- device_fingerprint (which device this body is sealed to)

### POST /api/enroll/:token

Validates the enrollment token (one-time). If valid, serves an HTML page that:
- Generates a WebAuthn credential (P-256 with user presence + verification)
- Generates an X25519 keypair for the device
- Sends the keys to POST /api/enroll/:token (JSON: credential_pub, box_pub, credential_id, label)
- Redirects to success page

### POST /assertion/:id

Receives a signed WebAuthn assertion (JSON: request_id, credential_id,
client_data_json, authenticator_data, signature).

The server:
- Calls protocol::verify::verify() with the verdict and request
- If OK, publishes the verdict to NATS subject `sudo.verdict.<id>`
- Returns OK or error

## NATS Flow

On receiving sudo.request.<host> message with payload:

{
  "header": {
    "id": "...",
    "host": "...",
    "user": "...",
    "ts": ...
  },
  "sealed": [
    {
      "ephemeral_pub": "...",
      "nonce": "...",
      "ciphertext": "...",
      "device_fingerprint": "..."
    }
  ]
}

The server:
1. Buffers the request with its ID
2. If the user has a registered device, sends a notification to ntfy with the
   URL https://sudo.internal.psalmond.com/?id=<id>
3. Serves the request via GET /api/pending/:id with encrypted body
4. On receiving a valid assertion via POST /assertion/:id, publishes verdict
   to NATS sudo.verdict.<id> and removes from pending
5. On expiry (timeout), removes from pending and NACKs the message

## WebAuthn Page JavaScript

```javascript
async function approve() {
  // 1. Fetch pending requests
  const pending = await fetch('/api/pending').then(r => r.json());

  // 2. For each request, decrypt and show context
  const first = pending[0];
  const device = await loadDevice(); // from localStorage
  const decrypted = await decryptBody(first.encrypted_body, device.box_secret);

  // 3. Show context
  showRequest({
    host: decrypted.host,
    user: decrypted.user,
    command: decrypted.command,
    argv: decrypted.argv,
    cwd: decrypted.cwd,
    pidChain: decrypted.pid_chain,
    expiresAt: first.expires_at
  });

  // 4. Build WebAuthn ceremony
  const requestHash = await sha256(JSON.stringify(decrypted));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: requestHash,
      rpId: 'sudo.internal.psalmond.com',
      allowCredentials: [{ id: device.credential_id, type: 'public-key' }],
      userVerification: 'required'
    }
  });

  // 5. POST the assertion
  await fetch(`/assertion/${first.request_id}`, {
    method: 'POST',
    body: JSON.stringify({
      credential_id: b64(assertion.rawId),
      client_data_json: assertion.response.clientDataJSON,
      authenticator_data: assertion.response.authenticatorData,
      signature: assertion.response.signature
    })
  });
}
```

## Persistence

Pending requests are in-memory only (bounded by queue timeout).
Device enrollment is persistent (written to /var/lib/sudo-approve/devices.json
on the server host).
Enrollment tokens are in-memory only (expire after first use).

## NATS Subjects

- `sudo.request.>` — requests from hooks
- `sudo.verdict.<id>` — verdicts the hook waits on

## Streams Config

SUDO_APPROVE stream holds request bodies with 10-minute expiry. Work queue
consumer is server-hosted.

## Failure Behavior

- NATS unreachable: log error, keep running (HTTP still works)
- Malformed request payload: NACK the message, log warning
- Assertion verification fails: return 401, log error
- Request expires: drop from pending, NACK the message

## Dependencies

- axum for HTTP
- tokio for async
- protocol crate for types and verify()
- async-nats for NATS
- TRACING for logging
- base64 for credential encoding
