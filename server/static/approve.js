// WebAuthn approval ceremony for sudo page.
//
// This script:
// 1. Decrypts the request details from the server's encrypted payload
// 2. Shows context to the user (who is approving what)
// 3. Builds a WebAuthn assertion ceremony with the request hash as challenge
// 4. Signs the request hash with the enrolled device credential
// 5. POSTs the resulting verdict to the server for relay to NATS

// Constants
const RP_ID = 'sudo.internal.psalmond.com';

/**
 * Decode Base64URL text.
 * @param {string} text
 * @returns {ArrayBuffer}
 */
function decodeB64Url(text) {
  const encoded = text.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
}

/**
 * SHA-256 hash of text.
 * @param {string} text
 * @returns {Promise<ArrayBuffer>}
 */
async function sha256(text) {
  const data = new TextEncoder().encode(text);
  return crypto.subtle.digest('SHA-256', data);
}

/**
 * Decrypt the request body payload using the device's box secret.
 *
 * Payload format:
 *   - 32 bytes: ephemeral_box_pub (X25519)
 *   - 12 bytes: nonce
 *   - ciphertext (ChaCha20-Poly1305)
 *
 * We do X25519 key exchange with the device's box_secret, then decrypt.
 *
 * @param {string} payloadB64 Base64-encoded payload
 * @param {ArrayBuffer} deviceBoxSecret 32-byte X25519 secret
 * @returns {Promise<{id: string, host: string, user: string, command: string, argv: string[], cwd: string, pid_chain: string[], ts: number}>}
 */
async function decryptRequest(body, deviceBoxSecret) {
  const payload = decodeB64Url(body);

  if (payload.length < 44) {
    throw new Error('invalid payload');
  }

  const ephemeralPub = payload.slice(0, 32);
  const nonce = payload.slice(32, 44);
  const ciphertext = payload.slice(44);

  // X25519 key exchange: ephemeral_pub * box_secret
  const shared = await crypto.subtle.importKey(
    'raw',
    deviceBoxSecret,
    { name: 'ECDH', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: await crypto.subtle.importKey(
        'raw',
        ephemeralPub,
        { name: 'ECDH', hash: 'SHA-256' },
        false,
        []
      )
    },
    shared,
    256
  );

  // Derive ChaCha20 key from shared secret
  const keyHash = await crypto.subtle.digest('SHA-256', bits);
  const chachaKey = await crypto.subtle.importKey(
    'raw',
    keyHash.slice(0, 32),
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: 'ChaCha20-Poly1305', nonce: nonce },
    await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: new TextEncoder().encode('chacha20')
      },
      chachaKey,
      { name: 'ChaCha20-Poly1305', length: 256 },
      false,
      ['decrypt']
    ),
    ciphertext
  );

  // Parse the request JSON
  const text = new TextDecoder().decode(decrypted);
  return JSON.parse(text);
}

/**
 * Approve a request using WebAuthn.
 * @param {string} requestId
 * @param {object} request Decrypted request details
 * @param {ArrayBuffer} credentialId Enrolled device's credential ID
 */
async function approveRequest(requestId, request, credentialId) {
  // Build the challenge: sha256(canonical(request) || "approve")
  const canonical = JSON.stringify({
    id: request.id,
    nonce: request.body.nonce,
    host: request.host,
    user: request.user,
    uid: request.body.uid,
    runas_uid: request.body.runas_uid,
    cwd: request.cwd,
    tty: request.body.tty,
    command: request.command,
    argv: request.argv,
    pid_chain: request.pid_chain,
    ts: request.ts,
    expiry: request.body.expiry
  });

  const challenge = await sha256(canonical + 'approve');

  // WebAuthn ceremony
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: challenge,
      rpId: RP_ID,
      allowCredentials: [{
        id: credentialId,
        type: 'public-key'
      }],
      userVerification: 'required',
      timeout: 30000
    }
  });

  // POST the assertion
  const response = await fetch(`/assertion/${requestId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      id: requestId,
      credential_id: btoa(String.fromCharCode(...new Uint8Array(assertion.rawId))),
      client_data_json: new TextDecoder().decode(assertion.response.clientDataJSON),
      authenticator_data: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
      signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature)))
    })
  });

  return response;
}

/**
 * Enroll a new device using WebAuthn.
 * @returns {Promise<{credential_id: ArrayBuffer, credential_pub: object}>}
 */
async function enrollDevice() {
  const userId = crypto.getRandomValues(new Uint8Array(16));

  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { name: 'sudo', id: RP_ID },
      user: { id: userId, name: 'sudo-approve', displayName: 'sudo' },
      challenge: await sha256('enroll'),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { userVerification: 'required', requireResidentKey: false },
      timeout: 30000
    }
  });

  return {
    credential_id: credential.rawId,
    credential_pub: await credential.response.getPublicKey(),
    credential_jwk: await crypto.subtle.importKey('jwk',
      JSON.parse(new TextDecoder().decode(credential.response.getPublicKey())),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    )
  };
}

/**
 * Generate a secure random X25519 keypair.
 * The browser doesn't have built-in X25519, so we use HKDF with a random seed.
 * @returns {Promise<ArrayBuffer>} 32-byte secret
 */
function generateBoxSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytes;
}

// Export for module contexts (if used)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { decryptRequest, approveRequest, enrollDevice, generateBoxSecret };
}
