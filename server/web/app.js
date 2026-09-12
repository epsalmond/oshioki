"use strict";

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });
const REGISTRATION_DOMAIN = enc.encode("oshioki/enroll/registration/v1\0");
const PROOF_DOMAIN = enc.encode("oshioki/enroll/proof/v1\0");
const TRANSCRIPT_DOMAIN = enc.encode("oshioki/enroll/transcript/v1\0");
const APPROVE_DOMAIN = enc.encode("oshioki/approve/v1\0");
// Contextual sudo authentication has its own challenge domain, so a command
// approval signature can never satisfy an authentication verifier.
const AUTH_CHALLENGE_DOMAIN = enc.encode("oshioki/authenticate/sudo/v1\0");

function b64(bytes) {
  return sodium.to_base64(new Uint8Array(bytes), sodium.base64_variants.URLSAFE_NO_PADDING);
}
function unb64(value) {
  if (value.includes("=")) throw new Error("padded base64url rejected");
  return sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
}
function concat(...parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length); let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}
function lengthPrefix(value) {
  const prefix = new Uint8Array(8); new DataView(prefix.buffer).setBigUint64(0, BigInt(value.length));
  return concat(prefix, value);
}
async function hmac(key, data) {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data));
}
async function enrollmentMac(secret, domain, fields) {
  const derived = await hmac(secret, domain);
  return hmac(derived, concat(...fields.map(lengthPrefix)));
}
async function sha256(...parts) { return new Uint8Array(await crypto.subtle.digest("SHA-256", concat(...parts))); }

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("oshioki", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("devices", { keyPath: "fingerprint" });
    request.onerror = () => reject(request.error); request.onsuccess = () => resolve(request.result);
  });
}
async function putDevice(device) {
  const db = await openDb();
  await new Promise((resolve, reject) => { const tx = db.transaction("devices", "readwrite"); tx.objectStore("devices").put(device); tx.oncomplete = resolve; tx.onerror = () => reject(tx.error); });
  db.close();
}
async function allDevices() {
  const db = await openDb();
  const devices = await new Promise((resolve, reject) => { const request = db.transaction("devices").objectStore("devices").getAll(); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
  db.close(); return devices;
}
function requestId() { return location.pathname.split("/").filter(Boolean).at(-1); }
// The target account is what the approval grants, so it is always shown,
// including sudo's implicit root default. The number is not resolved to a
// name here: the account lives on the requesting host, not in this browser.
function runAsLabel(uid) { return uid === 0 ? "root (uid 0)" : `uid ${uid}`; }
// One argument per line already separates them, but an argument holding a
// newline would still split in two. Anything not plainly printable, the empty
// argument included, is wrapped in shell single quotes.
const PLAIN_ARGUMENT = /^[A-Za-z0-9@%+=:,./_-]+$/;
function quoteArgument(argument) {
  return PLAIN_ARGUMENT.test(argument) ? argument : `'${argument.split("'").join("'\\''")}'`;
}
// JSON-like quoting makes environment names and values unambiguous without
// putting attacker-controlled markup in the page. Escape non-ASCII characters
// as well: look-alike Unicode and invisible format characters must not make a
// signed variable appear to be a different one.
function quoteReviewString(value) {
  if (typeof value !== "string") throw new Error("request field is not a string");
  let escaped = '"';
  for (const character of value) {
    const code = character.codePointAt(0);
    if (character === "\\") escaped += "\\\\";
    else if (character === '"') escaped += '\\"';
    else if (character === "\b") escaped += "\\b";
    else if (character === "\f") escaped += "\\f";
    else if (character === "\n") escaped += "\\n";
    else if (character === "\r") escaped += "\\r";
    else if (character === "\t") escaped += "\\t";
    else if (code < 0x20 || code === 0x7f || code > 0x7e) {
      escaped += code <= 0xffff
        ? `\\u${code.toString(16).padStart(4, "0")}`
        : `\\u{${code.toString(16)}}`;
    } else escaped += character;
  }
  return `${escaped}"`;
}
function formatEnvironment(environment) {
  if (!Array.isArray(environment)) throw new Error("request environment is not a list");
  return environment.map((entry, index) => {
    if (!entry || typeof entry.name !== "string" || typeof entry.value !== "string") {
      throw new Error("request environment entry is invalid");
    }
    return `[${index}] name=${quoteReviewString(entry.name)} value=${quoteReviewString(entry.value)}`;
  }).join("\n") || "(none)";
}
function text(id, value) { document.getElementById(id).textContent = value; }
function failure(error) { console.error(error); text("status", "This request could not be verified."); }

async function enrollment() {
  await sodium.ready;
  const enrollmentId = requestId();
  const fragment = location.hash.slice(1); history.replaceState(null, "", location.pathname);
  if (!fragment) throw new Error("missing enrollment secret");
  const secret = unb64(fragment); if (secret.length !== 32) throw new Error("bad enrollment secret");
  const button = document.getElementById("enroll"); button.hidden = false; text("status", "Touch ID or Face ID will create a credential for this browser profile.");
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const registrationChallenge = await enrollmentMac(secret, REGISTRATION_DOMAIN, []);
      const credential = await navigator.credentials.create({ publicKey: {
        challenge: registrationChallenge, rp: { id: location.hostname, name: "Sudo approval" },
        user: { id: crypto.getRandomValues(new Uint8Array(32)), name: `sudo-${enrollmentId}`, displayName: "Sudo approval" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], timeout: 120000,
        authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required", userVerification: "required" },
        attestation: "none",
      }});
      const box = sodium.crypto_box_keypair();
      const apiTokenBytes = crypto.getRandomValues(new Uint8Array(32)); const apiToken = b64(apiTokenBytes);
      const apiTokenHash = await sha256(enc.encode(apiToken));
      const label = `${navigator.platform || "browser"} ${new Date().toISOString().slice(0, 10)}`;
      const proofChallenge = await enrollmentMac(secret, PROOF_DOMAIN, [new Uint8Array(credential.rawId), box.publicKey, apiTokenHash, enc.encode(label)]);
      const proof = await navigator.credentials.get({ publicKey: { challenge: proofChallenge, rpId: location.hostname,
        allowCredentials: [{ type: "public-key", id: credential.rawId }], userVerification: "required", timeout: 120000 } });
      const fields = [enc.encode(enrollmentId), new Uint8Array(credential.response.clientDataJSON), new Uint8Array(credential.response.attestationObject),
        new Uint8Array(proof.response.authenticatorData), new Uint8Array(proof.response.clientDataJSON), new Uint8Array(proof.response.signature),
        new Uint8Array(credential.rawId), box.publicKey, apiTokenHash, enc.encode(label)];
      const submission = { kind: "webauthn", version: 1, enrollment_id: enrollmentId, registration_client_data_json: b64(fields[1]), attestation_object: b64(fields[2]),
        proof_authenticator_data: b64(fields[3]), proof_client_data_json: b64(fields[4]), proof_signature: b64(fields[5]), credential_id: b64(fields[6]),
        box_public_key: b64(fields[7]), api_token_hash: b64(fields[8]), label, transcript_hmac: b64(await enrollmentMac(secret, TRANSCRIPT_DOMAIN, fields)) };
      const response = await fetch(`/api/v1/enrollments/${enrollmentId}/submission`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(submission) });
      if (!response.ok) throw new Error(`submission failed ${response.status}`);
      for (let attempt = 0; attempt < 150; attempt += 1) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        const statusResponse = await fetch(`/api/v1/enrollments/${enrollmentId}/status`);
        if (!statusResponse.ok) throw new Error("status failed"); const status = await statusResponse.json();
        if (status.status === "active") { await putDevice({ fingerprint: status.fingerprint, credentialId: b64(credential.rawId), boxSecret: b64(box.privateKey), apiToken }); text("status", `Enrolled as ${status.fingerprint}`); button.hidden = true; return; }
        if (status.status === "expired" || status.status === "rejected") throw new Error(`enrollment ${status.status}`);
      }
      throw new Error("activation timeout");
    } catch (error) { button.disabled = false; failure(error); }
  }, { once: true });
}

async function approval() {
  await sodium.ready; const id = requestId(); let selected;
  for (const device of await allDevices()) {
    const response = await fetch(`/api/v1/requests/${id}`, { headers: { authorization: `Bearer ${device.apiToken}` } });
    if (response.status === 401) continue; if (!response.ok) throw new Error(`request failed ${response.status}`);
    selected = { device, payload: await response.json() }; break;
  }
  if (!selected) throw new Error("no enrolled browser profile owns this request");
  const sealed = selected.payload.sealed; const shared = sodium.crypto_scalarmult(unb64(selected.device.boxSecret), unb64(sealed.ephemeral_pub));
  if (shared.every(value => value === 0)) throw new Error("invalid shared secret");
  const raw = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, unb64(sealed.ciphertext), null, unb64(sealed.nonce), shared);
  const request = JSON.parse(dec.decode(raw)); if (request.version !== 1 || request.request_id !== id) throw new Error("request mismatch");
  const acknowledgement = await fetch(`/api/v1/requests/${id}/ack`, { method: "POST", headers: { authorization: `Bearer ${selected.device.apiToken}`, "content-type": "application/json" }, body: JSON.stringify({ type: "alive", version: 1, request_id: id }) });
  if (!acknowledgement.ok) throw new Error(`acknowledgement failed ${acknowledgement.status}`);
  text("host", request.host); text("user", `${request.user} / ${request.uid}`); text("runas", runAsLabel(request.runas_uid));
  if (request.session) { text("session", request.session); document.getElementById("session-label").hidden = false; document.getElementById("session").hidden = false; }
  text("command", request.command);
  text("argv", request.argv.map(quoteArgument).join("\n")); text("cwd", request.cwd); text("process-chain", request.pid_chain.join("\n"));
  text("env", formatEnvironment(request.env ?? []));
  text("status", `Expires ${new Date(request.expires_at * 1000).toLocaleTimeString()}`); document.getElementById("request").hidden = false; document.getElementById("actions").hidden = false;
  const headers = { authorization: `Bearer ${selected.device.apiToken}`, "content-type": "application/json" };
  document.getElementById("deny").addEventListener("click", async () => {
    const body = { version: 1, request_id: id, device_fingerprint: selected.device.fingerprint };
    const response = await fetch(`/api/v1/requests/${id}/deny`, { method: "POST", headers, body: JSON.stringify(body) });
    if (!response.ok) throw new Error(`deny failed ${response.status}`); text("status", "Denied."); document.getElementById("actions").hidden = true;
  }, { once: true });
  document.getElementById("approve").addEventListener("click", async () => {
    const challenge = await sha256(APPROVE_DOMAIN, raw);
    const assertion = await navigator.credentials.get({ publicKey: { challenge, rpId: location.hostname,
      allowCredentials: [{ type: "public-key", id: unb64(selected.device.credentialId) }], userVerification: "required", timeout: 90000 } });
    const body = { version: 1, request_id: id, device_fingerprint: selected.device.fingerprint, credential_id: b64(assertion.rawId),
      authenticator_data: b64(assertion.response.authenticatorData), client_data_json: b64(assertion.response.clientDataJSON), signature: b64(assertion.response.signature) };
    const response = await fetch(`/api/v1/requests/${id}/approve`, { method: "POST", headers, body: JSON.stringify(body) });
    if (!response.ok) throw new Error(`approval failed ${response.status}`); text("status", "Approval sent."); document.getElementById("actions").hidden = true;
  }, { once: true });
}

// Renders the submitted invocation with its status intact. A truncated or
// missing command line is labelled as such: PAM does not know what sudo will
// finally run, and nothing on this page may present partial context as if it
// were the verified final command.
function formatInvocation(invocation) {
  if (!invocation || typeof invocation.status !== "string") throw new Error("invocation is invalid");
  if (invocation.status === "unavailable") return "unavailable (not captured)";
  if (!Array.isArray(invocation.argv)) throw new Error("invocation argv is invalid");
  const argv = invocation.argv.map(quoteArgument).join("\n");
  const command = typeof invocation.command === "string" ? invocation.command : "";
  const body = argv || command || "(none)";
  if (invocation.status === "available") return body;
  if (invocation.status === "truncated") {
    const omitted = Number.isInteger(invocation.omitted_args)
      ? ` (+${invocation.omitted_args} more arguments omitted)`
      : " (cut short)";
    return `truncated: ${body}${omitted}`;
  }
  throw new Error("unknown invocation status");
}
// The invoking account, with its UID always shown: the name is a host-side
// lookup that can fail, and the number is what PAM actually captured.
function invokingLabel(trusted) {
  return typeof trusted.invoking_user === "string" && trusted.invoking_user
    ? `${trusted.invoking_user} / ${trusted.invoking_uid}`
    : `uid ${trusted.invoking_uid}`;
}

async function authentication() {
  await sodium.ready; const id = requestId(); let selected;
  for (const device of await allDevices()) {
    const response = await fetch(`/api/v1/auth/${id}`, { headers: { authorization: `Bearer ${device.apiToken}` } });
    if (response.status === 401) continue; if (!response.ok) throw new Error(`request failed ${response.status}`);
    selected = { device, payload: await response.json() }; break;
  }
  // No hardware credential in this browser profile means no authentication
  // is possible here. Only a WebAuthn or Secure Enclave device may answer
  // this lane, so the honest instruction is to go back to the terminal.
  if (!selected) { text("status", "No enrolled security key in this browser can authenticate this request. Enter your password at the terminal instead."); return; }
  if (!window.PublicKeyCredential || !navigator.credentials) { text("status", "This browser cannot use a security key. Enter your password at the terminal instead."); return; }
  const sealed = selected.payload.sealed; const shared = sodium.crypto_scalarmult(unb64(selected.device.boxSecret), unb64(sealed.ephemeral_pub));
  if (shared.every(value => value === 0)) throw new Error("invalid shared secret");
  const raw = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, unb64(sealed.ciphertext), null, unb64(sealed.nonce), shared);
  const request = JSON.parse(dec.decode(raw));
  if (request.version !== 2 || request.type !== "sudo_authentication_request" || request.request_id !== id) throw new Error("authentication request mismatch");
  const acknowledgement = await fetch(`/api/v1/auth/${id}/ack`, { method: "POST", headers: { authorization: `Bearer ${selected.device.apiToken}`, "content-type": "application/json" }, body: JSON.stringify({ type: "alive", version: 1, request_id: id }) });
  if (!acknowledgement.ok) throw new Error(`acknowledgement failed ${acknowledgement.status}`);
  const trusted = request.trusted; const submitted = request.submitted ?? {};
  text("host", trusted.host); text("principal", `${trusted.pam_user} / ${trusted.pam_uid}`);
  text("invoking-user", invokingLabel(trusted)); text("service", trusted.service);
  text("tty", typeof trusted.tty === "string" && trusted.tty ? trusted.tty : "unknown");
  if (submitted.session) { text("session", submitted.session); document.getElementById("session-label").hidden = false; document.getElementById("session").hidden = false; }
  text("invocation", formatInvocation(submitted.invocation));
  text("status", `Expires ${new Date(request.expires_at * 1000).toLocaleTimeString()}`);
  for (const shown of ["request", "invocation-note", "actions", "cancel-note"]) document.getElementById(shown).hidden = false;
  const headers = { authorization: `Bearer ${selected.device.apiToken}`, "content-type": "application/json" };
  // One action, and it is affirmative. There is no refusal to send: closing
  // the page sends nothing, and the host falls back to a password prompt.
  //
  // A dismissed or timed-out security key prompt is not a refusal either, so
  // it must not consume the operator's only chance to answer: the button is
  // re-armed and the request stays open until it expires on the host. The
  // `sending` flag, not `{ once: true }`, is what keeps two assertions from
  // being in flight at once.
  const button = document.getElementById("authenticate");
  let sending = false;
  button.addEventListener("click", async () => {
    if (sending) return;
    sending = true; button.disabled = true;
    try {
      const challenge = await sha256(AUTH_CHALLENGE_DOMAIN, raw);
      const assertion = await navigator.credentials.get({ publicKey: { challenge, rpId: location.hostname,
        allowCredentials: [{ type: "public-key", id: unb64(selected.device.credentialId) }], userVerification: "required", timeout: 90000 } });
      const body = { version: 2, request_id: id, device_fingerprint: selected.device.fingerprint, credential_id: b64(assertion.rawId),
        authenticator_data: b64(assertion.response.authenticatorData), client_data_json: b64(assertion.response.clientDataJSON), signature: b64(assertion.response.signature) };
      const response = await fetch(`/api/v1/auth/${id}/authenticate-webauthn`, { method: "POST", headers, body: JSON.stringify(body) });
      if (!response.ok) throw new Error(`authentication failed ${response.status}`);
      text("status", "Authentication sent."); document.getElementById("actions").hidden = true;
    } catch (error) {
      console.error(error);
      text("status", "Authentication cancelled. Enter your password at the terminal, or try again.");
      sending = false; button.disabled = false;
    }
  });
}

// Keep the formatter available to the small, DOM-free unit test as well as
// the page. The approval flow still starts only in a browser document.
if (typeof globalThis !== "undefined") globalThis.OshiokiApprovalReview = { formatEnvironment, quoteReviewString, formatInvocation };
if (typeof document !== "undefined" && document.body) {
  const page = document.body.dataset.page;
  let flow;
  if (page === "enroll") flow = enrollment();
  else if (page === "auth") flow = authentication();
  else flow = approval();
  flow.catch(failure);
}
