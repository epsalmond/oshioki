"use strict";

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });
const REGISTRATION_DOMAIN = enc.encode("management-plane-sudo-approve/enroll/registration/v1\0");
const PROOF_DOMAIN = enc.encode("management-plane-sudo-approve/enroll/proof/v1\0");
const TRANSCRIPT_DOMAIN = enc.encode("management-plane-sudo-approve/enroll/transcript/v1\0");
const APPROVE_DOMAIN = enc.encode("management-plane-sudo-approve/approve/v1\0");

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
    const request = indexedDB.open("management-plane-sudo-approve", 1);
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
      const submission = { version: 1, enrollment_id: enrollmentId, registration_client_data_json: b64(fields[1]), attestation_object: b64(fields[2]),
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
  text("host", request.host); text("user", `${request.user} / ${request.uid}`); text("command", request.command);
  text("argv", request.argv.join("\n")); text("cwd", request.cwd); text("process-chain", request.pid_chain.join("\n"));
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

(document.body.dataset.page === "enroll" ? enrollment() : approval()).catch(failure);
