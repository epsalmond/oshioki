"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const sodium = require("libsodium-wrappers");

const decode = value => Buffer.from(value, "base64url");

sodium.ready.then(() => {
  const raw = Buffer.from('{"version":1,"request_id":"vector-1"}');
  const challenge = crypto.createHash("sha256")
    .update(Buffer.from("management-plane-sudo-approve/approve/v1\0"))
    .update(raw).digest("base64url");
  assert.equal(challenge, "5VNwjeIaxy3rOFXvz7lUoZvgjLjgWdxzU3255JY4qBI");

  const shared = sodium.crypto_scalarmult(
    decode("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"),
    decode("V9tLNZ8jrl4Ubk4lEgVnBHIlBjSMFQwUdT0Mkz0E1CE"),
  );
  const plaintext = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
    null,
    decode("WGPFmg8nyJM8A4tNZfX1esd_ehYPrFuiMKhs5FTOL35DUvX_DGXi6B03BbDA8HPF5zbxCGE"),
    null,
    decode("CwsLCwsLCwsLCwsL"),
    shared,
  );
  assert.deepEqual(Buffer.from(plaintext), raw);
}).catch(error => {
  console.error(error);
  process.exitCode = 1;
});
