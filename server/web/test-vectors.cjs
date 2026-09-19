"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const vm = require("node:vm");
const sodium = require("libsodium-wrappers");

const decode = value => Buffer.from(value, "base64url");

sodium.ready.then(() => {
  const browserSource = fs.readFileSync(`${__dirname}/app.js`, "utf8");
  const browserContext = { console, TextEncoder, TextDecoder, crypto: {}, globalThis: {} };
  vm.createContext(browserContext);
  vm.runInContext(browserSource, browserContext, { filename: "app.js" });
  const { formatEnvironment, quoteReviewString } = browserContext.globalThis.OshiokiApprovalReview;
  assert.equal(
    formatEnvironment([
      { name: "BASH_ENV", value: "/tmp/attacker-init" },
      { name: "LD_PRELOAD", value: "/tmp/evil\\n.so\\\";echo pwned" },
    ]),
    '[0] name="BASH_ENV" value="/tmp/attacker-init"\n[1] name="LD_PRELOAD" value="/tmp/evil\\\\n.so\\\\\\\";echo pwned"',
  );
  assert.equal(quoteReviewString("suffix\u202e-hidden"), '"suffix\\u202e-hidden"');

  const requestGolden = JSON.parse(fs.readFileSync(
    `${__dirname}/../../tests/compat/goldens/request-v1.json`,
    "utf8",
  ));
  assert.equal(requestGolden.version, 1);
  assert.equal(requestGolden.request_id, "req-1");
  assert.equal(requestGolden.command, "/usr/bin/apt");
  const authGolden = JSON.parse(fs.readFileSync(
    `${__dirname}/../../tests/compat/goldens/auth-envelope-v2.json`,
    "utf8",
  ));
  assert.equal(authGolden.type, "sudo_authentication");
  assert.equal(authGolden.version, 2);

  const raw = Buffer.from('{"version":1,"request_id":"vector-1"}');
  const challenge = crypto.createHash("sha256")
    .update(Buffer.from("oshioki/approve/v1\0"))
    .update(raw).digest("base64url");
  assert.equal(challenge, "mTBOp81bPTi4PmjpqFmNPFz3vFWCzk1yBKBHmHEkWV4");

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
