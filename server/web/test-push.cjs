"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const appContext = { TextEncoder, TextDecoder, URL, btoa, atob, console, crypto: {}, globalThis: {} };
vm.createContext(appContext);
vm.runInContext(fs.readFileSync(`${__dirname}/app.js`, "utf8"), appContext, { filename: "app.js" });
const push = appContext.globalThis.OshiokiPush;

assert.equal(push.parseEnrollmentUrl("https://sudo.test/enroll/abc-123#secret", "https://sudo.test"), "/enroll/abc-123#secret");
assert.throws(() => push.parseEnrollmentUrl("https://other.test/enroll/abc#secret", "https://sudo.test"), /Oshioki origin/);
assert.throws(() => push.parseEnrollmentUrl("https://sudo.test/enroll/abc?x=1#secret", "https://sudo.test"), /fragment secret/);
assert.throws(() => push.parseEnrollmentUrl("https://sudo.test/setup#secret", "https://sudo.test"), /\/enroll\/<id>/);
assert.throws(() => push.parseEnrollmentUrl("https://sudo.test/enroll/abc", "https://sudo.test"), /fragment secret/);

const events = {};
const shown = [];
const worker = {
  location: { origin: "https://sudo.test" },
  addEventListener(name, listener) { events[name] = listener; },
  registration: { showNotification: async (...args) => shown.push(args) },
  clients: { matchAll: async () => [], openWindow: async target => ({ target }) },
};
const workerContext = { self: worker, URL, console };
vm.createContext(workerContext);
vm.runInContext(fs.readFileSync(`${__dirname}/service-worker.js`, "utf8"), workerContext, { filename: "service-worker.js" });
const workerApi = worker.OshiokiPushWorker;
assert.equal(JSON.stringify(workerApi.pushPayload({ version: 1, lane: "request", request_id: "req-1" })), JSON.stringify({ version: 1, lane: "request", request_id: "req-1" }));
assert.equal(workerApi.notificationTarget({ version: 1, lane: "auth", request_id: "auth-1" }), "https://sudo.test/a/auth-1");
assert.equal(workerApi.notificationTarget({ version: 1, lane: "tool", request_id: "tool-1" }), "https://sudo.test/t/tool-1");
assert.equal(workerApi.notificationTag({ version: 1, lane: "request", request_id: "req-1" }), "request:req-1");
assert.equal(workerApi.pushPayload({ version: 1, lane: "request", request_id: "../r/evil" }), null);
assert.equal(workerApi.notificationTarget({ version: 2, lane: "request", request_id: "req-1" }), null);
assert.equal(workerApi.pushPayload({ version: 1, lane: "unknown", request_id: "req-1" }), null);

let pushWait;
events.push({
  data: { json: () => ({ version: 1, lane: "request", request_id: "req-1" }) },
  waitUntil(value) { pushWait = value; },
});
pushWait.then(() => {
  assert.equal(shown.length, 1);
  assert.equal(shown[0][0], "Oshioki");
  assert.equal(shown[0][1].tag, "request:req-1");
  assert.equal(shown[0][1].data.request_id, "req-1");

  let focused = false;
  worker.clients.matchAll = async () => [{ url: "https://sudo.test/setup", navigate: async target => ({ focus: async () => { assert.equal(target, "https://sudo.test/r/req-2"); focused = true; } }), focus: async () => { focused = true; } }];
  let clickWait;
  events.notificationclick({ notification: { data: { version: 1, lane: "request", request_id: "req-2" }, close() {} }, waitUntil(value) { clickWait = value; } });
  return clickWait.then(() => {
    assert.equal(focused, true);
    let opened;
    worker.clients.openWindow = async target => { opened = target; return null; };
    worker.clients.matchAll = async () => [{ url: "https://sudo.test/setup", navigate: async () => { throw new Error("closed client"); }, focus: async () => {} }];
    let fallbackWait;
    events.notificationclick({ notification: { data: { version: 1, lane: "auth", request_id: "auth-3" }, close() {} }, waitUntil(value) { fallbackWait = value; } });
    return fallbackWait.then(() => {
      assert.equal(opened, "https://sudo.test/a/auth-3");
      console.log("push browser tests passed");
    });
  });
}).catch(error => { console.error(error); process.exitCode = 1; });

// Serialize transactions like IndexedDB, including requests queued from an
// onsuccess callback. Contexts share this database to exercise bootstrap races.
function fakeIndexedDb(stores) {
  const transactions = [];
  let active = false;
  function runNext() {
    if (active || !transactions.length) return;
    active = true;
    const tx = transactions.shift();
    function step() {
      if (tx.aborted) { active = false; tx.onabort?.(); runNext(); return; }
      const entry = tx.operations.shift();
      if (!entry) { active = false; tx.oncomplete?.(); runNext(); return; }
      const { request, action } = entry;
      try { request.result = structuredClone(action()); request.onsuccess?.(); }
      catch (error) { request.error = error; tx.error = error; request.onerror?.(); tx.onerror?.(); }
      queueMicrotask(step);
    }
    queueMicrotask(step);
  }
  const database = {
    transaction() {
      const tx = { operations: [], abort() { tx.aborted = true; }, objectStore(name) {
        const store = stores[name];
        function operation(action) {
          const request = {};
          tx.operations.push({ request, action });
          return request;
        }
        return {
          get(key) { return operation(() => store.get(key)); },
          getAll() { return operation(() => [...store.values()]); },
          put(value) { return operation(() => store.set(name === "devices" ? value.fingerprint : value.key, structuredClone(value))); },
          delete(key) { return operation(() => store.delete(key)); },
        };
      } };
      transactions.push(tx);
      queueMicrotask(runNext);
      return tx;
    },
    close() {},
  };
  return { open() {
    const request = {};
    queueMicrotask(() => { request.result = database; request.onsuccess?.(); });
    return request;
  } };
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function pushHarness({ legacy = false, subscription = true } = {}) {
  const stores = { devices: new Map(), settings: new Map() };
  stores.devices.set("first", { fingerprint: "first", apiToken: "first-token" });
  stores.devices.set("second", { fingerprint: "second", apiToken: "second-token" });
  if (legacy) {
    stores.settings.set("pushOwnerFingerprint", { key: "pushOwnerFingerprint", value: "second" });
    stores.settings.set("pushSubscriptionId", { key: "pushSubscriptionId", value: "second-id" });
  }
  const calls = [], events = [];
  let unsubscribed = 0, subscribed = 0, permissionRequests = 0;
  function makeSubscription(endpoint) {
    return {
      endpoint, expirationTime: null,
      toJSON: () => ({ keys: { p256dh: "p256dh", auth: "auth" } }),
      unsubscribe: async () => { unsubscribed++; currentSubscription = null; return true; },
    };
  }
  let currentSubscription = subscription ? makeSubscription("https://push.example/original") : null;
  let multiEnrollment = true;
  let nextEndpoint = "https://push.example/fresh";
  let post = async (_body, bearer) => ({ ok: true, status: 200, json: async () => ({ version: 1, subscription_id: `${bearer.slice(7)}-id` }) });
  let status = async () => ({ ok: true, status: 200, json: async () => ({ version: 1, enabled: true, registered: false, count: 0 }) });
  let lockQueue = Promise.resolve();
  const locks = { request(_name, _options, action) {
    events.push("lock");
    const result = lockQueue.then(action);
    lockQueue = result.catch(() => {});
    return result;
  } };
  const indexedDB = fakeIndexedDb(stores);
  function context() {
    const sandbox = { TextEncoder, TextDecoder, Uint8Array, URL, btoa, atob, console, crypto: require("node:crypto").webcrypto,
      indexedDB, navigator: { locks, serviceWorker: { register: async () => ({ pushManager: {
        getSubscription: async () => currentSubscription,
        subscribe: async () => { subscribed++; currentSubscription = makeSubscription(nextEndpoint); return currentSubscription; },
      } }) } }, PushManager: class {}, Notification: { permission: "granted", requestPermission: async () => { events.push("permission"); permissionRequests++; return "granted"; } }, isSecureContext: true,
      fetch: async (url, options = {}) => {
        calls.push({ url, options });
        if (url.endsWith("/push/config")) return { ok: true, status: 200, json: async () => ({ version: 1, enabled: true, multi_enrollment: multiEnrollment, vapid_public_key: "B".repeat(87) }) };
        if (url.endsWith("/push/status")) return status(options.headers.authorization);
        if (url.endsWith("/push/subscriptions") && options.method === "POST") return post(JSON.parse(options.body), options.headers.authorization);
        throw new Error(`unexpected fetch ${url}`);
      },
    };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(`${__dirname}/app.js`, "utf8"), sandbox, { filename: "app.js" });
    return sandbox;
  }
  const sandbox = context();
  return { stores, calls, events, sandbox, push: sandbox.OshiokiPush, context,
    posts: () => calls.filter(call => call.options.method === "POST"),
    setPost(value) { post = value; }, setStatus(value) { status = value; }, setMultiEnrollment(value) { multiEnrollment = value; }, setNextEndpoint(value) { nextEndpoint = value; },
    counters: () => ({ unsubscribed, subscribed, permissionRequests }),
  };
}
const json = value => JSON.parse(JSON.stringify(value));
async function testSharedEnrollment() {
  const h = pushHarness({ legacy: true });
  const result = await h.push.syncOwnedPushSubscription();
  assert.equal(result.registered, 2);
  assert.deepEqual(h.posts().map(call => call.options.headers.authorization), ["Bearer second-token", "Bearer first-token"]);
  const bodies = h.posts().map(call => JSON.parse(call.options.body));
  assert.equal(bodies[0].endpoint, "https://push.example/original");
  assert.equal(bodies[0].installation_token, bodies[1].installation_token);
  assert.match(bodies[0].installation_token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from(bodies[0].installation_token, "base64url").length, 32);
  assert.equal(Buffer.from(bodies[0].installation_token, "base64url").toString("base64url"), bodies[0].installation_token);
  assert.equal(await h.push.getSetting("pushOwnerFingerprint"), undefined);
  assert.equal(await h.push.getSetting("pushSubscriptionId"), undefined);
  assert.equal((await h.push.getSetting("pushBinding")).state, "bound");
  h.stores.devices.set("third", { fingerprint: "third", apiToken: "third-token" });
  await h.push.syncOwnedPushSubscription();
  assert.equal((await h.push.getSetting("pushBinding")).registrations.third, "third-token-id");
  assert.deepEqual(h.counters(), { unsubscribed: 0, subscribed: 0, permissionRequests: 0 });
  assert.equal(new Set(h.posts().map(call => JSON.parse(call.options.body).endpoint)).size, 1);
  assert.ok(h.calls.every(call => !call.url.includes(bodies[0].installation_token) && !call.url.includes("first-token")));
}
async function testPendingRetryAndClaimFailure() {
  const h = pushHarness({ legacy: true });
  let acceptedToken;
  h.setPost(async (body, bearer) => {
    assert.equal(bearer, "Bearer second-token");
    acceptedToken = body.installation_token;
    throw new Error("response lost");
  });
  await assert.rejects(h.push.syncOwnedPushSubscription(), /response lost/);
  const pending = await h.push.getSetting("pushBinding");
  assert.equal(pending.state, "pending");
  assert.equal(pending.installation_token, acceptedToken);
  assert.equal(await h.push.getSetting("pushOwnerFingerprint"), "second");
  h.setPost(async (body, bearer) => {
    assert.equal(body.installation_token, acceptedToken);
    return { ok: true, status: 200, json: async () => ({ version: 1, subscription_id: `${bearer}-id` }) };
  });
  await h.push.syncOwnedPushSubscription();
  assert.deepEqual(h.posts().map(call => call.options.headers.authorization), ["Bearer second-token", "Bearer second-token", "Bearer first-token"]);

  const denied = pushHarness({ legacy: true });
  denied.setPost(async () => ({ ok: false, status: 409, json: async () => { throw new Error("must not read private error body"); } }));
  await assert.rejects(denied.push.syncOwnedPushSubscription(), /Replace notification subscription/);
  assert.equal(denied.posts().length, 1);
  assert.equal((await denied.push.getSetting("pushBinding")).state, "pending");
  assert.equal(await denied.push.getSetting("pushOwnerFingerprint"), "second");
  assert.deepEqual(denied.counters(), { unsubscribed: 0, subscribed: 0, permissionRequests: 0 });
  denied.setPost(async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError("private response body must stay hidden"); } }));
  await assert.rejects(denied.push.syncOwnedPushSubscription(), error => error.message === "invalid push registration response");
}
async function testExplicitRecovery() {
  const h = pushHarness();
  await assert.rejects(h.push.syncOwnedPushSubscription(), /Replace notification subscription/);
  assert.equal(h.posts().length, 0);
  assert.equal(await h.push.getSetting("pushBinding"), undefined);
  await assert.rejects(h.push.enablePushForDevice(h.stores.devices.get("first")), /Replace notification subscription/);
  assert.equal(h.counters().unsubscribed, 0);
  const result = await h.push.enablePushForDevice(h.stores.devices.get("first"), { replace: true });
  assert.equal(result.registered, 2);
  assert.deepEqual(h.counters(), { unsubscribed: 1, subscribed: 1, permissionRequests: 0 });
  assert.equal((await h.push.getSetting("pushBinding")).endpoint, "https://push.example/fresh");

  const unchanged = pushHarness();
  unchanged.setNextEndpoint("https://push.example/original");
  await assert.rejects(unchanged.push.enablePushForDevice(null, { replace: true }), /Replace notification subscription/);
  assert.equal(unchanged.posts().length, 0);

  const missingOwner = pushHarness({ legacy: true });
  missingOwner.stores.devices.delete("second");
  await assert.rejects(missingOwner.push.syncOwnedPushSubscription(), /Replace notification subscription/);
  assert.equal(await missingOwner.push.getSetting("pushOwnerFingerprint"), "second");
  assert.equal(missingOwner.posts().length, 0);
}
async function testPartialAndRevokedEnrollment() {
  const h = pushHarness({ subscription: false });
  h.setPost(async (_body, bearer) => bearer === "Bearer second-token"
    ? { ok: false, status: 503 }
    : { ok: true, status: 200, json: async () => ({ version: 1, subscription_id: "first-id" }) });
  const partial = await h.push.enablePushForDevice(h.stores.devices.get("second"));
  assert.equal(partial.registered, 1);
  assert.equal(partial.failures.length, 1);
  assert.match(h.push.pushStatusText(partial), /1 of 2.*Some enrollments/);
  const token = (await h.push.getSetting("pushBinding")).installation_token;
  h.setPost(async (_body, bearer) => ({ ok: true, status: 200, json: async () => ({ version: 1, subscription_id: `${bearer}-id` }) }));
  assert.equal((await h.push.syncOwnedPushSubscription()).registered, 2);
  h.setPost(async (_body, bearer) => bearer === "Bearer first-token"
    ? { ok: false, status: 401 }
    : { ok: true, status: 200, json: async () => ({ version: 1, subscription_id: "second-id" }) });
  const revoked = await h.push.syncOwnedPushSubscription();
  assert.equal(revoked.registered, 1);
  const binding = await h.push.getSetting("pushBinding");
  assert.equal(binding.registrations.first, undefined);
  assert.equal(binding.registrations.second, "second-id");
  assert.equal(binding.installation_token, token);
  assert.equal(h.counters().unsubscribed, 0);
}
function revokeFirstEnrollment(h) {
  h.setStatus(async bearer => bearer === "Bearer first-token"
    ? { ok: false, status: 401, json: async () => { throw new Error("private error body"); } }
    : { ok: true, status: 200, json: async () => ({ version: 1, enabled: true, registered: false, count: 0 }) });
  h.setPost(async (_body, bearer) => bearer === "Bearer first-token"
    ? { ok: false, status: 401 }
    : { ok: true, status: 200, json: async () => ({ version: 1, subscription_id: "second-id" }) });
}
async function testFreshBootstrapSkipsRevokedEnrollment() {
  for (const replace of [false, true]) {
    const h = pushHarness({ subscription: replace });
    revokeFirstEnrollment(h);
    const result = await h.push.enablePushForDevice(h.stores.devices.get("first"), { replace });
    const binding = await h.push.getSetting("pushBinding");
    assert.equal(binding.bootstrap_fingerprint, "second");
    assert.equal(binding.state, "bound");
    assert.deepEqual(json(binding.registrations), { second: "second-id" });
    assert.equal(result.registered, 1);
    assert.equal(result.total, 2);
    assert.equal(result.failures[0].status, 401);
    assert.match(h.push.pushStatusText(result), /1 of 2.*unavailable or revoked/);
    assert.deepEqual(h.calls.filter(call => call.url.endsWith("/push/status")).map(call => call.options.headers.authorization),
      ["Bearer first-token", "Bearer second-token"]);
    assert.deepEqual(h.posts().map(call => call.options.headers.authorization), ["Bearer second-token", "Bearer first-token"]);
    await h.push.syncOwnedPushSubscription();
    assert.deepEqual(json(await h.push.getSetting("pushBinding")), json(binding));
    assert.equal(h.calls.filter(call => call.url.endsWith("/push/status")).length, 2);
    assert.deepEqual(h.counters(), { unsubscribed: Number(replace), subscribed: 1, permissionRequests: 0 });
  }

  // Automatic renewal has a previous binding, but no local claim for the new
  // endpoint. It must validate the new bootstrap just like explicit enable.
  const renewed = pushHarness();
  await renewed.push.createPushBinding("https://push.example/previous", "first");
  revokeFirstEnrollment(renewed);
  assert.equal((await renewed.push.syncOwnedPushSubscription()).registered, 1);
  assert.equal((await renewed.push.getSetting("pushBinding")).bootstrap_fingerprint, "second");
}
async function testFreshBootstrapRetryIsImmutable() {
  const h = pushHarness({ subscription: false });
  revokeFirstEnrollment(h);
  h.setPost(async (_body, bearer) => {
    assert.equal(bearer, "Bearer second-token");
    const binding = await h.push.getSetting("pushBinding");
    assert.equal(binding.state, "pending");
    assert.equal(binding.bootstrap_fingerprint, "second");
    return { ok: false, status: 503 };
  });
  await assert.rejects(h.push.enablePushForDevice(null), /registration failed \(503\)/);
  const pending = json(await h.push.getSetting("pushBinding"));
  assert.deepEqual(pending.registrations, {});
  h.setStatus(async () => { throw new Error("pending bootstrap must not reselect any identity"); });
  h.setPost(async () => ({ ok: false, status: 401 }));
  await assert.rejects(h.push.syncOwnedPushSubscription(), /Replace notification subscription/);
  assert.deepEqual(json(await h.push.getSetting("pushBinding")), pending);
  h.setPost(async (_body, bearer) => bearer === "Bearer first-token"
    ? { ok: false, status: 401 }
    : { ok: true, status: 200, json: async () => ({ version: 1, subscription_id: "second-id" }) });
  const result = await h.push.enablePushForDevice(h.stores.devices.get("first"));
  const bound = await h.push.getSetting("pushBinding");
  assert.equal(result.registered, 1);
  assert.equal(result.failures[0].status, 401);
  assert.equal(bound.state, "bound");
  assert.equal(bound.bootstrap_fingerprint, "second");
  assert.equal(bound.installation_token, pending.installation_token);
  assert.deepEqual(h.posts().map(call => call.options.headers.authorization),
    ["Bearer second-token", "Bearer second-token", "Bearer second-token", "Bearer first-token"]);
  assert.ok(h.posts().every(call => JSON.parse(call.options.body).installation_token === pending.installation_token));
  assert.deepEqual(h.counters(), { unsubscribed: 0, subscribed: 1, permissionRequests: 0 });
}
async function testBootstrapValidationFailsSafely() {
  for (const status of [403, 503]) {
    const h = pushHarness({ subscription: false });
    h.setStatus(async () => ({ ok: false, status, json: async () => { throw new Error("private error body"); } }));
    await assert.rejects(h.push.enablePushForDevice(null), new RegExp(`enrollment check failed \\(${status}\\)`));
    assert.equal(h.calls.filter(call => call.url.endsWith("/push/status")).length, 1);
    assert.equal(h.posts().length, 0);
    assert.equal(await h.push.getSetting("pushBinding"), undefined);
  }
  const malformed = pushHarness({ subscription: false });
  malformed.setStatus(async () => ({ ok: true, status: 200, json: async () => ({ version: 1 }) }));
  await assert.rejects(malformed.push.enablePushForDevice(null), /invalid push status response/);
  assert.equal(malformed.posts().length, 0);
  assert.equal(await malformed.push.getSetting("pushBinding"), undefined);
  const unavailable = pushHarness({ subscription: false });
  unavailable.setStatus(async () => ({ ok: false, status: 401 }));
  await assert.rejects(unavailable.push.enablePushForDevice(null), /No active saved enrollment/);
  assert.equal(unavailable.posts().length, 0);
  assert.equal(await unavailable.push.getSetting("pushBinding"), undefined);
  const legacy = pushHarness({ legacy: true });
  revokeFirstEnrollment(legacy);
  legacy.setStatus(async () => { throw new Error("legacy ownership must not be reselected"); });
  assert.equal((await legacy.push.syncOwnedPushSubscription()).registered, 1);
  assert.equal(legacy.posts()[0].options.headers.authorization, "Bearer second-token");
}
async function testBootstrapPreflightRetry() {
  const failures = [
    { response: async () => ({ ok: false, status: 403 }), message: /enrollment check failed \(403\)/ },
    { response: async () => ({ ok: false, status: 503 }), message: /enrollment check failed \(503\)/ },
    { response: async () => { throw new TypeError("network unavailable"); }, message: /network unavailable/ },
    { response: async () => ({ ok: true, status: 200, json: async () => ({ version: 1 }) }), message: /invalid push status response/ },
    { response: async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError("invalid JSON"); } }), message: /invalid push status response/ },
    { response: async () => ({ ok: false, status: 401 }), message: /No active saved enrollment/, checks: 2 },
  ];
  for (const replace of [false, true]) {
    for (const failure of failures) {
      const h = pushHarness({ legacy: replace, subscription: replace });
      if (replace) await h.push.syncOwnedPushSubscription();
      const previous = replace ? json(await h.push.getSetting("pushBinding")) : undefined;
      h.calls.length = 0;
      h.setStatus(failure.response);
      await assert.rejects(h.push.enablePushForDevice(null, { replace }), failure.message);
      assert.equal(h.calls.filter(call => call.url.endsWith("/push/status")).length, failure.checks || 1);
      assert.equal(h.posts().length, 0);
      assert.deepEqual(h.counters(), { unsubscribed: 0, subscribed: 0, permissionRequests: 0 });
      const registration = await h.sandbox.navigator.serviceWorker.register();
      assert.equal((await registration.pushManager.getSubscription())?.endpoint, previous?.endpoint);
      if (replace) {
        assert.deepEqual(json(await h.push.getSetting("pushBinding")), previous);
        // The old endpoint stays usable even while candidate checks fail.
        assert.equal((await h.push.syncOwnedPushSubscription()).registered, 2);
        assert.deepEqual(json(await h.push.getSetting("pushBinding")), previous);
        assert.ok(h.posts().every(call => {
          const body = JSON.parse(call.options.body);
          return body.endpoint === previous.endpoint && body.installation_token === previous.installation_token;
        }));
        assert.equal(h.calls.filter(call => call.url.endsWith("/push/status")).length, failure.checks || 1);
      } else {
        assert.equal(await h.push.getSetting("pushBinding"), undefined);
      }
      h.calls.length = 0;
      h.setStatus(async () => ({ ok: true, status: 200, json: async () => ({ version: 1, enabled: true, registered: false, count: 0 }) }));
      const result = await h.push.enablePushForDevice(null, { replace });
      assert.equal(result.registered, 2);
      assert.equal(result.failures.length, 0);
      assert.equal(h.calls.filter(call => call.url.endsWith("/push/status")).length, 1);
      assert.deepEqual(h.counters(), { unsubscribed: Number(replace), subscribed: 1, permissionRequests: 0 });
      assert.equal((await h.push.getSetting("pushBinding")).endpoint, "https://push.example/fresh");
    }
  }
}
async function testAtomicBootstrapAndStaleSuccess() {
  const h = pushHarness({ legacy: true });
  const other = h.context().OshiokiPush;
  const [a, b] = await Promise.all([
    h.push.createPushBinding("https://push.example/original", "second"),
    other.createPushBinding("https://push.example/original", "first"),
  ]);
  assert.equal(a.installation_token, b.installation_token);
  assert.equal(a.bootstrap_fingerprint, b.bootstrap_fingerprint);
  await Promise.all([h.push.syncOwnedPushSubscription(), other.syncOwnedPushSubscription()]);
  assert.equal(new Set(h.posts().map(call => JSON.parse(call.options.body).installation_token)).size, 1);
  assert.equal((await h.push.getSetting("pushBinding")).state, "bound");
  await Promise.all([h.push.savePushRegistration(a, "first", "one"), other.savePushRegistration(a, "second", "two")]);
  assert.deepEqual(json((await h.push.getSetting("pushBinding")).registrations), { first: "one", second: "two" });

  const entered = deferred(), released = deferred();
  h.setPost(async () => { entered.resolve(); await released.promise; return { ok: true, status: 200, json: async () => ({ version: 1, subscription_id: "stale-id" }) }; });
  const syncing = h.push.syncOwnedPushSubscription();
  await entered.promise;
  const replacement = await other.createPushBinding("https://push.example/replacement", "second");
  released.resolve();
  await assert.rejects(syncing, /subscription changed/);
  assert.deepEqual(json(await h.push.getSetting("pushBinding")), json(replacement));
}
async function testCompatibilityAndPermission() {
  const oldServer = pushHarness({ legacy: true });
  oldServer.setMultiEnrollment(false);
  const before = json([...oldServer.stores.settings]);
  await assert.rejects(oldServer.push.syncOwnedPushSubscription(), /server needs an update/);
  await assert.rejects(oldServer.push.enablePushForDevice(null, { replace: true }), /server needs an update/);
  assert.deepEqual(json([...oldServer.stores.settings]), before);
  assert.equal(oldServer.posts().length, 0);
  assert.equal(oldServer.counters().unsubscribed, 0);

  const unsupported = pushHarness({ legacy: true });
  delete unsupported.sandbox.navigator.locks;
  await assert.rejects(unsupported.push.syncOwnedPushSubscription(), /Web Locks/);
  assert.equal(unsupported.calls.length, 0);
  assert.equal(await unsupported.push.getSetting("pushOwnerFingerprint"), "second");

  const gesture = pushHarness({ subscription: false });
  gesture.sandbox.Notification.permission = "default";
  const enabling = gesture.push.enablePushForDevice(null);
  assert.deepEqual(gesture.events, ["permission"]);
  await enabling;
  assert.deepEqual(gesture.events.slice(0, 2), ["permission", "lock"]);
}
async function testApprovalUsesAuthorizedEnrollment() {
  const sodium = require("libsodium-wrappers");
  await sodium.ready;
  const h = pushHarness({ subscription: false });
  const firstBox = sodium.crypto_box_keypair(), secondBox = sodium.crypto_box_keypair();
  const encode = value => Buffer.from(value).toString("base64url");
  h.stores.devices.set("first", { fingerprint: "first", apiToken: "first-token", boxSecret: encode(firstBox.privateKey), credentialId: encode([1, 1]) });
  h.stores.devices.set("second", { fingerprint: "second", apiToken: "second-token", boxSecret: encode(secondBox.privateKey), credentialId: encode([2, 2]) });
  const request = { version: 1, request_id: "second-request", host: "second-host", user: "eric", uid: 1000, runas_uid: 0,
    command: "/usr/bin/true", argv: ["/usr/bin/true"], cwd: "/tmp", pid_chain: [], expires_at: 1900000000 };
  const raw = Buffer.from(JSON.stringify(request));
  const ephemeral = sodium.crypto_box_keypair(), nonce = sodium.randombytes_buf(12);
  const shared = sodium.crypto_scalarmult(ephemeral.privateKey, secondBox.publicKey);
  const sealed = { device_fingerprint: "second", ephemeral_pub: encode(ephemeral.publicKey), nonce: encode(nonce),
    ciphertext: encode(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(raw, null, null, nonce, shared)) };
  const elements = new Map();
  h.sandbox.document = { getElementById(id) {
    if (!elements.has(id)) elements.set(id, { hidden: true, textContent: "", addEventListener(name, action) { this[name] = action; } });
    return elements.get(id);
  } };
  h.sandbox.location = { pathname: "/r/second-request", hostname: "sudo.test" };
  h.sandbox.sodium = sodium;
  const calls = [];
  let credentialCalls = 0;
  h.sandbox.navigator.credentials = { get: async ({ publicKey }) => {
    credentialCalls++;
    assert.equal(encode(publicKey.allowCredentials[0].id), encode([2, 2]));
    const expected = require("node:crypto").createHash("sha256").update("oshioki/approve/v1\0").update(raw).digest();
    assert.equal(encode(publicKey.challenge), encode(expected));
    return { rawId: Uint8Array.from([2, 2]), response: { authenticatorData: Uint8Array.from([3]), clientDataJSON: Uint8Array.from([4]), signature: Uint8Array.from([5]) } };
  } };
  let available = true;
  h.sandbox.fetch = async (url, options) => {
    calls.push({ url, options });
    const owns = available && options.headers.authorization === "Bearer second-token";
    if (!owns) return { ok: false, status: 401 };
    if (url.endsWith("/second-request")) return { ok: true, status: 200, json: async () => ({ sealed }) };
    if (url.endsWith("/approve")) {
      const body = JSON.parse(options.body);
      assert.equal(body.device_fingerprint, "second");
      assert.equal(body.credential_id, encode([2, 2]));
    }
    return { ok: true, status: 200 };
  };
  await vm.runInContext("approval()", h.sandbox);
  assert.equal(elements.get("host").textContent, "second-host");
  await elements.get("approve").click();
  assert.equal(credentialCalls, 1);
  assert.deepEqual(calls.filter(call => call.options.method === "POST").map(call => call.options.headers.authorization), ["Bearer second-token", "Bearer second-token"]);
  available = false;
  const callCount = calls.length;
  await assert.rejects(vm.runInContext("approval()", h.sandbox), /no enrolled browser profile owns/);
  assert.equal(credentialCalls, 1);
  assert.ok(calls.slice(callCount).every(call => call.options.method !== "POST"));
}
(async () => {
  await testSharedEnrollment();
  await testPendingRetryAndClaimFailure();
  await testExplicitRecovery();
  await testPartialAndRevokedEnrollment();
  await testFreshBootstrapSkipsRevokedEnrollment();
  await testFreshBootstrapRetryIsImmutable();
  await testBootstrapValidationFailsSafely();
  await testBootstrapPreflightRetry();
  await testAtomicBootstrapAndStaleSuccess();
  await testCompatibilityAndPermission();
  await testApprovalUsesAuthorizedEnrollment();
  console.log("multi-enrollment push lifecycle and approval identity tests passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
