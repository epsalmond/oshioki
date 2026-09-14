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
assert.equal(workerApi.notificationTag({ version: 1, lane: "request", request_id: "req-1" }), "request:req-1");
assert.equal(workerApi.pushPayload({ version: 1, lane: "request", request_id: "../r/evil" }), null);
assert.equal(workerApi.notificationTarget({ version: 2, lane: "request", request_id: "req-1" }), null);

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

function fakeIndexedDb(stores) {
  const database = {
    transaction(names) {
      const tx = { objectStore(name) {
        const store = stores[name];
        return {
          get(key) { return operation(tx, () => store.get(key)); },
          put(value) { return operation(tx, () => store.set(value.key, value)); },
          delete(key) { return operation(tx, () => store.delete(key)); },
        };
      } };
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
function operation(tx, action) {
  const request = {};
  queueMicrotask(() => {
    try { request.result = action(); request.onsuccess?.(); }
    catch (error) { request.error = error; request.onerror?.(); }
    queueMicrotask(() => tx.oncomplete?.());
  });
  return request;
}

async function testOwnerSelectionAndTransfer() {
  const stores = { devices: new Map(), settings: new Map() };
  stores.devices.set("first", { fingerprint: "first", apiToken: "first-token" });
  stores.devices.set("second", { fingerprint: "second", apiToken: "second-token" });
  stores.settings.set("pushOwnerFingerprint", { key: "pushOwnerFingerprint", value: "second" });
  stores.settings.set("pushSubscriptionId", { key: "pushSubscriptionId", value: "second-id" });
  let currentSubscription = {
    endpoint: "https://push.example/second",
    expirationTime: null,
    toJSON: () => ({ keys: { p256dh: "p256dh", auth: "auth" } }),
    unsubscribe: async () => { currentSubscription = null; return true; },
  };
  const registration = {
    pushManager: {
      getSubscription: async () => currentSubscription,
      subscribe: async () => {
        currentSubscription = {
          endpoint: "https://push.example/fresh",
          expirationTime: null,
          toJSON: () => ({ keys: { p256dh: "fresh-p256dh", auth: "fresh-auth" } }),
          unsubscribe: async () => { currentSubscription = null; return true; },
        };
        return currentSubscription;
      },
    },
  };
  const ownerContext = { TextEncoder, TextDecoder, URL, btoa, atob, console, crypto: {}, navigator: { serviceWorker: { register: async () => registration } }, PushManager: class {}, Notification: { permission: "granted", requestPermission: async () => "granted" }, isSecureContext: true };
  ownerContext.globalThis = ownerContext;
  vm.createContext(ownerContext);
  ownerContext.indexedDB = fakeIndexedDb(stores);
  const calls = [];
  ownerContext.fetch = async (url, options = {}) => {
    calls.push({ url, options });
    if (url.endsWith("/push/config")) return { ok: true, status: 200, json: async () => ({ version: 1, enabled: true, vapid_public_key: "B".repeat(87) }) };
    if (url.endsWith("/push/status")) return { ok: true, status: 200, json: async () => ({ version: 1, enabled: true, registered: true, count: 1 }) };
    if (options.method === "DELETE") return { ok: false, status: 401, json: async () => ({}) };
    if (options.method === "POST") return { ok: true, status: 200, json: async () => ({ version: 1, subscription_id: "fresh-id" }) };
    throw new Error(`unexpected fetch ${url}`);
  };
  vm.runInContext(fs.readFileSync(`${__dirname}/app.js`, "utf8"), ownerContext, { filename: "app.js" });
  const ownerPush = ownerContext.globalThis.OshiokiPush;
  const synced = await ownerPush.syncOwnedPushSubscription();
  assert.equal(synced.device.apiToken, "second-token");
  const syncPost = calls.find(call => call.options.method === "POST");
  assert.equal(syncPost.options.headers.authorization, "Bearer second-token");

  stores.devices.set("old", { fingerprint: "old", apiToken: "old-token" });
  stores.devices.set("new", { fingerprint: "new", apiToken: "new-token" });
  stores.settings.set("pushOwnerFingerprint", { key: "pushOwnerFingerprint", value: "old" });
  stores.settings.set("pushSubscriptionId", { key: "pushSubscriptionId", value: "old-id" });
  currentSubscription = {
    endpoint: "https://push.example/old",
    expirationTime: null,
    toJSON: () => ({ keys: { p256dh: "old-p256dh", auth: "old-auth" } }),
    unsubscribe: async () => { currentSubscription = null; return true; },
  };
  const transfer = await ownerPush.enablePushForDevice({ fingerprint: "new", apiToken: "new-token" });
  assert.equal(transfer.device.apiToken, "new-token");
  const deleteCall = calls.find(call => call.options.method === "DELETE");
  assert.equal(deleteCall.options.headers.authorization, "Bearer old-token");
  const transferPosts = calls.filter(call => call.options.method === "POST");
  const transferPost = transferPosts.at(-1);
  assert.equal(transferPost.options.headers.authorization, "Bearer new-token");
  assert.equal(JSON.parse(transferPost.options.body).endpoint, "https://push.example/fresh");
  assert.equal(await ownerPush.getSetting("pushOwnerFingerprint"), "new");
  assert.equal(await ownerPush.getSetting("pushSubscriptionId"), "fresh-id");
  console.log("push owner tests passed");
}
testOwnerSelectionAndTransfer().catch(error => { console.error(error); process.exitCode = 1; });
