import { expect, test } from "@playwright/test";
import { startTlsProxy } from "../../../scripts/e2e-tls-proxy.mjs";

const origin = process.env.OSHIOKI_ORIGIN ?? "https://sudo.test";
let proxy;

test.beforeAll(async () => { proxy = await startTlsProxy(); });
test.afterAll(async () => {
  if (proxy) await new Promise(resolve => proxy.close(resolve));
});

async function navigate(page, url) {
  try {
    await page.goto(url);
  } catch (error) {
    if (!error.message.includes("ERR_NETWORK_CHANGED")) throw error;
    await new Promise(resolve => setTimeout(resolve, 50));
    await page.goto(url);
  }
}

test("setup accepts only same-origin enrollment URLs and clears the fragment", async ({ page }) => {
  await navigate(page, `${origin}/setup`);
  await page.locator("#enrollment-url").fill("https://other.example/enroll/test-enrollment-1#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.locator("#status")).toContainText("Oshioki origin");
  await expect(page).toHaveURL(/\/setup$/);

  const secret = "A".repeat(43);
  await page.locator("#enrollment-url").fill(`${origin}/enroll/test-enrollment-1#${secret}`);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL(/\/enroll\/test-enrollment-1$/);
  await expect(page).not.toHaveURL(/#/);
  expect(await page.evaluate(() => location.hash)).toBe("");
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
});

async function mockedPushBrowser(page, { fresh = false } = {}) {
  await page.addInitScript(({ fresh }) => {
    const makeSubscription = endpoint => ({
      endpoint, expirationTime: null,
      toJSON: () => ({ keys: { p256dh: "p256dh", auth: "auth" } }),
      unsubscribe: async () => { window.__pushUnsubscribed++; subscription = null; return true; },
    });
    let subscription = fresh ? null : makeSubscription("https://push.example/browser");
    const registration = { pushManager: {
      getSubscription: async () => subscription,
      subscribe: async () => { window.__pushSubscribed++; subscription = makeSubscription("https://push.example/fresh"); return subscription; },
    } };
    Object.defineProperty(navigator, "serviceWorker", { configurable: true, value: { register: async () => registration } });
    Object.defineProperty(window, "PushManager", { configurable: true, writable: true, value: function PushManager() {} });
    // Keep startup reconciliation idle until the fixture DB is ready.
    Object.defineProperty(window, "Notification", { configurable: true, writable: true, value: {
      permission: "default", requestPermission: async () => { window.__pushPermissionRequests++; Notification.permission = "granted"; return "granted"; },
    } });
    window.__pushCalls = [];
    window.__pushStatusCalls = [];
    window.__pushUnsubscribed = 0;
    window.__pushSubscribed = 0;
    window.__pushPermissionRequests = 0;
    Object.defineProperty(window, "__pushSubscriptionEndpoint", { get: () => subscription?.endpoint });
    window.__pushDatabaseReady = new Promise((resolve, reject) => {
      const request = indexedDB.open("oshioki", 2);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains("devices")) request.result.createObjectStore("devices", { keyPath: "fingerprint" });
        if (!request.result.objectStoreNames.contains("settings")) request.result.createObjectStore("settings", { keyPath: "key" });
      };
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction(["devices", "settings"], "readwrite");
        tx.objectStore("devices").put({ fingerprint: "first", apiToken: "first-token" });
        tx.objectStore("devices").put({ fingerprint: "second", apiToken: "second-token" });
        tx.objectStore("settings").put({ key: "pushOwnerFingerprint", value: "second" });
        tx.objectStore("settings").put({ key: "pushSubscriptionId", value: "second-id" });
        tx.oncomplete = () => { db.close(); resolve(); };
        tx.onerror = () => reject(tx.error);
      };
    });
    const originalFetch = window.fetch.bind(window);
    window.fetch = async (input, init = {}) => {
      const url = String(input);
      if (url.endsWith("/api/v1/push/config")) return new Response(JSON.stringify({
        version: 1, enabled: true, multi_enrollment: true, vapid_public_key: "B".repeat(87),
      }), { status: 200 });
      if (url.endsWith("/api/v1/push/status")) {
        window.__pushStatusCalls.push(init.headers.authorization);
        if (window.__pushStatusFailure === "503") return new Response("{}", { status: 503 });
        if (window.__pushStatusFailure === "network") throw new TypeError("network unavailable");
        if (window.__pushStatusFailure === "malformed") return new Response("{}", { status: 200 });
        if (window.__pushStatusFailure === "all401") return new Response("{}", { status: 401 });
        if (window.__pushRejectBearer === init.headers.authorization) return new Response("{}", { status: 401 });
        return new Response(JSON.stringify({ version: 1, enabled: true, registered: false, count: 0 }), { status: 200 });
      }
      if (url.endsWith("/api/v1/push/subscriptions")) {
        window.__pushCalls.push({ url, headers: init.headers, body: JSON.parse(init.body) });
        if (window.__pushHold) await window.__pushHold;
        if (window.__pushRejectBearer === init.headers.authorization) return new Response("{}", { status: 401 });
        if (window.__pushUnavailableBearer === init.headers.authorization) return new Response("{}", { status: 503 });
        return new Response(JSON.stringify({ version: 1, subscription_id: `${init.headers.authorization.slice(7)}-membership` }), { status: 200 });
      }
      return originalFetch(input, init);
    };
  }, { fresh });
  await navigate(page, `${origin}/setup`);
  await page.evaluate(async () => { await window.__pushDatabaseReady; Notification.permission = "granted"; });
}

for (const replace of [false, true]) {
  test(`fresh bootstrap skips a previously revoked enrollment on ${replace ? "replacement" : "first enable"}`, async ({ page }) => {
    await mockedPushBrowser(page, { fresh: !replace });
    const result = await page.evaluate(async replace => {
      window.__pushRejectBearer = "Bearer first-token";
      const status = await OshiokiPush.enablePushForDevice(null, { replace });
      return { registered: status.registered, text: OshiokiPush.pushStatusText(status),
        statuses: window.__pushStatusCalls, calls: window.__pushCalls, binding: await OshiokiPush.getSetting("pushBinding") };
    }, replace);
    expect(result.registered).toBe(1);
    expect(result.text).toContain("1 of 2");
    expect(result.text).toContain("unavailable or revoked");
    expect(result.statuses).toEqual(["Bearer first-token", "Bearer second-token"]);
    expect(result.calls.map(call => call.headers.authorization)).toEqual(["Bearer second-token", "Bearer first-token"]);
    expect(result.binding.bootstrap_fingerprint).toBe("second");
    expect(result.binding.state).toBe("bound");
    expect(result.binding.registrations).toEqual({ second: "second-token-membership" });
    const retried = await page.evaluate(async () => {
      await OshiokiPush.syncOwnedPushSubscription();
      return { binding: await OshiokiPush.getSetting("pushBinding"), statuses: window.__pushStatusCalls,
        unsubscribed: window.__pushUnsubscribed, subscribed: window.__pushSubscribed, prompts: window.__pushPermissionRequests };
    });
    expect(retried.binding).toEqual(result.binding);
    expect(retried.statuses).toEqual(result.statuses);
    expect(retried.unsubscribed).toBe(Number(replace));
    expect(retried.subscribed).toBe(1);
    expect(retried.prompts).toBe(0);
  });
}

test("a failed fresh bootstrap retries only its persisted active enrollment and capability", async ({ page }) => {
  await mockedPushBrowser(page, { fresh: true });
  const pending = await page.evaluate(async () => {
    window.__pushRejectBearer = "Bearer first-token";
    window.__pushUnavailableBearer = "Bearer second-token";
    let message;
    try { await OshiokiPush.enablePushForDevice(null); } catch (error) { message = error.message; }
    return { message, binding: await OshiokiPush.getSetting("pushBinding"), calls: window.__pushCalls };
  });
  expect(pending.message).toContain("registration failed (503)");
  expect(pending.binding.state).toBe("pending");
  expect(pending.binding.bootstrap_fingerprint).toBe("second");
  expect(pending.calls.map(call => call.headers.authorization)).toEqual(["Bearer second-token"]);
  const retried = await page.evaluate(async () => {
    window.__pushUnavailableBearer = null;
    const result = await OshiokiPush.syncOwnedPushSubscription();
    return { registered: result.registered, failures: result.failures.length, binding: await OshiokiPush.getSetting("pushBinding"),
      calls: window.__pushCalls, statuses: window.__pushStatusCalls, unsubscribed: window.__pushUnsubscribed,
      subscribed: window.__pushSubscribed, prompts: window.__pushPermissionRequests };
  });
  expect(retried.registered).toBe(1);
  expect(retried.failures).toBe(1);
  expect(retried.binding.state).toBe("bound");
  expect(retried.binding.bootstrap_fingerprint).toBe("second");
  expect(retried.binding.installation_token).toBe(pending.binding.installation_token);
  expect(retried.calls.map(call => call.headers.authorization)).toEqual(["Bearer second-token", "Bearer second-token", "Bearer first-token"]);
  expect(retried.statuses).toEqual(["Bearer first-token", "Bearer second-token"]);
  expect(new Set(retried.calls.map(call => call.body.installation_token)).size).toBe(1);
  expect(retried.unsubscribed).toBe(0);
  expect(retried.subscribed).toBe(1);
  expect(retried.prompts).toBe(0);
});

for (const replace of [false, true]) {
  for (const failure of ["503", "network", "malformed", "all401"]) {
    test(`${replace ? "replacement" : "first enable"} preserves subscription state after ${failure} preflight and retries`, async ({ page }) => {
      await mockedPushBrowser(page, { fresh: !replace });
      const failed = await page.evaluate(async ({ replace, failure }) => {
        if (replace) await OshiokiPush.syncOwnedPushSubscription();
        const previous = await OshiokiPush.getSetting("pushBinding");
        window.__pushCalls = [];
        window.__pushStatusCalls = [];
        window.__pushStatusFailure = failure;
        let message;
        try { await OshiokiPush.enablePushForDevice(null, { replace }); } catch (error) { message = error.message; }
        return { message, previous, binding: await OshiokiPush.getSetting("pushBinding"), calls: window.__pushCalls,
          statuses: window.__pushStatusCalls, endpoint: window.__pushSubscriptionEndpoint,
          subscribed: window.__pushSubscribed, unsubscribed: window.__pushUnsubscribed };
      }, { replace, failure });
      expect(failed.message).toContain({ "503": "enrollment check failed (503)", network: "network unavailable",
        malformed: "invalid push status response", all401: "No active saved enrollment" }[failure]);
      expect(failed.statuses).toEqual(failure === "all401" ? ["Bearer first-token", "Bearer second-token"] : ["Bearer first-token"]);
      expect(failed.binding).toEqual(failed.previous);
      expect(failed.endpoint).toBe(replace ? "https://push.example/browser" : undefined);
      expect(failed.calls).toEqual([]);
      expect(failed.subscribed).toBe(0);
      expect(failed.unsubscribed).toBe(0);
      if (replace) {
        const preserved = await page.evaluate(async () => {
          const result = await OshiokiPush.syncOwnedPushSubscription();
          return { registered: result.registered, binding: await OshiokiPush.getSetting("pushBinding"),
            calls: window.__pushCalls, statuses: window.__pushStatusCalls };
        });
        expect(preserved.registered).toBe(2);
        expect(preserved.binding).toEqual(failed.previous);
        expect(preserved.statuses).toEqual(failed.statuses);
        expect(preserved.calls).toHaveLength(2);
        for (const call of preserved.calls) {
          expect(call.body.endpoint).toBe(failed.previous.endpoint);
          expect(call.body.installation_token).toBe(failed.previous.installation_token);
        }
      }
      const retried = await page.evaluate(async replace => {
        window.__pushStatusFailure = null;
        window.__pushStatusCalls = [];
        const status = await OshiokiPush.enablePushForDevice(null, { replace });
        return { registered: status.registered, failures: status.failures.length, binding: await OshiokiPush.getSetting("pushBinding"),
          statuses: window.__pushStatusCalls, subscribed: window.__pushSubscribed,
          unsubscribed: window.__pushUnsubscribed, prompts: window.__pushPermissionRequests };
      }, replace);
      expect(retried.registered).toBe(2);
      expect(retried.failures).toBe(0);
      expect(retried.binding.state).toBe("bound");
      expect(retried.binding.endpoint).toBe("https://push.example/fresh");
      expect(retried.statuses).toEqual(["Bearer first-token"]);
      expect(retried.subscribed).toBe(1);
      expect(retried.unsubscribed).toBe(Number(replace));
      expect(retried.prompts).toBe(0);
    });
  }
}

test("shared browser claims its legacy owner first and preserves other memberships after revocation", async ({ page }) => {
  await mockedPushBrowser(page);
  const first = await page.evaluate(async () => {
    const result = await OshiokiPush.syncOwnedPushSubscription();
    return { result, calls: window.__pushCalls, binding: await OshiokiPush.getSetting("pushBinding"),
      legacyOwner: await OshiokiPush.getSetting("pushOwnerFingerprint") };
  });
  expect(first.result.registered).toBe(2);
  expect(first.calls.map(call => call.headers.authorization)).toEqual(["Bearer second-token", "Bearer first-token"]);
  expect(new Set(first.calls.map(call => call.body.endpoint)).size).toBe(1);
  expect(new Set(first.calls.map(call => call.body.installation_token)).size).toBe(1);
  expect(first.binding.state).toBe("bound");
  expect(first.legacyOwner).toBeUndefined();

  const revoked = await page.evaluate(async () => {
    window.__pushRejectBearer = "Bearer first-token";
    const result = await OshiokiPush.syncOwnedPushSubscription();
    return { registered: result.registered, failures: result.failures.length, binding: await OshiokiPush.getSetting("pushBinding"),
      unsubscribed: window.__pushUnsubscribed, subscribed: window.__pushSubscribed, prompts: window.__pushPermissionRequests };
  });
  expect(revoked.registered).toBe(1);
  expect(revoked.failures).toBe(1);
  expect(revoked.binding.registrations).toEqual({ second: "second-token-membership" });
  expect(revoked.binding.installation_token).toBe(first.binding.installation_token);
  expect(revoked.unsubscribed).toBe(0);
  expect(revoked.subscribed).toBe(0);
  expect(revoked.prompts).toBe(0);
});

test("real IndexedDB atomic bootstrap and conditional merges survive concurrent callers and stale responses", async ({ page }) => {
  await mockedPushBrowser(page);
  const result = await page.evaluate(async () => {
    const [one, two] = await Promise.all([
      OshiokiPush.createPushBinding("https://push.example/browser", "second"),
      OshiokiPush.createPushBinding("https://push.example/browser", "first"),
    ]);
    await Promise.all([OshiokiPush.syncOwnedPushSubscription(), OshiokiPush.syncOwnedPushSubscription()]);
    return { one, two, binding: await OshiokiPush.getSetting("pushBinding"), calls: window.__pushCalls };
  });
  expect(result.one.installation_token).toBe(result.two.installation_token);
  expect(result.one.bootstrap_fingerprint).toBe(result.two.bootstrap_fingerprint);
  expect(Object.keys(result.binding.registrations).sort()).toEqual(["first", "second"]);
  expect(new Set(result.calls.map(call => call.body.installation_token)).size).toBe(1);

  const stale = await page.evaluate(async () => {
    let release;
    window.__pushHold = new Promise(resolve => { release = resolve; });
    // Enter a registration POST, then simulate a newer generation written by
    // another context while its old response is in flight.
    let started;
    const entered = new Promise(resolve => { started = resolve; });
    const originalFetch = window.fetch;
    window.fetch = (...args) => {
      if (String(args[0]).endsWith("/push/subscriptions")) started();
      return originalFetch(...args);
    };
    const syncing = OshiokiPush.syncOwnedPushSubscription().then(() => null, error => error.message);
    await entered;
    const replacement = await OshiokiPush.createPushBinding("https://push.example/replacement", "second");
    window.__pushHold = null;
    release();
    const error = await syncing;
    return { replacement, error, saved: await OshiokiPush.getSetting("pushBinding") };
  });
  expect(stale.error).toContain("subscription changed");
  expect(stale.saved).toEqual(stale.replacement);
});

test("separate tabs serialize first claim and reuse the persisted installation capability", async ({ page, context }) => {
  await mockedPushBrowser(page);
  const other = await context.newPage();
  await mockedPushBrowser(other);
  const reconcile = tab => tab.evaluate(async () => {
    const result = await OshiokiPush.syncOwnedPushSubscription();
    return { registered: result.registered, binding: await OshiokiPush.getSetting("pushBinding"), calls: window.__pushCalls };
  });
  const [first, second] = await Promise.all([reconcile(page), reconcile(other)]);
  expect(first.registered).toBe(2);
  expect(second.registered).toBe(2);
  expect(first.binding.installation_token).toBe(second.binding.installation_token);
  expect(first.binding.bootstrap_fingerprint).toBe("second");
  expect(second.binding.bootstrap_fingerprint).toBe("second");
  const tokens = [...first.calls, ...second.calls].map(call => call.body.installation_token);
  expect(new Set(tokens).size).toBe(1);
  await other.close();
});
