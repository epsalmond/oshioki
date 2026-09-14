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

test("push ownership selects the recorded fingerprint in IndexedDB v2", async ({ page }) => {
  await page.addInitScript(() => {
    const subscription = {
      endpoint: "https://push.example/browser",
      expirationTime: null,
      toJSON: () => ({ keys: { p256dh: "p256dh", auth: "auth" } }),
    };
    const registration = { pushManager: { getSubscription: async () => subscription } };
    Object.defineProperty(navigator, "serviceWorker", { configurable: true, value: { register: async () => registration } });
    Object.defineProperty(window, "PushManager", { configurable: true, writable: true, value: function PushManager() {} });
    Object.defineProperty(window, "Notification", { configurable: true, writable: true, value: { permission: "granted" } });
    window.__pushCalls = [];
    const databaseReady = new Promise((resolve, reject) => {
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
    window.__pushDatabaseReady = databaseReady;
    const originalFetch = window.fetch.bind(window);
    window.fetch = async (input, init = {}) => {
      const url = String(input);
      if (url.endsWith("/api/v1/push/subscriptions")) {
        window.__pushCalls.push({ url, headers: init.headers, body: init.body });
        return new Response(JSON.stringify({ version: 1, subscription_id: "browser-id" }), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (url.endsWith("/api/v1/push/status")) {
        window.__pushCalls.push({ url, headers: init.headers });
        return new Response(JSON.stringify({ version: 1, enabled: true, registered: true, count: 1 }), { status: 200, headers: { "content-type": "application/json" } });
      }
      return originalFetch(input, init);
    };
  });
  await navigate(page, `${origin}/setup`);
  await page.evaluate(async () => {
    await window.__pushDatabaseReady;
    const support = window.OshiokiPush.pushSupport();
    if (!support.supported || Notification.permission !== "granted") throw new Error(`push test capability unavailable: ${JSON.stringify({ support, permission: Notification.permission })}`);
    const synced = await window.OshiokiPush.syncOwnedPushSubscription();
    if (!synced || synced.device.apiToken !== "second-token") throw new Error("wrong push owner selected");
    const selected = await window.OshiokiPush.deviceByFingerprint("second");
    if (!selected || selected.apiToken !== "second-token") throw new Error("wrong push owner selected");
    const calls = window.__pushCalls.filter(call => call.url.endsWith("/api/v1/push/subscriptions"));
    if (calls.length < 1 || calls.at(-1).headers.authorization !== "Bearer second-token") throw new Error("push registration used the wrong bearer");
  });
});
