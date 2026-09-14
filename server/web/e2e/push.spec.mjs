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
  await expect(page.locator("#status")).toContainText("same Oshioki origin");
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
  await navigate(page, `${origin}/setup`);
  await page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => {
      const request = indexedDB.open("oshioki", 2);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    await new Promise((resolve, reject) => {
      const tx = db.transaction(["devices", "settings"], "readwrite");
      tx.objectStore("devices").put({ fingerprint: "first", apiToken: "first-token" });
      tx.objectStore("devices").put({ fingerprint: "second", apiToken: "second-token" });
      tx.objectStore("settings").put({ key: "pushOwnerFingerprint", value: "second" });
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
    db.close();
    const selected = await window.OshiokiPush.deviceByFingerprint("second");
    if (!selected || selected.apiToken !== "second-token") throw new Error("wrong push owner selected");
  });
});
