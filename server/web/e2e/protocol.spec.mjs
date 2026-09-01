import { expect, test } from "@playwright/test";
import { connect } from "@nats-io/transport-node";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { join } from "node:path";
import { URL } from "node:url";

const hookBinary = process.env.SUDO_APPROVE_HOOK ?? "/work/target/release/sudo-approve";
const hookConfigDir = process.env.SUDO_APPROVE_TEST_CONFIG_DIR;
const origin = process.env.SUDO_APPROVE_ORIGIN ?? "https://sudo.test";
const natsOptions = {
  servers: process.env.NATS_URL ?? "nats://nats:4222",
  user: process.env.NATS_USER ?? "sudo-approve",
  pass: process.env.NATS_PASS ?? "test-only",
};
let proxy;
const activeHooks = new Set();
const enrolledFingerprints = new Set();

test.beforeAll(async () => {
  const target = new URL(process.env.SUDO_APPROVE_SERVER_HTTP ?? "http://server:8443");
  proxy = https.createServer({
    key: readFileSync(process.env.SUDO_APPROVE_TLS_KEY),
    cert: readFileSync(process.env.SUDO_APPROVE_TLS_CERT),
  }, (request, response) => {
    const upstream = http.request({
      hostname: target.hostname,
      port: target.port,
      path: request.url,
      method: request.method,
      headers: { ...request.headers, host: target.host },
    }, (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    });
    upstream.on("error", () => {
      response.writeHead(502, { "content-type": "text/plain" });
      response.end("upstream unavailable");
    });
    request.pipe(upstream);
  });
  await new Promise((resolve, reject) => {
    proxy.once("error", reject);
    proxy.listen(Number(process.env.SUDO_APPROVE_HTTPS_PORT ?? "443"), "127.0.0.1", resolve);
  });
});

test.afterAll(async () => {
  if (proxy) await new Promise((resolve) => proxy.close(resolve));
});

test.afterEach(async () => {
  const running = [...activeHooks];
  for (const processHandle of running) {
    if (processHandle.child.exitCode === null) processHandle.child.kill("SIGTERM");
  }
  await Promise.allSettled(running.map((processHandle) => processHandle.exited));

  const failures = [];
  const fingerprints = [...enrolledFingerprints];
  for (const fingerprint of fingerprints) {
    const revocation = hook(["revoke", fingerprint]);
    const result = await revocation.exited;
    if (result.code === 0) enrolledFingerprints.delete(fingerprint);
    else failures.push(`${fingerprint}: ${result.stderr}`);
  }
  expect(failures).toEqual([]);
});

function hook(args) {
  const child = spawn(hookBinary, args, {
    env: hookConfigDir
      ? { ...process.env, SUDO_APPROVE_CONFIG_DIR: hookConfigDir }
      : process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const exited = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  const processHandle = {
    child,
    exited,
    output: () => `${stdout}\n${stderr}`,
  };
  activeHooks.add(processHandle);
  exited.then(
    () => activeHooks.delete(processHandle),
    () => activeHooks.delete(processHandle),
  );
  return processHandle;
}

async function waitForMatch(processHandle, pattern, timeoutMs = 15_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const match = processHandle.output().match(pattern);
    if (match) return match;
    if (processHandle.child.exitCode !== null) {
      throw new Error(`hook exited before output matched ${pattern}: ${processHandle.output()}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  processHandle.child.kill("SIGTERM");
  throw new Error(`timed out waiting for hook output ${pattern}: ${processHandle.output()}`);
}

async function virtualProfile(browser, consoleErrors) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  page.on("pageerror", (error) => consoleErrors.push(error.message));
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { context, page, cdp, authenticatorId };
}

async function enrolledDevice(page) {
  return page.evaluate(async () => {
    const database = await new Promise((resolve, reject) => {
      const request = indexedDB.open("management-plane-sudo-approve", 1);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const devices = await new Promise((resolve, reject) => {
      const request = database.transaction("devices").objectStore("devices").getAll();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    database.close();
    return devices.at(0);
  });
}

async function enrollmentUrl(processHandle) {
  const match = await waitForMatch(processHandle, /https:\/\/sudo\.test(?::[0-9]+)?\/enroll\/[0-9a-f-]+#[A-Za-z0-9_-]+/);
  return match[0];
}

async function navigate(page, url) {
  try {
    await page.goto(url);
  } catch (error) {
    if (!error.message.includes("ERR_NETWORK_CHANGED")) throw error;
    await new Promise((resolve) => setTimeout(resolve, 50));
    await page.goto(url);
  }
}

async function completeEnrollment(profile, processHandle, url) {
  await navigate(profile.page, url);
  await expect(profile.page).not.toHaveURL(/#/);
  await profile.page.getByRole("button", { name: "Continue" }).click();
  await expect(profile.page.locator("#status")).toContainText("Enrolled as");
  const result = await processHandle.exited;
  const device = await enrolledDevice(profile.page);
  if (device?.fingerprint) enrolledFingerprints.add(device.fingerprint);
  expect(result.code, result.stderr).toBe(0);
  expect(device).toBeTruthy();
  return device;
}

async function enroll(profile) {
  const processHandle = hook(["enroll"]);
  return completeEnrollment(profile, processHandle, await enrollmentUrl(processHandle));
}

async function enrollAfterResume(profile) {
  const interrupted = hook(["enroll"]);
  const firstUrl = await enrollmentUrl(interrupted);
  const parsedUrl = new URL(firstUrl);
  const enrollmentId = parsedUrl.pathname.split("/").at(-1);
  expect(hookConfigDir).toBeTruthy();
  const statePath = join(hookConfigDir, "enrollments", `${enrollmentId}.json`);
  interrupted.child.kill("SIGTERM");
  const interruptedResult = await interrupted.exited;
  expect(interruptedResult.signal).toBe("SIGTERM");
  expect(existsSync(statePath)).toBe(true);
  const persisted = JSON.parse(readFileSync(statePath, "utf8"));
  expect(persisted.secret).toBe(parsedUrl.hash.slice(1));
  expect(statSync(statePath).mode & 0o777).toBe(0o600);

  const resumed = hook(["enroll", "--resume", enrollmentId]);
  const resumedUrl = await enrollmentUrl(resumed);
  expect(resumedUrl).toBe(firstUrl);
  const device = await completeEnrollment(profile, resumed, resumedUrl);
  expect(existsSync(statePath)).toBe(false);
  return device;
}

async function pendingRequest() {
  const connection = await connect(natsOptions);
  let resolveMessage;
  let rejectMessage;
  const message = new Promise((resolve, reject) => {
    resolveMessage = resolve;
    rejectMessage = reject;
  });
  const subscription = connection.subscribe("sudo.request.>", {
    max: 1,
    callback: (error, value) => {
      if (error) rejectMessage(error);
      else resolveMessage(JSON.parse(new TextDecoder().decode(value.data)));
    },
  });
  await connection.flush();
  const processHandle = hook(["test"]);
  const timeout = new Promise((_, reject) => {
    setTimeout(() => reject(new Error("timed out waiting for sudo request")), 15_000);
  });
  const envelope = await Promise.race([message, timeout]);
  subscription.unsubscribe();
  await connection.drain();
  return { envelope, processHandle };
}

async function apiRequest(requestId, token) {
  return new Promise((resolve, reject) => {
    const request = https.request({
      hostname: "127.0.0.1",
      port: Number(process.env.SUDO_APPROVE_HTTPS_PORT ?? "443"),
      path: `/api/v1/requests/${requestId}`,
      method: "GET",
      servername: "sudo.test",
      rejectUnauthorized: false,
      headers: {
        host: new URL(origin).host,
        authorization: `Bearer ${token}`,
      },
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.once("end", () => {
        const payload = Buffer.concat(chunks).toString("utf8");
        let body = null;
        if (payload) {
          try { body = JSON.parse(payload); } catch { body = payload; }
        }
        resolve({
          status: response.statusCode,
          body,
        });
      });
    });
    request.once("error", reject);
    request.end();
  });
}

async function requestStatus(requestId, token) {
  return (await apiRequest(requestId, token)).status;
}

async function waitForRouted(page, requestId, token) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const status = await page.evaluate(async ({ id, apiToken }) => {
      const response = await fetch(`/api/v1/requests/${id}`, {
        headers: { authorization: `Bearer ${apiToken}` },
      });
      return response.status;
    }, { id: requestId, apiToken: token });
    if (status === 200) return;
    expect(status).toBe(404);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`request ${requestId} was not routed`);
}

async function requestWith(profile, device, action) {
  const { envelope, processHandle } = await pendingRequest();
  await navigate(profile.page, `${origin}/healthz`);
  await waitForRouted(profile.page, envelope.request_id, device.apiToken);
  await navigate(profile.page, `${origin}/r/${envelope.request_id}`);
  await expect(profile.page.locator("#request")).toBeVisible();
  await expect(profile.page.locator("#actions")).toBeVisible();
  await expect(profile.page.locator("#command")).toHaveText("/usr/bin/true");
  await expect(profile.page.locator("#argv")).toHaveText("/usr/bin/true");

  const owned = await profile.page.evaluate(async ({ requestId, token }) => {
    const response = await fetch(`/api/v1/requests/${requestId}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    return { status: response.status, body: response.ok ? await response.json() : null };
  }, { requestId: envelope.request_id, token: device.apiToken });
  expect(owned.status).toBe(200);
  expect(owned.body.sealed.device_fingerprint).toBe(device.fingerprint);

  const wrongTokenStatus = await requestStatus(envelope.request_id, "x".repeat(32));
  expect(wrongTokenStatus).toBe(401);

  await profile.page.getByRole("button", { name: action === "approve" ? "Approve" : "Deny" }).click();
  await expect(profile.page.locator("#status")).toContainText(action === "approve" ? "Approval sent" : "Denied");
  const result = await processHandle.exited;
  if (action === "approve") {
    expect(result.code, result.stderr).toBe(0);
  } else {
    expect(result.code).not.toBe(0);
    expect(result.stderr).toContain("request explicitly denied");
  }
}

test("two browser profiles enroll independently and own their approvals", async ({ browser }) => {
  const consoleErrors = [];
  const first = await virtualProfile(browser, consoleErrors);
  const second = await virtualProfile(browser, consoleErrors);
  const firstDevice = await enroll(first);
  const secondDevice = await enroll(second);

  expect(firstDevice.fingerprint).not.toBe(secondDevice.fingerprint);
  expect(firstDevice.credentialId).not.toBe(secondDevice.credentialId);
  expect(firstDevice.boxSecret).not.toBe(secondDevice.boxSecret);
  expect(firstDevice.apiToken).not.toBe(secondDevice.apiToken);

  await requestWith(first, firstDevice, "approve");
  await first.page.goto("about:blank");
  await requestWith(first, firstDevice, "approve");
  await requestWith(second, secondDevice, "deny");

  expect(consoleErrors).toEqual([]);
  await first.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: first.authenticatorId });
  await second.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: second.authenticatorId });
  await first.context.close();
  await second.context.close();
});

test("enrollment resumes with the same secret and rejects expired local state", async ({ browser }) => {
  const consoleErrors = [];
  const profile = await virtualProfile(browser, consoleErrors);
  const device = await enrollAfterResume(profile);
  expect(device).toBeTruthy();
  expect(consoleErrors).toEqual([]);

  expect(hookConfigDir).toBeTruthy();
  const enrollmentId = "00000000-0000-4000-8000-000000000001";
  const enrollmentDirectory = join(hookConfigDir, "enrollments");
  mkdirSync(enrollmentDirectory, { recursive: true });
  const expiredPath = join(enrollmentDirectory, `${enrollmentId}.json`);
  writeFileSync(expiredPath, JSON.stringify({
    version: 1,
    enrollment_id: enrollmentId,
    secret: "A".repeat(43),
    expires_at: 1,
  }), { mode: 0o600 });
  try {
    const expired = hook(["enroll", "--resume", enrollmentId]);
    const expiredResult = await expired.exited;
    expect(expiredResult.code).not.toBe(0);
    expect(expiredResult.stderr).toContain("enrollment expired");
    expect(existsSync(expiredPath)).toBe(false);

    const invalid = hook(["enroll", "--resume", "../../outside"]);
    const invalidResult = await invalid.exited;
    expect(invalidResult.code).not.toBe(0);
    expect(invalidResult.stderr).toContain("invalid enrollment id");
  } finally {
    rmSync(expiredPath, { force: true });
  }

  await profile.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: profile.authenticatorId });
  await profile.context.close();
});

test("ciphertext tampering fails before request rendering", async ({ browser }) => {
  const consoleErrors = [];
  const profile = await virtualProfile(browser, consoleErrors);
  const device = await enroll(profile);
  const { envelope, processHandle } = await pendingRequest();
  await navigate(profile.page, `${origin}/healthz`);
  await waitForRouted(profile.page, envelope.request_id, device.apiToken);
  const owned = await apiRequest(envelope.request_id, device.apiToken);
  expect(owned.status).toBe(200);
  const tampered = owned.body;
  const ciphertext = tampered.sealed.ciphertext;
  tampered.sealed.ciphertext = `${ciphertext[0] === "A" ? "B" : "A"}${ciphertext.slice(1)}`;

  await profile.page.route(`**/api/v1/requests/${envelope.request_id}`, async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", json: tampered });
  });
  await navigate(profile.page, `${origin}/r/${envelope.request_id}`);
  await expect(profile.page.locator("#status")).toHaveText("This request could not be verified.");
  await expect(profile.page.locator("#request")).toBeHidden();
  await expect(profile.page.locator("#actions")).toBeHidden();
  expect(consoleErrors).toHaveLength(1);
  expect(consoleErrors[0]).toMatch(/ciphertext cannot be decrypted using that key/);

  await profile.page.unroute(`**/api/v1/requests/${envelope.request_id}`);
  await profile.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: profile.authenticatorId });
  await profile.context.close();
});
