import { expect, test } from "@playwright/test";
import { connect } from "@nats-io/transport-node";
import sodium from "libsodium-wrappers";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import https from "node:https";
import { join } from "node:path";
import { URL } from "node:url";
import { startTlsProxy } from "../../../scripts/e2e-tls-proxy.mjs";

const hookBinary = process.env.OSHIOKI_HOOK ?? "/work/target/release/oshioki";
const hookConfigDir = process.env.OSHIOKI_TEST_CONFIG_DIR;
const origin = process.env.OSHIOKI_ORIGIN ?? "https://sudo.test";
const natsOptions = {
  servers: process.env.NATS_URL ?? "nats://nats:4222",
  user: process.env.NATS_USER ?? "oshioki",
  pass: process.env.NATS_PASS ?? "test-only",
};
let proxy;
const activeHooks = new Set();
const activeConnections = new Set();
const enrolledFingerprints = new Set();

// The same proxy the rest of the E2E runs as a standalone process.
test.beforeAll(async () => {
  proxy = await startTlsProxy();
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

  const connections = [...activeConnections];
  activeConnections.clear();
  await Promise.allSettled(connections.map((connection) => connection.drain()));

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
      ? { ...process.env, OSHIOKI_CONFIG_DIR: hookConfigDir }
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
      const request = indexedDB.open("oshioki", 2);
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
  const subscription = connection.subscribe("oshioki.request.>", {
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
  activeConnections.delete(connection);
  return { envelope, processHandle };
}

async function apiRequest(requestId, token) {
  return new Promise((resolve, reject) => {
    const request = https.request({
      hostname: "127.0.0.1",
      port: Number(process.env.OSHIOKI_HTTPS_PORT ?? "443"),
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
  // `oshioki test` builds a request that targets root, and the page names the
  // target rather than leaving sudo's default implicit.
  await expect(profile.page.locator("#runas")).toHaveText("root (uid 0)");
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

async function oneMessage(connection, subject) {
  let resolveMessage;
  let rejectMessage;
  const message = new Promise((resolve, reject) => {
    resolveMessage = resolve;
    rejectMessage = reject;
  });
  const subscription = connection.subscribe(subject, {
    max: 1,
    callback: (error, value) => error ? rejectMessage(error) : resolveMessage(value.data),
  });
  return { subscription, message };
}

async function testNatsConnection() {
  const connection = await connect(natsOptions);
  activeConnections.add(connection);
  return connection;
}

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

function unb64url(value) {
  return Buffer.from(value, "base64url");
}

async function toolRequestEnvelope(requestId, device, publicDevice) {
  await sodium.ready;
  const issuedAt = Math.floor(Date.now() / 1000);
  const input = {
    command: "printf '<img src=x onerror=alert(1)>'",
    description: "Print exact text",
    large_value: Number("9007199254740993"),
  };
  const nativeEvent = {
    hook_event_name: "PermissionRequest",
    tool_name: "Bash",
    tool_input: input,
    cwd: "/tmp/oshioki-project",
    session_id: "session-tool-1",
    agent_id: "agent-subtask-1",
    agent_type: "worker",
    permission_mode: "default",
  };
  const largeNumberToken = '"large_value":9007199254740992';
  const nativeEventJson = JSON.stringify(nativeEvent).replace(
    largeNumberToken,
    '"large_value":9007199254740993',
  );
  const request = {
    type: "tool_approval_request",
    version: 3,
    request_id: requestId,
    nonce: b64url(sodium.randombytes_buf(16)),
    harness: "claude",
    event: "PermissionRequest",
    tool_name: "Bash",
    tool_input: input,
    cwd: nativeEvent.cwd,
    native_event_json: nativeEventJson,
    context: {
      session_id: nativeEvent.session_id,
      agent_id: nativeEvent.agent_id,
      agent_type: nativeEvent.agent_type,
      permission_mode: nativeEvent.permission_mode,
    },
    description: null,
    issued_at: issuedAt,
    expires_at: issuedAt + 90,
  };
  const requestJson = JSON.stringify(request).replace(
    largeNumberToken,
    '"large_value":9007199254740993',
  );
  if (!nativeEventJson.includes('"large_value":9007199254740993')
      || !requestJson.includes('"large_value":9007199254740993')) {
    throw new Error("large-number test fixture lost its exact JSON token");
  }
  const raw = Buffer.from(requestJson);
  const ephemeral = sodium.crypto_box_keypair();
  const shared = sodium.crypto_scalarmult(ephemeral.privateKey, unb64url(publicDevice.box_public_key));
  const nonce = sodium.randombytes_buf(12);
  const ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(raw, null, null, nonce, shared);
  return {
    request,
    requestJson,
    envelope: {
      type: "tool_approval",
      version: 3,
      request_id: requestId,
      issued_at: request.issued_at,
      expires_at: request.expires_at,
      sealed: [{
        device_fingerprint: device.fingerprint,
        ephemeral_pub: b64url(ephemeral.publicKey),
        nonce: b64url(nonce),
        ciphertext: b64url(ciphertext),
      }],
    },
  };
}

async function exerciseToolDecision(profile, device, action) {
  const publicDevice = await profile.page.evaluate(async fingerprint => {
    const response = await fetch(`/api/v1/devices/${fingerprint}`);
    return response.ok ? await response.json() : null;
  }, device.fingerprint);
  expect(publicDevice).toBeTruthy();
  const connection = await testNatsConnection();
  const requestId = `tool-${crypto.randomUUID()}`;
  const delivery = await oneMessage(connection, `oshioki.tool.delivery.${requestId}`);
  const acknowledgement = await oneMessage(connection, `oshioki.tool.ack.${requestId}`);
  const verdict = await oneMessage(connection, `oshioki.tool.verdict.${requestId}`);
  await connection.flush();
  const { request, requestJson, envelope } = await toolRequestEnvelope(requestId, device, publicDevice);
  connection.publish("oshioki.tool.request", Buffer.from(JSON.stringify(envelope)));
  await connection.flush();
  const delivered = JSON.parse(Buffer.from(await delivery.message).toString("utf8"));
  expect(delivered).toEqual({ type: "tool_approval_delivery", version: 3, request_id: requestId });

  await navigate(profile.page, `${origin}/t/${requestId}`);
  await expect(profile.page.locator("#tool-input")).toContainText("<img src=x onerror=alert(1)>");
  await expect(profile.page.locator("#tool-input")).toContainText("agent-subtask-1");
  await expect(profile.page.locator("#tool-input")).toContainText("PermissionRequest");
  expect(await profile.page.locator("#tool-input").textContent()).toBe(request.native_event_json);
  expect(request.native_event_json).toContain('"large_value":9007199254740993');
  expect(requestJson).toContain('"large_value":9007199254740993');
  expect(await profile.page.locator("img").count()).toBe(0);
  const acknowledged = JSON.parse(Buffer.from(await acknowledgement.message).toString("utf8"));
  expect(acknowledged).toEqual({ type: "tool_approval_ack", version: 3, request_id: requestId });

  await profile.page.getByRole("button", { name: action === "approve" ? "Approve once" : "Deny" }).click();
  await expect(profile.page.locator("#status")).toContainText(action === "approve" ? "Approved once" : "Denied");
  const decision = JSON.parse(Buffer.from(await verdict.message).toString("utf8"));
  expect(decision.type).toBe(action === "approve" ? "tool_approval_approve_webauthn" : "tool_approval_deny_webauthn");
  expect(decision.version).toBe(3);
  expect(decision.request_id).toBe(requestId);
  expect(decision.device_fingerprint).toBe(device.fingerprint);
  expect(Buffer.from(decision.signature, "base64url").length).toBeGreaterThanOrEqual(8);
  expect(Object.keys(decision).sort()).toEqual([
    "authenticator_data", "client_data_json", "credential_id", "device_fingerprint", "request_id", "signature", "type", "version",
  ]);
  expect(request.native_event_json).toContain("agent_type");
  await connection.drain();
  activeConnections.delete(connection);
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

test("server delivery receipt permits a delayed browser open and approval", async ({ browser }) => {
  const consoleErrors = [];
  const profile = await virtualProfile(browser, consoleErrors);
  const device = await enroll(profile);
  const requestStarted = Date.now();
  const { envelope, processHandle } = await pendingRequest();

  // Ingestion and the durable delivery outbox must produce a fast receipt,
  // even though the browser has not opened the per-request URL yet.
  await waitForMatch(processHandle, /Request delivered; waiting for approver\.\.\./, 5_000);
  expect(Date.now() - requestStarted).toBeLessThan(5_000);

  // Model the real notification path: the operator does not open the browser
  // until ten seconds after sudo started.
  await new Promise((resolve) => setTimeout(resolve, 10_000));
  await navigate(profile.page, `${origin}/healthz`);
  await waitForRouted(profile.page, envelope.request_id, device.apiToken);
  await navigate(profile.page, `${origin}/r/${envelope.request_id}`);
  await expect(profile.page.locator("#request")).toBeVisible();
  await expect(profile.page.locator("#actions")).toBeVisible();
  await waitForMatch(processHandle, /Waiting for approval\.\.\./, 5_000);

  // Keep the approval tap at roughly T+20s, after the page has acknowledged
  // that it opened and checked the sealed request.
  const remaining = 20_000 - (Date.now() - requestStarted);
  if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
  await profile.page.getByRole("button", { name: "Approve" }).click();
  await expect(profile.page.locator("#status")).toContainText("Approval sent");
  const result = await processHandle.exited;
  expect(result.code, result.stderr).toBe(0);
  expect(Date.now() - requestStarted).toBeGreaterThanOrEqual(19_000);
  expect(consoleErrors).toEqual([]);

  await profile.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: profile.authenticatorId });
  await profile.context.close();
});

test("tool approval browser signs approve once and deny as distinct terminal decisions", async ({ browser }) => {
  const consoleErrors = [];
  const profile = await virtualProfile(browser, consoleErrors);
  const device = await enroll(profile);
  await navigate(profile.page, `${origin}/healthz`);
  await exerciseToolDecision(profile, device, "approve");
  await navigate(profile.page, `${origin}/healthz`);
  await exerciseToolDecision(profile, device, "deny");
  expect(consoleErrors).toEqual([]);
  await profile.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: profile.authenticatorId });
  await profile.context.close();
});

test("cancelling the tool passkey sends no decision", async ({ browser }) => {
  const consoleErrors = [];
  const profile = await virtualProfile(browser, consoleErrors);
  const device = await enroll(profile);
  await navigate(profile.page, `${origin}/healthz`);
  const publicDevice = await profile.page.evaluate(async fingerprint => {
    const response = await fetch(`/api/v1/devices/${fingerprint}`);
    return response.json();
  }, device.fingerprint);
  const connection = await testNatsConnection();
  const requestId = `tool-cancel-${crypto.randomUUID()}`;
  const delivery = await oneMessage(connection, `oshioki.tool.delivery.${requestId}`);
  const acknowledgement = await oneMessage(connection, `oshioki.tool.ack.${requestId}`);
  const verdict = await oneMessage(connection, `oshioki.tool.verdict.${requestId}`);
  await connection.flush();
  const { envelope } = await toolRequestEnvelope(requestId, device, publicDevice);
  connection.publish("oshioki.tool.request", Buffer.from(JSON.stringify(envelope)));
  await connection.flush();
  await delivery.message;
  await navigate(profile.page, `${origin}/t/${requestId}`);
  await acknowledgement.message;
  await profile.page.evaluate(() => {
    navigator.credentials.get = () => Promise.reject(new DOMException("cancelled", "NotAllowedError"));
  });
  await profile.page.getByRole("button", { name: "Deny" }).click();
  await expect(profile.page.locator("#status")).toContainText("No decision was sent");
  await expect(profile.page.locator("#actions")).toBeVisible();
  await expect(Promise.race([verdict.message.then(() => "received"), new Promise(resolve => setTimeout(() => resolve("none"), 300))])).resolves.toBe("none");
  expect(consoleErrors).toEqual([]);
  await connection.drain();
  await profile.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: profile.authenticatorId });
  await profile.context.close();
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
