import { defineConfig } from "@playwright/test";
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";

function disposableCertificatePin() {
  const certificatePath = process.env.OSHIOKI_TLS_CERT;
  if (!certificatePath) return null;
  const certificate = new X509Certificate(readFileSync(certificatePath));
  const publicKey = certificate.publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(publicKey).digest("base64");
}

const launchArgs = ["--host-resolver-rules=MAP sudo.test 127.0.0.1"];
const certificatePin = disposableCertificatePin();
if (certificatePin) launchArgs.push(`--ignore-certificate-errors-spki-list=${certificatePin}`);

export default defineConfig({
  testDir: "./e2e",
  timeout: 180_000,
  expect: { timeout: 30_000 },
  workers: 1,
  fullyParallel: false,
  reporter: [["line"]],
  use: {
    browserName: "chromium",
    headless: true,
    ignoreHTTPSErrors: true,
    launchOptions: {
      args: launchArgs,
    },
    trace: "retain-on-failure",
  },
});
