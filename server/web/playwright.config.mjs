import { defineConfig } from "@playwright/test";

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
      args: ["--host-resolver-rules=MAP sudo.test 127.0.0.1"],
    },
    trace: "retain-on-failure",
  },
});
