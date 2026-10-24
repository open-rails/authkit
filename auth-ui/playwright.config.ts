import { defineConfig, devices } from "@playwright/test"

export default defineConfig({
  testDir: "critical",
  testMatch: "**/*.spec.ts",
  globalSetup: "./critical/setup.ts",
  workers: 1,
  retries: 0,
  timeout: 30_000,
  forbidOnly: !!process.env.CI,
  reporter: [
    ...(process.env.CI ? [["github"] as ["github"]] : []),
    ["list"],
    ["json", { outputFile: "test-results/critical.json" }],
  ],
  use: { baseURL: process.env.E2E_BASE_URL, trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
})
