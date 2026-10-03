import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end tests drive the REAL dashboard against the REAL backend (scripts/e2e_server.py: deterministic, JWT auth on, in-memory stores).
 * `npm run build` must have run first. Ports are separate from the dev defaults so a running dev stack does not interfere.
 */
const API = 8100;
const WEB = 3100;

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false, // one backend with shared state: tests create their own data but run in order
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 45_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : [["list"]],
  use: { baseURL: `http://127.0.0.1:${WEB}`, trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: `python ../logunify-backend/scripts/e2e_server.py --port ${API}`,
      url: `http://127.0.0.1:${API}/health`,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
    {
      command: `npx next start -H 127.0.0.1 -p ${WEB}`,
      url: `http://127.0.0.1:${WEB}/login`,
      env: { LOGUNIFY_API_URL: `http://127.0.0.1:${API}`, PORT: String(WEB) },
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
  ],
});
