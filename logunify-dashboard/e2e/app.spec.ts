import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { API, auth, ingest, mint, raiseAlert, signedIn } from "./support";

test.describe("authentication", () => {
  test("anonymous visitors are sent to /login and a bad token is rejected", async ({ page }) => {
    await page.goto("/alerts");
    await expect(page).toHaveURL(/\/login/, { timeout: 20_000 });
    await page.getByLabel("Access token").fill("not-a-jwt");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.locator("#login-error")).toBeVisible();
    await expect(page).toHaveURL(/\/login/);
  });

  test("a valid token signs in and sign-out clears the session", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Access token").fill(mint("analyst"));
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
    await page.getByRole("button", { name: /sign out/i }).click();
    await expect(page).toHaveURL(/\/login/);
    expect(await page.evaluate(() => sessionStorage.getItem("logunify_token"))).toBeNull();
  });

  test("a token the server rejects (revoked) sends the user back to login", async ({ page, request }) => {
    const jti = `rev-${Date.now()}`;
    await signedIn(page, "analyst", { jti });
    await page.goto("/");
    await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
    const r = await request.post(`${API}/api/v1/auth/revoke`, { headers: auth("admin"), data: { jti, reason: "e2e" } });
    expect(r.ok()).toBeTruthy();
    await page.goto("/alerts");
    await expect(page).toHaveURL(/\/login/, { timeout: 15_000 });
  });
});

test.describe("role-aware UI (the server is the real gate)", () => {
  test("viewer does not see analyst/admin areas and the API refuses them", async ({ page, request }) => {
    await signedIn(page, "viewer");
    await page.goto("/");
    const nav = page.getByRole("navigation", { name: "Main" });
    await expect(nav).toBeVisible();
    await expect(nav.getByRole("link", { name: /governance/i })).toHaveCount(0);
    const r = await request.get(`${API}/api/v1/audit`, { headers: auth("viewer") });
    expect(r.status()).toBe(403);
  });

  test("admin sees governance", async ({ page }) => {
    await signedIn(page, "admin");
    await page.goto("/governance");
    await expect(page.getByRole("heading", { name: "Governance", level: 1 })).toBeVisible();
    await expect(page.getByRole("button", { name: "Verify hash chain" })).toBeVisible();
  });
});

test.describe("CERT-In alert workflow", () => {
  test("raise, acknowledge, record report, close", async ({ page, request }) => {
    const id = await raiseAlert(request);
    await signedIn(page, "analyst");
    await page.goto("/alerts");
    await expect(page.getByRole("heading", { name: /CERT-In 6-hour workflow/ })).toBeVisible();
    await page.getByRole("button", { name: id.slice(0, 8), exact: false }).first().click().catch(async () => {
      await page.locator("section[aria-label='Alert list'] button").first().click();
    });
    const detail = page.getByRole("region", { name: "Alert detail" });
    await expect(detail).toBeVisible();
    await detail.getByRole("button", { name: "Acknowledge" }).click();
    await detail.getByRole("textbox").first().fill("Triaged by e2e");
    await detail.getByRole("button", { name: /^Acknowledge|Confirm|Save/ }).last().click();
    await expect(detail.getByRole("status").first()).toBeVisible();
    await detail.getByRole("button", { name: /Record: reported/ }).click();
    await detail.getByRole("textbox").first().fill("INC-E2E-1");
    await detail.getByRole("button", { name: /^(Record|Save|Confirm)/ }).last().click();
    await expect(detail.getByRole("status").first()).toBeVisible();
    const alert = await (await request.get(`${API}/api/v1/alerts/${id}`, { headers: auth("analyst") })).json();
    expect(alert.ack).not.toBeNull();
    expect(alert.reported?.reference).toBe("INC-E2E-1");
  });
});

test.describe("analyst workflow: ownership, notes, search", () => {
  test("take an alert, add a case note, see it under Mine", async ({ page, request }) => {
    const id = await raiseAlert(request);
    await signedIn(page, "analyst", { sub: "ravi" });
    await page.goto(`/alerts?id=${encodeURIComponent(id)}`);
    const detail = page.getByRole("region", { name: "Alert detail" });
    await expect(detail.getByText("Nobody owns this alert yet.")).toBeVisible();
    await detail.getByRole("button", { name: "Take it" }).click();
    await expect(detail.getByText("Assigned to you.")).toBeVisible();
    await expect(detail.getByRole("region", { name: "Owner" })).toContainText("Assigned to ravi");
    await detail.getByLabel("Add a note").fill("Checked auth.log, root login from an unknown address");
    await detail.getByRole("button", { name: "Add note" }).click();
    await expect(detail.getByText("Checked auth.log, root login from an unknown address")).toBeVisible();
    await page.getByRole("button", { name: "Mine" }).click();
    await expect(page.locator("section[aria-label='Alert list']").getByRole("button", { name: id })).toBeVisible();
    await page.getByRole("button", { name: "Unassigned" }).click();
    await expect(page.locator("section[aria-label='Alert list']").getByRole("button", { name: id })).toHaveCount(0);
    const notes = await (await request.get(`${API}/api/v1/alerts/${id}/notes`, { headers: auth("analyst") })).json();
    expect(notes.items.map((n: { by: string }) => n.by)).toEqual(["ravi"]);
  });

  test("search a time range, save the search, run it again, delete it", async ({ page, request }) => {
    const marker = `e2emarker${Date.now()}`;
    await ingest(request, `Oct  3 10:00:00 host9 sshd[7]: Failed password for ${marker} from 198.51.100.9 port 22 ssh2`);
    await signedIn(page, "analyst", { sub: "meena" });
    await page.goto("/search");
    await page.getByLabel("Query").fill(marker);
    await page.getByLabel("Time range").selectOption("-1h");
    await page.getByRole("button", { name: "Search", exact: true }).click();
    const results = page.getByRole("region", { name: "Results" });
    await expect(results.getByText(/1 match/)).toBeVisible();
    await expect(results.getByTestId("coverage")).toContainText("Older history is not searchable here");
    await page.getByLabel("Save as").fill(`find ${marker}`);
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "Saved" })).toBeVisible();
    await page.getByLabel("Query").fill("");
    await page.getByRole("button", { name: `Run find ${marker}` }).click();
    await expect(results.getByText(/1 match/)).toBeVisible();
    await expect(page.getByLabel("Query")).toHaveValue(marker);
    await page.getByRole("button", { name: `Delete find ${marker}` }).click();
    await expect(page.getByRole("button", { name: `Run find ${marker}` })).toHaveCount(0);
    await page.getByLabel("Query").fill('"unterminated');
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect(page.locator("p[role=alert]")).toContainText("unbalanced quote");
  });

  test("viewers cannot reach search and the API refuses them", async ({ page, request }) => {
    expect((await request.get(`${API}/api/v1/logs/search`, { headers: auth("viewer") })).status()).toBe(403);
    expect((await request.get(`${API}/api/v1/searches`, { headers: auth("viewer") })).status()).toBe(403);
    await signedIn(page, "viewer");
    await page.goto("/search");
    await expect(page.getByLabel("Query")).toHaveCount(0);
  });
});

test.describe("alert calibration", () => {
  test("replay shows funnel, sweep and preview; feedback and suppression rules work", async ({ page, request }) => {
    const id = await raiseAlert(request);
    const close = await request.post(`${API}/api/v1/alerts/${id}/close`, { headers: auth("analyst"), data: { by: "e2e", resolution: "false_positive", note: "e2e: known nightly job clears the log" } });
    expect(close.ok()).toBeTruthy();
    await signedIn(page, "admin", { sub: "boss" });
    await page.goto("/calibration");
    await expect(page.getByRole("heading", { name: "Alert calibration", level: 1 })).toBeVisible();
    await expect(page.getByTestId("confidence")).toContainText(/confidence/i);
    await expect(page.getByRole("heading", { name: "Why alerts do or do not fire" })).toBeVisible();
    await expect(page.getByRole("table", { name: /at each threshold/ })).toBeVisible();
    await expect(page.getByTestId("recommendation")).not.toBeEmpty();
    await expect(page.getByRole("img", { name: /Histogram of anomaly scores/ })).toBeVisible();
    // a candidate threshold is previewed without changing configuration
    await page.getByLabel(/Candidate threshold/).fill("0.5");
    await page.getByRole("button", { name: "Run replay" }).click();
    await expect(page.getByRole("img", { name: /Histogram/ })).toContainText("candidate");
    await expect(page.getByRole("heading", { name: /Analyst feedback/ })).toBeVisible();
    await expect(page.getByText("False-positive rate")).toBeVisible();
    // an admin creates, then revokes, a suppression rule
    const form = page.getByRole("form", { name: "New suppression rule" });
    await form.getByLabel(/Technique/).fill("T1070");
    await form.getByLabel(/Asset pattern/).fill(`e2e-${Date.now()}-*`);
    await form.getByLabel(/Reason/).fill("e2e: nightly backup rotates the audit log");
    await form.getByRole("button", { name: "Create rule" }).click();
    await expect(page.getByRole("status").filter({ hasText: /^Created SUP-/ })).toBeVisible();
    await page.getByRole("button", { name: "Revoke" }).first().click();
    await expect(page.getByRole("status").filter({ hasText: /^Revoked SUP-/ })).toBeVisible();
    // blanket rules are refused by the server
    const blanket = await request.post(`${API}/api/v1/suppressions`, { headers: auth("admin"), data: { technique: "T1070", asset: "*", reason: "switch everything off please", days: 30 } });
    expect(blanket.status()).toBe(422);
  });

  test("analysts can read calibration but not create suppression rules; viewers are refused", async ({ page, request }) => {
    const rule = { technique: "T1070", asset: "x-*", reason: "analyst should not be able to do this", days: 7 };
    expect((await request.post(`${API}/api/v1/suppressions`, { headers: auth("analyst"), data: rule })).status()).toBe(403);
    expect((await request.get(`${API}/api/v1/alerts-calibration`, { headers: auth("viewer") })).status()).toBe(403);
    await signedIn(page, "analyst");
    await page.goto("/calibration");
    await expect(page.getByTestId("confidence")).toBeVisible();
    await expect(page.getByRole("form", { name: "New suppression rule" })).toHaveCount(0);
    await expect(page.getByText("Creating or revoking rules needs the admin role.")).toBeVisible();
  });
});

test.describe("trace and operations", () => {
  test("a record is traced to the bytes received", async ({ page, request }) => {
    const doc = await ingest(request, "Oct  3 10:00:00 host1 sshd[42]: Accepted password for alice from 198.51.100.7 port 4022 ssh2");
    await signedIn(page, "analyst");
    await page.goto(`/trace?id=${encodeURIComponent(doc.event.id)}`);
    await expect(page.locator("#verdict, [aria-labelledby=verdict]").first()).toBeVisible();
    await expect(page.getByLabel("passed").first()).toBeVisible();
  });

  test("operations page shows system and DLQ", async ({ page }) => {
    await signedIn(page, "admin");
    await page.goto("/operations");
    await expect(page.getByRole("heading", { name: "Operations", level: 1 })).toBeVisible();
    await expect(page.getByRole("region").first()).toBeVisible();
  });
});

test.describe("governance", () => {
  test("audit hash chain verifies", async ({ page }) => {
    await signedIn(page, "admin");
    await page.goto("/governance");
    await page.getByRole("button", { name: "Verify hash chain" }).click();
    await expect(page.getByRole("status").filter({ hasText: /valid|intact|verified|ok/i }).first()).toBeVisible();
  });
});

test.describe("accessibility (axe, WCAG 2 A/AA)", () => {
  const pages: [string, "viewer" | "analyst" | "admin" | null][] = [
    ["/login", null], ["/", "analyst"], ["/alerts", "analyst"], ["/search", "analyst"], ["/calibration", "analyst"], ["/trace", "analyst"], ["/operations", "admin"], ["/governance", "admin"],
  ];
  for (const [path, role] of pages) {
    test(`no violations on ${path}`, async ({ page }) => {
      if (role) await signedIn(page, role);
      await page.goto(path);
      await page.waitForLoadState("domcontentloaded");
      if (role) await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
      await page.waitForTimeout(800);
      const res = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect(res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`)).toEqual([]);
    });
  }
});
