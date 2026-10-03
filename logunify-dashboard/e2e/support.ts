import { createHmac, randomUUID } from "node:crypto";
import { expect, type APIRequestContext, type Page } from "@playwright/test";

export const API = "http://127.0.0.1:8100";
const SECRET = process.env.E2E_JWT_SECRET ?? "e2e-secret-e2e-secret-e2e-secret-0123456789";

const b64 = (o: unknown) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");

/** A signed HS256 token for the e2e backend (the same shared secret the server was started with). */
export function mint(role: "viewer" | "analyst" | "admin", opts: { sub?: string; ttl?: number; jti?: string } = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const head = b64({ alg: "HS256", typ: "JWT" });
  const body = b64({ sub: opts.sub ?? `${role}-e2e`, iat: now, exp: now + (opts.ttl ?? 3600), jti: opts.jti ?? randomUUID(), roles: [role] });
  const sig = createHmac("sha256", SECRET).update(`${head}.${body}`).digest("base64url");
  return `${head}.${body}.${sig}`;
}

/** Start a page already signed in (token placed in sessionStorage before any script runs). */
export async function signedIn(page: Page, role: "viewer" | "analyst" | "admin", opts: Parameters<typeof mint>[1] = {}) {
  const t = mint(role, opts);
  await page.addInitScript((tok) => sessionStorage.setItem("logunify_token", tok), t);
  return t;
}

export const auth = (role: "viewer" | "analyst" | "admin") => ({ Authorization: `Bearer ${mint(role)}` });

let seq = 0;
/** Ingest a log through the API and return the normalized document once the pipeline produced it. */
export async function ingest(request: APIRequestContext, line: string) {
  const r = await request.post(`${API}/api/v1/ingest`, { headers: auth("admin"), data: { logs: [line] } });
  expect(r.status()).toBe(202);
  const needle = line.slice(0, 40);
  for (let i = 0; i < 60; i++) {
    const recent = await (await request.get(`${API}/api/v1/logs/recent?limit=200`, { headers: auth("admin") })).json();
    const hit = recent.items.find((d: { event?: { original?: string } }) => (d.event?.original ?? "").includes(needle.slice(0, 20)) || (d.event?.original ?? "") === line);
    if (hit) return hit;
    await new Promise((res) => setTimeout(res, 150));
  }
  throw new Error(`log never appeared: ${line}`);
}

/** A critical log that the e2e backend scores 0.95: unique remote address per call so alerts do not dedup into each other. */
export function criticalLog(): string {
  seq += 1;
  const octet = (Date.now() + seq * 7) % 200 + 20;
  return `Audit log cleared by user root on db-${seq} from 203.0.113.${octet} token=abc${seq}`;
}

export async function raiseAlert(request: APIRequestContext): Promise<string> {
  const before = (await (await request.get(`${API}/api/v1/alerts?limit=500`, { headers: auth("analyst") })).json()).items.map((a: { id: string }) => a.id);
  await ingest(request, criticalLog());
  for (let i = 0; i < 60; i++) {
    const now = (await (await request.get(`${API}/api/v1/alerts?limit=500`, { headers: auth("analyst") })).json()).items;
    const fresh = now.find((a: { id: string }) => !before.includes(a.id));
    if (fresh) return fresh.id;
    await new Promise((res) => setTimeout(res, 200));
  }
  throw new Error("no alert was raised");
}
