import type { NextRequest } from "next/server";

/**
 * Runtime reverse proxy to the LogUnify backend (replaces next.config rewrites, which bake the target URL in at BUILD time and so
 * cannot be configured per deployment). The target comes from LOGUNIFY_API_URL when the server STARTS, the backend URL never reaches
 * the browser, and responses are streamed through (Server-Sent Events work).
 */
export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length", "cookie"]);

async function proxy(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }): Promise<Response> {
  const { path } = await ctx.params;
  const base = (process.env.LOGUNIFY_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
  const url = `${base}/api/${path.map(encodeURIComponent).join("/")}${req.nextUrl.search}`;

  const headers = new Headers();
  req.headers.forEach((v, k) => {
    if (!HOP.has(k.toLowerCase())) headers.set(k, v);
  });
  // keep the address chain an upstream reverse proxy gave us; the backend believes it only from its trusted-proxy list
  const xff = req.headers.get("x-forwarded-for");
  if (xff) headers.set("x-forwarded-for", xff);
  const init: RequestInit & { duplex?: "half" } = { method: req.method, headers, signal: req.signal, redirect: "manual", cache: "no-store" };
  if (req.method !== "GET" && req.method !== "HEAD") {
    init.body = req.body;
    init.duplex = "half";
  }
  let up: Response;
  try {
    up = await fetch(url, init);
  } catch {
    return Response.json({ detail: "LogUnify backend unreachable" }, { status: 502 });
  }
  const out = new Headers();
  up.headers.forEach((v, k) => {
    if (!HOP.has(k.toLowerCase()) && k.toLowerCase() !== "content-encoding") out.set(k, v);
  });
  return new Response(up.body, { status: up.status, headers: out });
}

export { proxy as GET, proxy as POST, proxy as PATCH, proxy as PUT, proxy as DELETE };
