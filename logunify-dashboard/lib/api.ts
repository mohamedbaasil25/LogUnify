import type { AlertEvent, AlertNote, Calibration, CalibrationParams, Suppression, AlertSummary, AlertView, LogQuery, LogSearchResult, SavedSearch, AuditRow, CertReport, ComplianceReport, DlqView, Me, SystemInfo, TraceResult } from "./types-app";
import type { ParserInfo, AuditResult, BatchList, LogSource, Metrics, ProofBundle, RecentLogs, SourceCreate, ThroughputSeries, VerifyResult } from "./types";

/** Errors carry the backend's message (FastAPI `detail`, string or validation list). */
export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

const TOKEN_KEY = "logunify_token";

/** Bearer token for backends running LOGUNIFY_AUTH_MODE=jwt. Kept in sessionStorage (cleared when the tab closes). */
export const auth = {
  get: (): string => {
    try {
      return sessionStorage.getItem(TOKEN_KEY) ?? "";
    } catch {
      return "";
    }
  },
  set: (t: string) => {
    try {
      t ? sessionStorage.setItem(TOKEN_KEY, t) : sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      /* storage blocked */
    }
  },
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = auth.get();
  const headers = { ...(init?.headers as Record<string, string> | undefined), ...(token ? { authorization: `Bearer ${token}` } : {}) };
  const res = await fetch(path, { cache: "no-store", ...init, headers });
  if (res.status === 401 && token && typeof window !== "undefined") {
    auth.set(""); // expired / revoked / invalid token: drop it so the session layer shows the sign-in page
    window.dispatchEvent(new Event("logunify:unauthorized"));
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      const d = body?.detail;
      if (typeof d === "string") msg = d;
      else if (Array.isArray(d)) msg = d.map((e: { loc?: unknown[]; msg?: string }) => `${e.loc?.slice(-1)[0] ?? ""}: ${e.msg}`).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(msg, res.status);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

export const api = {
  metrics: (signal?: AbortSignal) => request<Metrics>("/api/v1/metrics", { signal }),
  throughput: (signal?: AbortSignal) => request<ThroughputSeries>("/api/v1/metrics/throughput?window=60", { signal }),
  recent: (limit: number, signal?: AbortSignal) => request<RecentLogs>(`/api/v1/logs/recent?limit=${limit}`, { signal }),
  batches: (signal?: AbortSignal, limit = 1) => request<BatchList>(`/api/v1/integrity/batches?limit=${limit}`, { signal }),
  proof: (batchId: string, index: number) =>
    request<ProofBundle>(`/api/v1/integrity/batches/${encodeURIComponent(batchId)}/proof/${index}`),
  audit: (batchId: string) => request<AuditResult>(`/api/v1/integrity/batches/${encodeURIComponent(batchId)}/audit`),
  verify: (body: unknown) =>
    request<VerifyResult>("/api/v1/integrity/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  parsers: (signal?: AbortSignal) => request<{ items: ParserInfo[]; errors: string[] }>("/api/v1/parsers", { signal }),
  sources: (signal?: AbortSignal) => request<{ items: LogSource[] }>("/api/v1/sources", { signal }),
  createSource: (body: SourceCreate) =>
    request<LogSource>("/api/v1/sources", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  deleteSource: (id: string) => request<void>(`/api/v1/sources/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ---- session / system
  me: (signal?: AbortSignal) => request<Me>("/api/v1/auth/me", { signal }),
  system: (signal?: AbortSignal) => request<SystemInfo>("/api/v1/system", { signal }),

  // ---- alerts (CERT-In workflow)
  alerts: (status: string, signal?: AbortSignal, assignee = "") =>
    request<{ items: AlertSummary[] }>(`/api/v1/alerts?status=${encodeURIComponent(status)}&limit=200${assignee ? `&assignee=${encodeURIComponent(assignee)}` : ""}`, { signal }),
  alertAssign: (id: string, by: string, to: string | null, note = "") => post<AlertView>(`/api/v1/alerts/${encodeURIComponent(id)}/assign`, { by, to, note }),
  alertNotes: (id: string, signal?: AbortSignal) => request<{ items: AlertNote[] }>(`/api/v1/alerts/${encodeURIComponent(id)}/notes`, { signal }),
  alertAddNote: (id: string, by: string, text: string) => post<AlertNote>(`/api/v1/alerts/${encodeURIComponent(id)}/notes`, { by, text }),
  alert: (id: string, signal?: AbortSignal) => request<AlertView>(`/api/v1/alerts/${encodeURIComponent(id)}`, { signal }),
  alertReport: (id: string, signal?: AbortSignal) => request<CertReport>(`/api/v1/alerts/${encodeURIComponent(id)}/cert-in-report`, { signal }),
  alertReportText: async (id: string) => {
    const t = auth.get();
    const r = await fetch(`/api/v1/alerts/${encodeURIComponent(id)}/cert-in-report?format=text`, { headers: t ? { authorization: `Bearer ${t}` } : {} });
    if (!r.ok) throw new ApiError(`${r.status} ${r.statusText}`, r.status);
    return r.text();
  },
  alertEvents: (id: string, signal?: AbortSignal) => request<{ items: AlertEvent[] }>(`/api/v1/alerts/${encodeURIComponent(id)}/events`, { signal }),
  alertAck: (id: string, by: string, note: string) => post<AlertView>(`/api/v1/alerts/${encodeURIComponent(id)}/ack`, { by, note }),
  alertDetails: (id: string, by: string, fields: Record<string, unknown>) => patch<unknown>(`/api/v1/alerts/${encodeURIComponent(id)}/details`, { by, ...fields }),
  alertReported: (id: string, by: string, via: string, reference: string, note: string) =>
    post<AlertView>(`/api/v1/alerts/${encodeURIComponent(id)}/report`, { by, via, reference, note }),
  alertClose: (id: string, by: string, resolution: string, note: string) => post<AlertView>(`/api/v1/alerts/${encodeURIComponent(id)}/close`, { by, resolution, note }),

  // ---- calibration / suppressions
  calibration: (q: CalibrationParams, signal?: AbortSignal) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(q)) if (v) p.set(k, v);
    return request<Calibration>(`/api/v1/alerts-calibration?${p}`, { signal });
  },
  createSuppression: (body: { technique: string; asset: string; reason: string; days: number }) => post<Suppression>("/api/v1/suppressions", body),
  revokeSuppression: (id: string) => request<Suppression>(`/api/v1/suppressions/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ---- search / saved searches
  logSearch: (q: LogQuery, limit = 100, offset = 0, signal?: AbortSignal) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== "") p.set(k, String(v));
    p.set("limit", String(limit));
    p.set("offset", String(offset));
    return request<LogSearchResult>(`/api/v1/logs/search?${p}`, { signal });
  },
  searches: (signal?: AbortSignal) => request<{ items: SavedSearch[] }>("/api/v1/searches", { signal }),
  createSearch: (body: { name: string; kind: "logs" | "alerts"; query: object; shared: boolean }) => post<SavedSearch>("/api/v1/searches", body),
  deleteSearch: (id: string) => request<void>(`/api/v1/searches/${encodeURIComponent(id)}`, { method: "DELETE" }),
  runSearch: (id: string) => post<{ search: SavedSearch; result: { total: number; items: unknown[]; coverage?: LogSearchResult["coverage"] } }>(`/api/v1/searches/${encodeURIComponent(id)}/run`, {}),

  // ---- trace
  trace: (id: string, includeRaw = false) => request<TraceResult>(`/api/v1/trace/${encodeURIComponent(id)}${includeRaw ? "?include_raw=true" : ""}`),

  // ---- operations
  dlq: (signal?: AbortSignal) => request<DlqView>("/api/v1/dlq?limit=50", { signal }),
  dlqReplay: (limit: number) => post<{ taken: number; resubmitted: number; returned_to_dlq: number }>(`/api/v1/dlq/replay?limit=${limit}`, {}),

  // ---- governance
  auditLog: (action: string, signal?: AbortSignal) =>
    request<{ keyed: boolean; items: AuditRow[] }>(`/api/v1/audit?limit=100${action ? `&action=${encodeURIComponent(action)}` : ""}`, { signal }),
  auditVerify: () => post<{ valid: boolean; records: number; broken_at: number | null; reason?: string; keyed?: boolean }>("/api/v1/audit/verify", {}),
  compliance: (signal?: AbortSignal) => request<ComplianceReport>("/api/v1/compliance/report", { signal }),
  compliancePdf: async () => {
    const t = auth.get();
    const r = await fetch("/api/v1/compliance/report.pdf", { headers: t ? { authorization: `Bearer ${t}` } : {} });
    if (!r.ok) throw new ApiError(`${r.status} ${r.statusText}`, r.status);
    return r.blob();
  },
  revoked: (signal?: AbortSignal) => request<{ jti: string[]; subjects: Record<string, number> }>("/api/v1/auth/revoked", { signal }),
  revokeSubject: (sub: string) => post<{ revoked: string }>("/api/v1/auth/revoke", { sub }),
  unrevokeSubject: (sub: string) => request<void>(`/api/v1/auth/revoke/subject/${encodeURIComponent(sub)}`, { method: "DELETE" }),
};

function post<T>(path: string, body: unknown) {
  return request<T>(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
}

function patch<T>(path: string, body: unknown) {
  return request<T>(path, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
}
