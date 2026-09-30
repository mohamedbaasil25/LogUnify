import type { AuditResult, BatchList, LogSource, Metrics, ProofBundle, RecentLogs, SourceCreate, ThroughputSeries, VerifyResult } from "./types";

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
  sources: (signal?: AbortSignal) => request<{ items: LogSource[] }>("/api/v1/sources", { signal }),
  createSource: (body: SourceCreate) =>
    request<LogSource>("/api/v1/sources", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  deleteSource: (id: string) => request<void>(`/api/v1/sources/${encodeURIComponent(id)}`, { method: "DELETE" }),
};
