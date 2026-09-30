import type { EcsDoc } from "./types";

export type Severity = "critical" | "high" | "medium" | "low" | "learning";

/** Anomaly score (0-1) -> analyst-facing severity. The backend tags ATT&CK only above 0.7. */
export function severityOf(doc: EcsDoc): { level: Severity; score: number | null } {
  const a = doc.logunify?.anomaly;
  if (!a || a.model_ready === false || typeof a.score !== "number")
    return { level: hasIndicator(doc) ? "high" : "learning", score: null };
  const s = a.score;
  const level: Severity = s >= 0.9 ? "critical" : s > 0.7 ? "high" : s >= 0.4 ? "medium" : "low";
  return { level: hasIndicator(doc) && (level === "low" || level === "medium") ? "high" : level, score: s };
}

/** A known-bad indicator (MISP / IOC feed) outranks a low ML score: escalate to at least High. */
export const hasIndicator = (doc: EcsDoc): boolean => !!doc.threat?.indicator?.provider || !!doc.logunify?.ti?.matched;

export function fmtNumber(n: number | undefined, digits = 0): string {
  if (n === undefined || Number.isNaN(n)) return "—";
  return n.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits });
}

export function fmtTime(iso: string | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString(undefined, { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

export function timeAgo(iso: string | undefined): string {
  if (!iso) return "—";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

export const shortHash = (h: string, n = 8) => `${h.slice(0, n)}…${h.slice(-4)}`;

/** Stable React key for an ECS doc (docs carry no id): FNV-1a over ingest time + original line. */
export function docKey(d: EcsDoc): string {
  const s = `${d.event?.ingested ?? d["@timestamp"]}|${d.event?.original ?? d.message ?? ""}`;
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 0x01000193);
  return (h >>> 0).toString(36);
}
