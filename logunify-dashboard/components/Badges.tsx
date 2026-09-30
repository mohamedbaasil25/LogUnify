import { Biohazard, Globe2, Home, ShieldAlert } from "lucide-react";
import type { EcsDoc } from "@/lib/types";
import { type Severity } from "@/lib/format";

const SEV_STYLE: Record<Severity, string> = {
  critical: "bg-crit/15 text-crit border-crit/40",
  high: "bg-warn/15 text-warn border-warn/40",
  medium: "bg-accent/15 text-accent border-accent/40",
  low: "bg-ok/10 text-ok border-ok/30",
  learning: "bg-panel2 text-mute border-line",
};

export function SeverityBadge({ level, score }: { level: Severity; score: number | null }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-medium ${SEV_STYLE[level]}`}
      title={score === null ? "Model still warming up: no anomaly score yet" : `Anomaly score ${score.toFixed(2)}`}
    >
      <span className="capitalize">{level}</span>
      {score !== null && <span className="tabular font-mono opacity-80">{score.toFixed(2)}</span>}
    </span>
  );
}

export function GeoBadge({ geo }: { geo: NonNullable<EcsDoc["source"]>["geo"] }) {
  if (!geo?.country_iso_code) return null;
  const internal = geo.country_iso_code === "--";
  const Icon = internal ? Home : Globe2;
  return (
    <span
      className="inline-flex items-center gap-1 rounded border border-line bg-panel2 px-1.5 py-0.5 text-[11px] text-mute"
      title={`${geo.country_name ?? geo.country_iso_code} (demo GeoIP data)`}
    >
      <Icon size={11} aria-hidden />
      <span className="font-mono">{internal ? "LAN" : geo.country_iso_code}</span>
    </span>
  );
}

export function AttackTag({ threat }: { threat: EcsDoc["threat"] }) {
  const id = threat?.technique?.id;
  if (!id) return <span className="text-mute">—</span>;
  return (
    <span
      className="inline-flex items-center gap-1 rounded border border-crit/40 bg-crit/10 px-2 py-0.5 text-xs text-crit"
      title={`${threat?.technique?.name ?? ""} · ${threat?.tactic?.name ?? ""} (placeholder mapping)`}
    >
      <ShieldAlert size={12} aria-hidden />
      <span className="font-mono">{id}</span>
    </span>
  );
}

export function TiBadge({ doc }: { doc: EcsDoc }) {
  const ind = doc.threat?.indicator;
  if (!ind?.provider) return null;
  const hits = doc.logunify?.ti?.matches?.[0];
  return (
    <span
      className="inline-flex items-center gap-1 rounded border border-crit/50 bg-crit/15 px-2 py-0.5 text-xs font-medium text-crit"
      title={`Threat intel match: ${hits?.value ?? ""} (${ind.type}) · feed ${ind.provider} · confidence ${ind.confidence ?? "?"}${ind.description ? " · " + ind.description : ""}`}
    >
      <Biohazard size={12} aria-hidden />
      TI
    </span>
  );
}

export function StatusPill({ tone, children }: { tone: "ok" | "warn" | "crit" | "mute"; children: React.ReactNode }) {
  const t = {
    ok: "bg-ok/10 text-ok border-ok/30",
    warn: "bg-warn/10 text-warn border-warn/30",
    crit: "bg-crit/10 text-crit border-crit/30",
    mute: "bg-panel2 text-mute border-line",
  }[tone];
  return <span className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-medium ${t}`}>{children}</span>;
}
