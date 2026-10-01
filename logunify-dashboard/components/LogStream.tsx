"use client";

import { ChevronRight, Pause, Play, Search } from "lucide-react";
import { Fragment, useMemo, useState } from "react";
import { docKey, fmtTime, hasIndicator, severityOf, type Severity } from "@/lib/format";
import type { EcsDoc } from "@/lib/types";
import { useLiveLogs } from "@/lib/useLiveLogs";
import { AttackTag, GeoBadge, SeverityBadge, TiBadge } from "./Badges";

type Filter = "all" | "ti" | Severity;

const FILTERS: { value: Filter; label: string }[] = [
  { value: "all", label: "All severities" },
  { value: "ti", label: "Threat-intel matches" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const logSource = (d: EcsDoc) => d.host?.name ?? d.observer?.product ?? "unattributed";

/** ECS event.action when the parser/mapper set one; otherwise the message itself, so no row is blank. */
function actionCell(d: EcsDoc) {
  const a = d.event?.action ?? d.event?.reason;
  if (a) return a;
  const m = d.message ?? d.event?.original;
  return m ? <span className="text-mute">{m}</span> : <span className="text-mute">—</span>;
}

export default function LogStream() {
  const [paused, setPaused] = useState(false);
  const [sev, setSev] = useState<Filter>("all");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const { items, live, error, lagged } = useLiveLogs(paused);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const seen = new Map<string, number>();
    return items
      .map((d) => {
        const base = docKey(d);
        const n = seen.get(base) ?? 0;          // identical lines in the same instant would collide
        seen.set(base, n + 1);
        return { d, key: n ? `${base}-${n}` : base, sev: severityOf(d) };
      })
      .filter((r) => sev === "all" || (sev === "ti" ? hasIndicator(r.d) : r.sev.level === sev))
      .filter(
        (r) =>
          !needle ||
          [r.d.source?.ip, logSource(r.d), r.d.event?.action, r.d.message, r.d.threat?.technique?.id]
            .join(" ")
            .toLowerCase()
            .includes(needle),
      );
  }, [items, sev, q]);

  return (
    <section className="rounded-lg border border-line bg-panel" aria-label="Live log stream">
      <header className="flex flex-wrap items-center gap-3 border-b border-line p-3">
        <div className="mr-auto flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${error && !live ? "bg-crit" : paused ? "bg-warn" : live ? "animate-pulse bg-ok" : "bg-warn"}`} aria-hidden />
          <h2 className="text-sm font-semibold">Live log stream</h2>
          <span className="text-xs text-mute">{error && !live ? "backend unreachable" : paused ? "paused" : live ? (lagged ? `live (push) · ${lagged} skipped` : "live (push)") : "connecting… polling every 15s"}</span>
        </div>
        <label className="relative">
          <span className="sr-only">Search logs</span>
          <Search size={14} className="pointer-events-none absolute left-2 top-2 text-mute" aria-hidden />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search IP, source, action…"
            className="w-56 rounded border border-line bg-bg py-1.5 pl-7 pr-2 text-sm placeholder:text-mute"
          />
        </label>
        <label>
          <span className="sr-only">Filter by severity</span>
          <select
            value={sev}
            onChange={(e) => setSev(e.target.value as Filter)}
            className="rounded border border-line bg-bg px-2 py-1.5 text-sm"
          >
            {FILTERS.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </select>
        </label>
        <button
          onClick={() => setPaused((p) => !p)}
          className="inline-flex items-center gap-1.5 rounded border border-line bg-panel2 px-2.5 py-1.5 text-sm hover:border-accent"
          aria-pressed={paused}
        >
          {paused ? <Play size={14} aria-hidden /> : <Pause size={14} aria-hidden />}
          {paused ? "Resume" : "Pause"}
        </button>
      </header>

      <div className="max-h-[560px] overflow-auto">
        <table className="w-full min-w-[820px] border-collapse text-left text-sm">
          <thead className="sticky top-0 z-10 bg-panel2 text-xs uppercase tracking-wider text-mute">
            <tr>
              <th className="w-8 px-2 py-2" aria-label="Expand" />
              <th className="px-3 py-2 font-medium">Timestamp</th>
              <th className="px-3 py-2 font-medium">Source IP</th>
              <th className="px-3 py-2 font-medium">Log source</th>
              <th className="px-3 py-2 font-medium">Event action</th>
              <th className="px-3 py-2 font-medium">Severity</th>
              <th className="px-3 py-2 font-medium">ATT&amp;CK / TI</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ d, key, sev: s }) => {
              const expanded = open === key;
              return (
                <Fragment key={key}>
                  <tr
                    className={`border-t border-line hover:bg-panel2/60 ${s.level === "critical" || s.level === "high" ? "bg-crit/[0.04]" : ""}`}
                  >
                    <td className="px-2 py-1.5">
                      <button
                        onClick={() => setOpen(expanded ? null : key)}
                        aria-expanded={expanded}
                        aria-label={expanded ? "Collapse event details" : "Expand event details"}
                        className="rounded p-1 text-mute hover:text-fg"
                      >
                        <ChevronRight size={14} className={expanded ? "rotate-90" : ""} aria-hidden />
                      </button>
                    </td>
                    <td className="tabular whitespace-nowrap px-3 py-1.5 font-mono text-xs text-mute">{fmtTime(d["@timestamp"])}</td>
                    <td className="whitespace-nowrap px-3 py-1.5">
                      <span className="inline-flex items-center gap-2">
                        <span className="font-mono text-xs">{d.source?.ip ?? "—"}</span>
                        <GeoBadge geo={d.source?.geo} />
                      </span>
                    </td>
                    <td className="max-w-[160px] truncate px-3 py-1.5" title={logSource(d)}>
                      {logSource(d)}
                      <span className="ml-1.5 text-[11px] uppercase text-mute">{d.logunify?.source_format}</span>
                    </td>
                    <td className="max-w-[240px] truncate px-3 py-1.5" title={d.message}>
                      {actionCell(d)}
                    </td>
                    <td className="px-3 py-1.5">
                      <SeverityBadge level={s.level} score={s.score} />
                    </td>
                    <td className="px-3 py-1.5">
                      <span className="inline-flex items-center gap-1.5">
                        <AttackTag threat={d.threat} />
                        <TiBadge doc={d} />
                      </span>
                    </td>
                  </tr>
                  {expanded && (
                    <tr className="border-t border-line bg-bg">
                      <td colSpan={7} className="px-4 py-3">
                        {d.logunify?.template?.text && (
                          <p className="mb-2 text-xs text-mute">
                            Template #{d.logunify.template.id}: <span className="font-mono text-fg">{d.logunify.template.text}</span>
                          </p>
                        )}
                        <pre className="max-h-64 overflow-auto rounded border border-line bg-panel p-3 font-mono text-xs leading-relaxed">
                          {JSON.stringify(d, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-mute">
                  {error && items.length === 0
                    ? "Can't reach the LogUnify API. Is the backend running on port 8000?"
                    : items.length > 0
                      ? "No events match the current filters."
                      : "Waiting for events…"}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
