"use client";

import { Activity, Link2, ShieldAlert, Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import { fmtNumber, shortHash, timeAgo } from "@/lib/format";
import { usePoll } from "@/lib/usePoll";
import { StatusPill } from "./Badges";

function Card({
  label,
  icon: Icon,
  tone = "text-accent",
  children,
  foot,
}: {
  label: string;
  icon: typeof Activity;
  tone?: string;
  children: React.ReactNode;
  foot?: React.ReactNode;
}) {
  return (
    <section className="flex min-h-[132px] flex-col justify-between rounded-lg border border-line bg-panel p-4" aria-label={label}>
      <header className="flex items-center justify-between text-xs uppercase tracking-wider text-mute">
        <h2 className="font-medium">{label}</h2>
        <Icon size={16} className={tone} aria-hidden />
      </header>
      <div className="mt-2">{children}</div>
      <footer className="mt-2 text-xs text-mute">{foot}</footer>
    </section>
  );
}

function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) return <div className="h-8" />;
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * 100},${30 - (v / max) * 28}`).join(" ");
  return (
    <svg viewBox="0 0 100 32" preserveAspectRatio="none" className="h-8 w-full" role="img" aria-label="Events per second, last 60 seconds">
      <polyline points={pts} fill="none" stroke="#7ba3ff" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

const Big = ({ children, unit }: { children: React.ReactNode; unit?: string }) => (
  <p className="tabular text-3xl font-semibold leading-none">
    {children}
    {unit && <span className="ml-1 text-base font-normal text-mute">{unit}</span>}
  </p>
);

export default function MetricCards() {
  const { data: m, error: mErr } = usePoll((s) => api.metrics(s), 2000);
  const { data: t } = usePoll((s) => api.throughput(s), 2000);
  const { data: b } = usePoll((s) => api.batches(s), 4000);

  const offline = !!mErr && !m;
  const dash = offline ? "—" : undefined;
  const anomalyPct = m && m.processed ? (100 * m.anomalies) / m.processed : 0;

  const latest = b?.items[0];
  const anchor = latest?.anchor;

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <Card
        label="Ingestion rate"
        icon={Activity}
        foot={m ? `${fmtNumber(m.processed)} processed · ${fmtNumber(m.dropped)} dropped` : dash}
      >
        <Big unit="EPS">{m ? fmtNumber(m.throughput_eps["10s"], 1) : "—"}</Big>
        <Sparkline values={t?.series.map((p) => p.count) ?? []} />
      </Card>

      <Card
        label="Anomaly count"
        icon={ShieldAlert}
        tone="text-crit"
        foot={m ? `${anomalyPct.toFixed(2)}% of processed events scored > 0.70` : dash}
      >
        <Big>{m ? fmtNumber(m.anomalies) : "—"}</Big>
      </Card>

      <Card
        label="Noise reduced"
        icon={Sparkles}
        tone="text-ok"
        foot={m ? `${fmtNumber(m.templates)} templates cover ${fmtNumber(m.processed)} events · ${m.compression_ratio.toFixed(1)}× compression` : dash}
      >
        <Big unit="%">{m ? fmtNumber(m.noise_reduced_pct, 1) : "—"}</Big>
      </Card>

      <Card
        label="Blockchain anchor"
        icon={Link2}
        tone={anchor ? "text-ok" : "text-warn"}
        foot={
          anchor
            ? `${shortHash(anchor.tx_id)} · block ${anchor.block_number} · ${timeAgo(anchor.timestamp)}`
            : b
              ? `${b.pending_records}/${b.batch_size} records pending in current batch`
              : dash
        }
      >
        {!b ? (
          <Big>—</Big>
        ) : anchor ? (
          <div className="space-y-1.5">
            <StatusPill tone="ok">Anchored · {anchor.status}</StatusPill>
            <p className="text-xs text-mute">
              {latest?.id} · {anchor.channel}
              {anchor.mock && <span className="ml-1 rounded bg-warn/15 px-1 text-warn">MOCK</span>}
            </p>
          </div>
        ) : (
          <StatusPill tone="warn">Awaiting first batch</StatusPill>
        )}
      </Card>
    </div>
  );
}
