"use client";

import { Clock } from "lucide-react";
import { useEffect, useState } from "react";

/** Remaining time to a deadline, ticking every second. Colour AND text change (never colour alone): ok > 2 h, warn <= 2 h, critical <= 30 min / overdue. */
export function useRemaining(dueAt: string | number | undefined, active = true) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [active]);
  const due = dueAt === undefined ? NaN : typeof dueAt === "number" ? dueAt * 1000 : new Date(dueAt).getTime();
  return Number.isNaN(due) ? null : Math.floor((due - now) / 1000);
}

export function fmtDuration(totalSeconds: number): string {
  const s = Math.abs(totalSeconds);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return h > 0 ? `${h}h ${String(m).padStart(2, "0")}m` : `${m}m ${String(sec).padStart(2, "0")}s`;
}

export default function Countdown({ dueAt, active = true, label = "CERT-In report due" }: { dueAt: string; active?: boolean; label?: string }) {
  const left = useRemaining(dueAt, active);
  if (left === null) return <span className="text-mute">—</span>;
  if (!active) return <span className="text-mute">clock stopped</span>;
  const overdue = left < 0;
  const tone = overdue || left <= 1800 ? "border-crit/50 bg-crit/10 text-crit" : left <= 7200 ? "border-warn/50 bg-warn/10 text-warn" : "border-line bg-panel2 text-fg";
  return (
    <span
      className={`tabular inline-flex items-center gap-1.5 whitespace-nowrap rounded border px-2 py-0.5 text-xs font-medium ${tone}`}
      title={`${label}: ${new Date(dueAt).toLocaleString()}`}
    >
      <Clock size={12} aria-hidden />
      {overdue ? `OVERDUE by ${fmtDuration(left)}` : `${fmtDuration(left)} left`}
    </span>
  );
}
