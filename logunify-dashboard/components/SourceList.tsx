"use client";

import { Globe, Plug, Radio, Trash2 } from "lucide-react";
import { useState } from "react";
import { api } from "@/lib/api";
import { fmtNumber } from "@/lib/format";
import type { LogSource } from "@/lib/types";
import { StatusPill } from "./Badges";

const ICON = { syslog: Radio, http: Globe, api: Plug } as const;

function detail(s: LogSource): string {
  if (s.type === "syslog") return `${String(s.config.protocol).toUpperCase()} :${s.config.port}`;
  if (s.type === "api") return `${s.config.url} · every ${s.config.poll_interval_s}s`;
  return String(s.config.ingest_path ?? "");
}

export default function SourceList({ sources, onChanged }: { sources: LogSource[] | undefined; onChanged: () => void }) {
  const [confirm, setConfirm] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function remove(id: string) {
    try {
      await api.deleteSource(id);
      setConfirm(null);
      setErr(null);
      onChanged();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Delete failed");
    }
  }

  return (
    <section className="rounded-lg border border-line bg-panel" aria-label="Configured log sources">
      <header className="border-b border-line px-4 py-3">
        <h2 className="text-sm font-semibold">Log sources</h2>
      </header>
      {err && <p role="alert" className="px-4 pt-3 text-sm text-crit">{err}</p>}
      {!sources?.length ? (
        <p className="px-4 py-8 text-center text-sm text-mute">
          No sources configured yet. Use “Add source” to register a Syslog, HTTP or API feed.
        </p>
      ) : (
        <ul className="divide-y divide-line">
          {sources.map((s) => {
            const Icon = ICON[s.type];
            return (
              <li key={s.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 text-sm">
                <Icon size={16} className="text-accent" aria-hidden />
                <div className="min-w-0 flex-1">
                  <p className="truncate font-medium">{s.name}</p>
                  <p className="truncate font-mono text-xs text-mute">{detail(s)}</p>
                </div>
                <span className="text-xs uppercase text-mute">{s.format}</span>
                <span className="tabular text-xs text-mute">{fmtNumber(s.received)} received</span>
                <StatusPill tone={s.status === "active" ? "ok" : "warn"}>{s.status}</StatusPill>
                {confirm === s.id ? (
                  <span className="flex items-center gap-1.5 text-xs">
                    <button onClick={() => remove(s.id)} className="rounded bg-crit px-2 py-1 font-medium text-bg">Delete</button>
                    <button onClick={() => setConfirm(null)} className="rounded border border-line px-2 py-1">Keep</button>
                  </span>
                ) : (
                  <button onClick={() => setConfirm(s.id)} className="rounded p-1.5 text-mute hover:text-crit" aria-label={`Delete source ${s.name}`}>
                    <Trash2 size={15} aria-hidden />
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
