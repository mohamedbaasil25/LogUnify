"use client";

import { Inbox, RefreshCw, Server, Wrench } from "lucide-react";
import { useState } from "react";
import { StatusPill } from "@/components/Badges";
import RoleGate from "@/components/RoleGate";
import { api } from "@/lib/api";
import { useSession } from "@/lib/session";
import { usePoll } from "@/lib/usePoll";

const card = "rounded-lg border border-line bg-panel";

function SystemCard() {
  const { data, error } = usePoll((s) => api.system(s), 10_000);
  return (
    <section className={`${card} p-4`} aria-labelledby="sys">
      <h2 id="sys" className="mb-3 flex items-center gap-2 text-sm font-semibold"><Server size={15} aria-hidden /> System</h2>
      {error && <p role="alert" className="text-sm text-crit">{error}</p>}
      {data && (
        <>
          <p className="mb-3">
            <StatusPill tone={data.ready ? "ok" : "crit"}>{data.ready ? "ready" : "NOT ready"}</StatusPill>
            {data.problems.map((p) => <span key={p} className="ml-2 text-sm text-crit">{p}</span>)}
          </p>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-3">
            {[
              ["Version", data.version], ["Message bus", data.bus], ["Worker", data.worker_id ?? "—"], ["Auth mode", data.auth_mode],
              ["Consumer restarts", String(data.consumer_restarts)], ["ECS validation", data.taxonomy_mode],
              ["Raw archive", data.raw_archive ? "on" : "off"], ["Demo traffic", data.mock_generator ? "ON (not for production)" : "off"], ["API docs", data.docs_enabled ? "exposed" : "off"],
            ].map(([k, v]) => (
              <div key={k}><dt className="text-xs uppercase tracking-wider text-mute">{k}</dt><dd className={v.startsWith("ON") ? "text-warn" : ""}>{v}</dd></div>
            ))}
          </dl>
        </>
      )}
    </section>
  );
}

function ParsersCard() {
  const { data, error } = usePoll((s) => api.parsers(s), 30_000);
  return (
    <section className={card} aria-labelledby="parsers">
      <h2 id="parsers" className="flex items-center gap-2 border-b border-line px-4 py-3 text-sm font-semibold"><Wrench size={15} aria-hidden /> Parsers</h2>
      {error && <p role="alert" className="px-4 pt-3 text-sm text-crit">{error}</p>}
      {data?.errors.length ? (
        <ul className="m-4 space-y-1 rounded border border-crit/40 bg-crit/10 p-3 text-xs text-crit" aria-label="Parser files that failed to load">
          {data.errors.map((e) => <li key={e}>⚠ {e}</li>)}
        </ul>
      ) : null}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[480px] border-collapse text-left text-sm">
          <caption className="sr-only">Loaded parsers, their versions and kinds</caption>
          <thead className="bg-panel2 text-xs uppercase tracking-wider text-mute">
            <tr><th scope="col" className="px-4 py-2 font-medium">Name</th><th scope="col" className="px-4 py-2 font-medium">Version</th><th scope="col" className="px-4 py-2 font-medium">Kind</th><th scope="col" className="px-4 py-2 font-medium">Description</th></tr>
          </thead>
          <tbody>
            {data?.items.map((p) => (
              <tr key={p.name} className="border-t border-line">
                <td className="px-4 py-2 font-mono text-xs">{p.name}</td><td className="px-4 py-2 text-mute">{p.version}</td>
                <td className="px-4 py-2 text-mute">{p.kind}</td><td className="px-4 py-2 text-mute">{p.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="px-4 py-3 text-xs text-mute">New parsers are YAML or Python files placed in the backend's parser directory; they are deployed like code, never uploaded here.</p>
    </section>
  );
}

function DlqCard() {
  const [n, setN] = useState(1000);
  const [msg, setMsg] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const { data, error } = usePoll((s) => api.dlq(s), 10_000, true, 0);
  const lost = data ? data.stats.lost_full + data.stats.lost_queue + data.stats.lost_io : 0;
  const total = data ? Object.values(data.by_reason).reduce((a, b) => a + b, 0) : 0;

  async function replay() {
    setMsg(null);
    try {
      const r = await api.dlqReplay(n);
      setMsg(`Re-submitted ${r.resubmitted} of ${r.taken}; ${r.returned_to_dlq} went back to the dead-letter file.`);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
    setConfirm(false);
  }

  return (
    <section className={card} aria-labelledby="dlq">
      <h2 id="dlq" className="flex items-center gap-2 border-b border-line px-4 py-3 text-sm font-semibold"><Inbox size={15} aria-hidden /> Dead-letter store</h2>
      <div className="space-y-3 p-4">
        {error && <p role="alert" className="text-sm text-crit">{error}</p>}
        {lost > 0 && <p role="alert" className="rounded border border-crit/50 bg-crit/10 p-2 text-sm text-crit">{lost} dead-lettered logs were LOST (queue/disk full). Free space or raise the cap now.</p>}
        {data && (
          <>
            <p className="text-sm text-mute">
              Logs the pipeline accepted but could not normalize are kept here with their raw bytes. <b className="text-fg">{data.stats.written}</b> written ·{" "}
              {(data.stats.file_bytes / 1024).toFixed(1)} KiB on disk · {total} counted this run.
            </p>
            {Object.keys(data.by_reason).length > 0 && (
              <ul className="flex flex-wrap gap-2 text-xs">
                {Object.entries(data.by_reason).map(([k, v]) => <li key={k} className="rounded border border-line bg-panel2 px-2 py-1">{k}: <b>{v}</b></li>)}
              </ul>
            )}
            {data.preview.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[520px] border-collapse text-left text-xs">
                  <caption className="sr-only">Oldest dead-lettered records</caption>
                  <thead className="text-mute"><tr><th scope="col" className="py-1 pr-3 font-medium">event.id</th><th scope="col" className="py-1 pr-3 font-medium">Reason</th><th scope="col" className="py-1 pr-3 font-medium">Stage</th><th scope="col" className="py-1 font-medium">Error</th></tr></thead>
                  <tbody>
                    {data.preview.map((r) => (
                      <tr key={r.event_id + r.ts} className="border-t border-line"><td className="py-1 pr-3 font-mono">{r.event_id.slice(0, 13)}…</td><td className="py-1 pr-3">{r.reason}</td><td className="py-1 pr-3">{r.stage}</td><td className="py-1 text-mute">{r.error}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <div className="flex flex-wrap items-end gap-3">
              <div>
                <label htmlFor="replay-n" className="mb-1 block text-xs uppercase tracking-wider text-mute">Replay up to</label>
                <input id="replay-n" type="number" min={1} max={100000} value={n} onChange={(e) => setN(Number(e.target.value) || 1)} className="w-28 rounded border border-line bg-bg px-3 py-2 text-sm" />
              </div>
              {confirm ? (
                <span className="flex gap-2">
                  <button onClick={replay} className="rounded bg-accent px-3 py-2 text-sm font-medium text-bg">Yes, replay {n}</button>
                  <button onClick={() => setConfirm(false)} className="rounded border border-line px-3 py-2 text-sm">Cancel</button>
                </span>
              ) : (
                <button onClick={() => setConfirm(true)} disabled={data.stats.written === 0} className="inline-flex items-center gap-1.5 rounded border border-line bg-panel2 px-3 py-2 text-sm hover:border-accent disabled:opacity-50">
                  <RefreshCw size={14} aria-hidden /> Replay…
                </button>
              )}
            </div>
            {msg && <p role="status" className="text-sm text-ok">{msg}</p>}
            <p className="text-xs text-mute">Replay re-submits the original bytes with the original event.id (idempotent downstream). Fix the parser first, or they will land here again.</p>
          </>
        )}
      </div>
    </section>
  );
}

export default function OperationsPage() {
  const { can } = useSession();
  return (
    <RoleGate min="analyst" what="Operations">
      <h1 className="text-lg font-semibold">Operations</h1>
      <div className="grid gap-4 xl:grid-cols-2">
        <SystemCard />
        <ParsersCard />
      </div>
      <RoleGate min="admin" what="The dead-letter store">
        {can("admin") && <DlqCard />}
      </RoleGate>
    </RoleGate>
  );
}
