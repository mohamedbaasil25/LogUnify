"use client";

import { Play, Save, Search as SearchIcon, Trash2, Users } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { fmtTime, severityOf, docKey } from "@/lib/format";
import { useActor } from "@/lib/session";
import type { LogQuery, LogSearchResult, SavedSearch } from "@/lib/types-app";
import { SeverityBadge } from "./Badges";

const input = "w-full rounded border border-line bg-bg px-3 py-2 text-sm placeholder:text-mute";
const label = "mb-1 block text-xs font-medium uppercase tracking-wider text-mute";
const btn = "inline-flex items-center gap-1.5 rounded border border-line bg-panel2 px-3 py-2 text-sm hover:border-accent disabled:opacity-50";
const btnPrimary = "inline-flex items-center gap-1.5 rounded bg-accent px-3 py-2 text-sm font-medium text-bg hover:opacity-90 disabled:opacity-50";
const RANGES = [
  { v: "-15m", l: "Last 15 minutes" },
  { v: "-1h", l: "Last hour" },
  { v: "-6h", l: "Last 6 hours" },
  { v: "-24h", l: "Last 24 hours" },
  { v: "-7d", l: "Last 7 days" },
  { v: "", l: "Everything held" },
];

export default function SearchView() {
  const actor = useActor();
  const [q, setQ] = useState("");
  const [range, setRange] = useState("-1h");
  const [format, setFormat] = useState("");
  const [minScore, setMinScore] = useState("");
  const [result, setResult] = useState<LogSearchResult | null>(null);
  const [alertRows, setAlertRows] = useState<{ id: string; status: string; technique: string; host: string | null; assignee: string | null }[] | null>(null);
  const [heading, setHeading] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saved, setSaved] = useState<SavedSearch[]>([]);
  const [name, setName] = useState("");
  const [share, setShare] = useState(false);

  const query = useCallback((): LogQuery => ({ q: q.trim() || undefined, from: range || undefined, format: format.trim() || undefined, min_score: minScore ? Number(minScore) : undefined }), [q, range, format, minScore]);

  const loadSaved = useCallback(() => api.searches().then((r) => setSaved(r.items)).catch((e) => setError(e instanceof Error ? e.message : String(e))), []);
  useEffect(() => {
    loadSaved();
  }, [loadSaved]);

  async function run(qq: LogQuery = query()) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setAlertRows(null);
      setResult(await api.logSearch(qq, 200));
      setHeading("Log search");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function runSaved(s: SavedSearch) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await api.runSearch(s.id);
      setHeading(s.name);
      if (s.kind === "logs") {
        setAlertRows(null);
        setResult(r.result as unknown as LogSearchResult);
        setQ(s.query.q ?? "");
        setRange(s.query.from ?? "");
        setFormat(s.query.format ?? "");
        setMinScore(s.query.min_score === undefined ? "" : String(s.query.min_score));
      } else {
        setResult(null);
        setAlertRows(r.result.items as never);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    try {
      await api.createSearch({ name: name.trim(), kind: "logs", query: query(), shared: share });
      setNotice(`Saved “${name.trim()}”. Relative ranges such as “last hour” are re-evaluated every time it runs.`);
      setName("");
      await loadSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Search</h1>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <section className="min-w-0 space-y-4">
          <form
            className="space-y-3 rounded-lg border border-line bg-panel p-4"
            onSubmit={(e) => {
              e.preventDefault();
              run();
            }}
            aria-label="Search logs"
          >
            <div>
              <label htmlFor="q" className={label}>Query</label>
              <input id="q" value={q} onChange={(e) => setQ(e.target.value)} className={input} placeholder='failed password source.ip:203.0.113.* -user.name:root' maxLength={500} />
              <p className="mt-1 text-xs text-mute">Words match the message; <code>field:value</code> is exact (use <code>*</code> as wildcard); a leading <code>-</code> excludes. Terms are AND-ed.</p>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div>
                <label htmlFor="range" className={label}>Time range</label>
                <select id="range" value={range} onChange={(e) => setRange(e.target.value)} className={input}>
                  {RANGES.map((r) => <option key={r.v} value={r.v}>{r.l}</option>)}
                </select>
              </div>
              <div>
                <label htmlFor="fmt" className={label}>Parser</label>
                <input id="fmt" value={format} onChange={(e) => setFormat(e.target.value)} className={input} placeholder="e.g. windows_security" maxLength={41} />
              </div>
              <div>
                <label htmlFor="score" className={label}>Min anomaly score (0-1)</label>
                <input id="score" type="number" min={0} max={1} step={0.05} value={minScore} onChange={(e) => setMinScore(e.target.value)} className={input} />
              </div>
            </div>
            <div className="flex flex-wrap items-end gap-2">
              <button type="submit" className={btnPrimary} disabled={busy}><SearchIcon size={14} aria-hidden /> Search</button>
              <div className="ml-auto flex flex-wrap items-end gap-2">
                <div>
                  <label htmlFor="sname" className={label}>Save as</label>
                  <input id="sname" value={name} onChange={(e) => setName(e.target.value)} className={input} maxLength={80} placeholder="Search name" />
                </div>
                <label className="flex items-center gap-1.5 pb-2 text-xs"><input type="checkbox" checked={share} onChange={(e) => setShare(e.target.checked)} /> Share with all analysts</label>
                <button type="button" className={btn} disabled={!name.trim()} onClick={save}><Save size={14} aria-hidden /> Save</button>
              </div>
            </div>
          </form>

          {notice && <p role="status" className="rounded border border-ok/40 bg-ok/10 p-2 text-sm text-ok">{notice}</p>}
          {error && <p role="alert" className="rounded border border-crit/40 bg-crit/10 p-2 text-sm text-crit">{error}</p>}

          {result && (
            <section aria-label="Results" className="rounded-lg border border-line bg-panel">
              <header className="border-b border-line p-3 text-sm">
                <b>{heading}</b>: {result.total.toLocaleString()} match{result.total === 1 ? "" : "es"}{result.total > result.items.length ? `, showing the newest ${result.items.length}` : ""}
                <p className="mt-1 text-xs text-warn" data-testid="coverage">
                  Searched {result.coverage.events_held.toLocaleString()} events held by this instance
                  {result.coverage.oldest ? ` (${new Date(result.coverage.oldest).toLocaleString()} to ${new Date(result.coverage.newest ?? result.coverage.oldest).toLocaleString()})` : ""}. Older history is not searchable here; it lives in your SIEM.
                </p>
              </header>
              {result.items.length === 0 ? <p className="px-4 py-10 text-center text-sm text-mute">Nothing matched in this window. That does not prove it did not happen outside it.</p> : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[640px] border-collapse text-left text-sm">
                    <caption className="sr-only">Matching events, newest first</caption>
                    <thead className="bg-panel2 text-xs uppercase tracking-wider text-mute">
                      <tr>
                        <th scope="col" className="px-3 py-2 font-medium">Time</th>
                        <th scope="col" className="px-3 py-2 font-medium">Severity</th>
                        <th scope="col" className="px-3 py-2 font-medium">Source</th>
                        <th scope="col" className="px-3 py-2 font-medium">Message</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.items.map((d) => {
                        const sv = severityOf(d);
                        return (
                          <tr key={docKey(d)} className="border-t border-line align-top">
                            <td className="tabular whitespace-nowrap px-3 py-2 text-xs text-mute">{fmtTime(d["@timestamp"])}</td>
                            <td className="px-3 py-2"><SeverityBadge level={sv.level} score={sv.score} /></td>
                            <td className="px-3 py-2 text-xs">{d.host?.name ?? d.source?.ip ?? "—"}<span className="block text-mute">{d.logunify?.source_format}</span></td>
                            <td className="break-words px-3 py-2 text-xs">
                              {d.message ?? d.event?.original}
                              {d.event?.id && <Link className="ml-2 font-mono text-accent underline" href={`/trace?id=${encodeURIComponent(d.event.id)}`}>trace</Link>}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}

          {alertRows && (
            <section aria-label="Alert results" className="rounded-lg border border-line bg-panel p-3 text-sm">
              <b>{heading}</b>: {alertRows.length} alert{alertRows.length === 1 ? "" : "s"}
              <ul className="mt-2 space-y-1">
                {alertRows.map((a) => (
                  <li key={a.id}><Link className="font-mono text-xs text-accent underline" href={`/alerts?id=${encodeURIComponent(a.id)}`}>{a.id}</Link> <span className="text-xs text-mute">{a.status} · {a.technique} · {a.host ?? "?"} · {a.assignee ?? "unassigned"}</span></li>
                ))}
              </ul>
            </section>
          )}
        </section>

        <aside aria-label="Saved searches" className="space-y-2 rounded-lg border border-line bg-panel p-3 lg:self-start">
          <h2 className="text-sm font-semibold">Saved searches</h2>
          {saved.length === 0 ? <p className="text-xs text-mute">None yet. Run a search, name it, and save it.</p> : (
            <ul className="space-y-2">
              {saved.map((s) => (
                <li key={s.id} className="rounded border border-line bg-bg p-2">
                  <p className="flex items-center gap-1.5 text-sm font-medium">
                    {s.name}
                    {s.shared && <span title="Shared with all analysts" className="inline-flex items-center gap-0.5 text-xs text-mute"><Users size={12} aria-hidden /> shared</span>}
                  </p>
                  <p className="break-words text-xs text-mute">{s.kind === "logs" ? [s.query.q, s.query.from && `range ${s.query.from}`, s.query.format].filter(Boolean).join(" · ") || "all events" : `alerts ${s.query.status ?? ""} ${s.query.assignee ?? ""}`}</p>
                  <div className="mt-2 flex gap-2">
                    <button className={btn} onClick={() => runSaved(s)} aria-label={`Run ${s.name}`}><Play size={13} aria-hidden /> Run</button>
                    {(s.owner === actor || !actor) && (
                      <button className={btn} aria-label={`Delete ${s.name}`} onClick={async () => { await api.deleteSearch(s.id).catch((e) => setError(String(e.message ?? e))); loadSaved(); }}><Trash2 size={13} aria-hidden /></button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </aside>
      </div>
    </div>
  );
}
