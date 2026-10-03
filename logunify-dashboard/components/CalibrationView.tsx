"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { Calibration, CalibrationParams, NoisyAsset } from "@/lib/types-app";

const input = "w-full rounded border border-line bg-bg px-3 py-2 text-sm placeholder:text-mute";
const label = "mb-1 block text-xs font-medium uppercase tracking-wider text-mute";
const btn = "inline-flex items-center gap-1.5 rounded border border-line bg-panel2 px-3 py-2 text-sm hover:border-accent disabled:opacity-50";
const btnPrimary = "inline-flex items-center gap-1.5 rounded bg-accent px-3 py-2 text-sm font-medium text-bg hover:opacity-90 disabled:opacity-50";
const card = "rounded-lg border border-line bg-panel p-4";
const WINDOWS = [
  { v: "", l: "Everything held" },
  { v: "-1h", l: "Last hour" },
  { v: "-6h", l: "Last 6 hours" },
  { v: "-24h", l: "Last 24 hours" },
  { v: "-72h", l: "Last 3 days" },
  { v: "-7d", l: "Last 7 days" },
];
const pct = (x: number | null) => (x === null ? "n/a" : `${Math.round(x * 100)}%`);
const day = (s: number) => new Date(s * 1000).toLocaleDateString();

export default function CalibrationView() {
  const { can } = useSession();
  const [f, setF] = useState({ format: "", from: "", threshold: "", critical: "", capacity: "20", feedback: "30", synthetic: false });
  const [parsers, setParsers] = useState<string[]>([]);
  const [data, setData] = useState<Calibration | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [prefill, setPrefill] = useState<{ technique: string; asset: string } | null>(null);

  const params = useMemo<CalibrationParams>(
    () => ({ format: f.format, from: f.from, threshold: f.threshold, critical: f.critical.trim(), capacity_per_day: f.capacity, feedback_days: f.feedback, include_synthetic: f.synthetic ? "true" : "" }),
    [f],
  );
  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setData(await api.calibration(params));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [params]);

  useEffect(() => {
    load();
    api.parsers().then((r) => setParsers(r.items.map((p) => p.name))).catch(() => {});
    // initial load only; later runs are explicit (a replay walks every held event)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF((p) => ({ ...p, [k]: e.target.value }));
  const r = data?.replay;

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Alert calibration</h1>
      <p className="rounded border border-line bg-panel p-3 text-xs text-mute">
        Two kinds of evidence, never mixed. <b className="text-fg">Replay</b> re-runs the alert rules over the events this instance still holds and counts what each
        threshold <i>would</i> have produced; it cannot tell a false positive from a real one. <b className="text-fg">Feedback</b> is what your analysts decided when they
        closed alerts that did fire. Nothing on this page changes the threshold: that stays a reviewed configuration change. Only suppression rules (admin) take effect immediately.
      </p>

      <form
        aria-label="Calibration controls"
        className={`${card} grid gap-3 sm:grid-cols-2 lg:grid-cols-4`}
        onSubmit={(e) => {
          e.preventDefault();
          load();
        }}
      >
        <div>
          <label htmlFor="c-format" className={label}>Source (parser)</label>
          <select id="c-format" value={f.format} onChange={set("format")} className={input}>
            <option value="">All sources</option>
            {parsers.map((p) => <option key={p}>{p}</option>)}
          </select>
        </div>
        <div>
          <label htmlFor="c-from" className={label}>Replay window</label>
          <select id="c-from" value={f.from} onChange={set("from")} className={input}>
            {WINDOWS.map((w) => <option key={w.v} value={w.v}>{w.l}</option>)}
          </select>
        </div>
        <div>
          <label htmlFor="c-thr" className={label}>Candidate threshold (blank = configured {data?.configured.threshold ?? ""})</label>
          <input id="c-thr" type="number" min={0} max={0.99} step={0.01} value={f.threshold} onChange={set("threshold")} className={input} />
        </div>
        <div>
          <label htmlFor="c-crit" className={label}>Candidate critical techniques (CSV)</label>
          <input id="c-crit" value={f.critical} onChange={set("critical")} placeholder="blank = configured set" className={input} maxLength={300} />
        </div>
        <div>
          <label htmlFor="c-cap" className={label}>Analyst capacity (alerts / day)</label>
          <input id="c-cap" type="number" min={1} value={f.capacity} onChange={set("capacity")} className={input} />
        </div>
        <div>
          <label htmlFor="c-fb" className={label}>Feedback period</label>
          <select id="c-fb" value={f.feedback} onChange={set("feedback")} className={input}>
            {["7", "30", "90", "365"].map((d) => <option key={d} value={d}>{d} days</option>)}
          </select>
        </div>
        <div className="sm:col-span-2 lg:col-span-4">
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" className="mt-1" checked={f.synthetic} onChange={(e) => setF((p) => ({ ...p, synthetic: e.target.checked }))} />
            <span>
              Include events and alerts from <b>synthetic (test) sources</b>
              <span className="block text-xs text-mute">Off by default. A source tagged <code>synthetic</code> is a drill / test feed: it does not teach the model and is not your traffic, so calibrating on it measures the test, not your environment.</span>
            </span>
          </label>
        </div>
        <div className="flex items-end gap-2 sm:col-span-2">
          <button type="submit" className={btnPrimary} disabled={busy}>{busy ? "Replaying…" : "Run replay"}</button>
          <button type="button" className={btn} onClick={() => setF({ format: "", from: "", threshold: "", critical: "", capacity: "20", feedback: "30", synthetic: false })}>Reset</button>
        </div>
      </form>

      {error && <p role="alert" className="rounded border border-crit/40 bg-crit/10 p-3 text-sm text-crit">{error}</p>}
      {notice && <p role="status" className="rounded border border-ok/40 bg-ok/10 p-2 text-sm text-ok">{notice}</p>}
      {!data && !error && <p className="text-sm text-mute">Loading…</p>}

      {data && r && (
        <>
          <Confidence data={data} />
          <div className="grid gap-4 lg:grid-cols-2">
            <section aria-labelledby="hist-t" className={card}>
              <h2 id="hist-t" className="text-sm font-semibold">Anomaly score distribution</h2>
              <Histogram data={data} />
            </section>
            <section aria-labelledby="fun-t" className={card}>
              <h2 id="fun-t" className="text-sm font-semibold">Why alerts do or do not fire</h2>
              <Funnel funnel={r.funnel} />
            </section>
          </div>

          <section aria-labelledby="sweep-t" className={card}>
            <h2 id="sweep-t" className="text-sm font-semibold">Threshold sweep</h2>
            <p className="mt-1 text-sm" data-testid="recommendation">{r.recommendation.text}</p>
            <Sweep data={data} />
          </section>

          <section aria-labelledby="prev-t" className={card}>
            <h2 id="prev-t" className="text-sm font-semibold">
              Alerts the candidate would have raised: {r.preview.alerts} (from {r.preview.events} events{r.preview.suppressed ? `, ${r.preview.suppressed} held back by suppression rules` : ""})
            </h2>
            <p className="mb-2 text-xs text-mute">{r.note}</p>
            {r.preview.items.length === 0 ? <p className="text-sm text-mute">None in this scope.</p> : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] border-collapse text-left text-sm">
                  <caption className="sr-only">Alerts the candidate settings would have raised, oldest first</caption>
                  <thead className="bg-panel2 text-xs uppercase tracking-wider text-mute">
                    <tr><th scope="col" className="px-3 py-2">Time</th><th scope="col" className="px-3 py-2">Technique</th><th scope="col" className="px-3 py-2">Asset</th><th scope="col" className="px-3 py-2">Score</th><th scope="col" className="px-3 py-2">Sample message</th></tr>
                  </thead>
                  <tbody>
                    {r.preview.items.map((a, i) => (
                      <tr key={`${a.asset}-${a.at}-${i}`} className="border-t border-line align-top">
                        <td className="tabular whitespace-nowrap px-3 py-2 text-xs text-mute">{a.at ? new Date(a.at).toLocaleString() : "—"}</td>
                        <td className="px-3 py-2"><span className="font-mono text-xs">{a.technique}</span> <span className="text-mute">{a.technique_name}</span><span className="block text-xs text-mute">{a.basis}</span></td>
                        <td className="px-3 py-2 text-xs">{a.asset}{a.occurrences > 1 && <span className="ml-1 text-mute">×{a.occurrences}</span>}</td>
                        <td className="tabular px-3 py-2 text-xs">{a.score.toFixed(2)}</td>
                        <td className="break-words px-3 py-2 text-xs">{a.message}{a.event_id && <Link className="ml-2 font-mono text-accent underline" href={`/trace?id=${encodeURIComponent(a.event_id)}`}>trace</Link>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {r.preview.truncated && <p className="mt-1 text-xs text-mute">Showing the first {r.preview.items.length}.</p>}
              </div>
            )}
          </section>

          <Feedback data={data} canTune={can("admin")} onSuppress={(a) => setPrefill({ technique: a.technique, asset: a.asset })} />
          <Suppressions data={data} canTune={can("admin")} prefill={prefill} onChanged={(msg) => { setNotice(msg); load(); }} onError={setError} />
        </>
      )}
    </div>
  );
}

// ------------------------------------------------------------------------------------------------------------------------
function Confidence({ data }: { data: Calibration }) {
  const c = data.replay.confidence;
  const tone = c.level === "high" ? "border-ok/40 bg-ok/10 text-ok" : c.level === "medium" ? "border-warn/40 bg-warn/10 text-warn" : "border-crit/40 bg-crit/10 text-crit";
  const cov = data.replay.coverage;
  return (
    <div className="space-y-1">
      <p role="status" data-testid="confidence" className={`rounded border p-3 text-sm ${tone}`}>
        <b className="uppercase">{c.level} confidence.</b> {c.why}.
      </p>
      <p className="text-xs text-mute">
        {cov.events_in_scope.toLocaleString()} of {cov.events_held.toLocaleString()} held events in scope (buffer {cov.buffer.toLocaleString()}).
        {cov.synthetic_excluded > 0 && <b className="text-warn"> {cov.synthetic_excluded.toLocaleString()} event(s) from synthetic test sources are left out. </b>} {cov.note}. Tagging threshold:{" "}
        {data.configured.tagging_threshold ?? "?"}: events below it carry no technique, so thresholds under it behave like it.
      </p>
    </div>
  );
}

function Histogram({ data }: { data: Calibration }) {
  const h = data.replay.histogram;
  const W = 520, H = 150, L = 8, B = 22, bw = (W - L * 2) / h.length;
  const max = Math.max(1, ...h.map((b) => Math.log1p(b.count)));
  const x = (v: number) => L + v * (W - L * 2);
  const cur = data.configured.threshold, cand = data.candidate.threshold;
  const total = h.reduce((a, b) => a + b.count, 0);
  const above = (t: number) => h.filter((b) => b.from >= t - 1e-9).reduce((a, b) => a + b.count, 0);
  return (
    <div>
      <p className="text-xs text-mute">
        {total.toLocaleString()} scored events. Bar height is on a log scale so the rare high scores stay visible. p50 {data.replay.percentiles.p50 ?? "–"}, p99 {data.replay.percentiles.p99 ?? "–"}, max {data.replay.percentiles.max ?? "–"}.
      </p>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Histogram of anomaly scores. ${above(cur)} events score at or above the configured threshold ${cur}.`} className="mt-2 w-full">
        {h.map((b, i) => {
          const bh = b.count ? Math.max(2, (Math.log1p(b.count) / max) * (H - B - 10)) : 0;
          return (
            <rect key={i} x={L + i * bw + 1} y={H - B - bh} width={bw - 2} height={bh} rx={2} className="fill-accent/80">
              <title>{`${b.from.toFixed(2)}–${b.to.toFixed(2)}: ${b.count.toLocaleString()} events`}</title>
            </rect>
          );
        })}
        <line x1={L} x2={W - L} y1={H - B} y2={H - B} className="stroke-line" />
        {[0, 0.25, 0.5, 0.75, 1].map((t) => <text key={t} x={x(t)} y={H - 6} textAnchor={t === 0 ? "start" : t === 1 ? "end" : "middle"} className="fill-mute text-[10px]">{t}</text>)}
        <line x1={x(cur)} x2={x(cur)} y1={4} y2={H - B} strokeDasharray="4 3" strokeWidth={1.5} className="stroke-warn" />
        <text x={Math.min(x(cur) + 4, W - 110)} y={12} className="fill-warn text-[10px]">configured {cur}</text>
        {Math.abs(cand - cur) > 1e-9 && (
          <>
            <line x1={x(cand)} x2={x(cand)} y1={4} y2={H - B} strokeWidth={1.5} className="stroke-ok" />
            <text x={Math.min(x(cand) + 4, W - 100)} y={26} className="fill-ok text-[10px]">candidate {cand}</text>
          </>
        )}
      </svg>
      <details className="mt-1 text-xs text-mute">
        <summary className="cursor-pointer">Show as a table</summary>
        <table className="mt-1 w-full text-left">
          <caption className="sr-only">Events per score bucket</caption>
          <thead><tr><th scope="col" className="pr-4">Score</th><th scope="col">Events</th></tr></thead>
          <tbody>{h.filter((b) => b.count).map((b) => <tr key={b.from}><td className="pr-4 tabular">{b.from.toFixed(2)}–{b.to.toFixed(2)}</td><td className="tabular">{b.count}</td></tr>)}</tbody>
        </table>
      </details>
    </div>
  );
}

function Funnel({ funnel }: { funnel: { step: string; count: number; why: string }[] }) {
  const top = Math.max(1, funnel[0]?.count ?? 1);
  // the step where the count falls the most (relative to the previous step) is the first thing to look at
  let worst = -1, worstDrop = 0;
  funnel.forEach((s, i) => {
    if (i === 0 || funnel[i - 1].count === 0) return;
    const drop = 1 - s.count / funnel[i - 1].count;
    if (drop > worstDrop) { worstDrop = drop; worst = i; }
  });
  return (
    <ol className="mt-2 space-y-2">
      {funnel.map((s, i) => (
        <li key={s.step}>
          <div className="flex items-baseline justify-between gap-2 text-sm">
            <span>{s.step}{i === worst && worstDrop > 0.5 && <span className="ml-2 rounded border border-warn/40 px-1.5 text-[11px] text-warn">biggest drop</span>}</span>
            <span className="tabular font-mono text-xs">{s.count.toLocaleString()}</span>
          </div>
          <div className="mt-0.5 h-2 rounded bg-panel2" aria-hidden>
            <div className="h-2 rounded bg-accent/80" style={{ width: `${s.count ? Math.max(1.5, (s.count / top) * 100) : 0}%` }} />
          </div>
          <p className="mt-0.5 text-[11px] text-mute">{s.why}</p>
        </li>
      ))}
    </ol>
  );
}

function Sweep({ data }: { data: Calibration }) {
  const rows = data.replay.sweep;
  const rec = data.replay.recommendation.threshold;
  const max = Math.max(1, ...rows.map((x) => x.alerts));
  return (
    <div className="mt-2 overflow-x-auto">
      <table className="w-full min-w-[560px] border-collapse text-left text-sm">
        <caption className="sr-only">Alerts the candidate critical set would have produced at each threshold over the replay window</caption>
        <thead className="bg-panel2 text-xs uppercase tracking-wider text-mute">
          <tr><th scope="col" className="px-3 py-2">Threshold</th><th scope="col" className="px-3 py-2">Alerts</th><th scope="col" className="px-3 py-2">Per day</th><th scope="col" className="px-3 py-2">Events</th><th scope="col" className="px-3 py-2">Techniques</th><th scope="col" className="px-3 py-2">Note</th></tr>
        </thead>
        <tbody>
          {rows.map((x) => {
            const isCur = Math.abs(x.threshold - data.configured.threshold) < 1e-9;
            const isRec = rec !== null && Math.abs(x.threshold - rec) < 1e-9;
            return (
              <tr key={x.threshold} className={`border-t border-line ${isCur ? "bg-accent/10" : ""}`}>
                <th scope="row" className="tabular px-3 py-2 font-mono text-xs font-normal">{x.threshold.toFixed(2)}</th>
                <td className="px-3 py-2">
                  <span className="tabular mr-2 inline-block w-8 text-right font-mono text-xs">{x.alerts}</span>
                  <span className="inline-block h-2 rounded bg-accent/80 align-middle" style={{ width: `${(x.alerts / max) * 80}px` }} aria-hidden />
                </td>
                <td className="tabular px-3 py-2 text-xs">{x.alerts_per_day ?? "n/a"}</td>
                <td className="tabular px-3 py-2 text-xs">{x.events}{x.suppressed ? <span className="text-mute"> (+{x.suppressed} suppressed)</span> : null}</td>
                <td className="px-3 py-2 text-xs text-mute">{Object.entries(x.techniques).map(([t, n]) => `${t}×${n}`).join(", ") || "—"}</td>
                <td className="px-3 py-2 text-xs">{[isCur && "configured", isRec && "suggested"].filter(Boolean).join(" · ")}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Feedback({ data, canTune, onSuppress }: { data: Calibration; canTune: boolean; onSuppress: (a: NoisyAsset) => void }) {
  const fb = data.feedback;
  const maxDay = Math.max(1, ...fb.per_day.map((d) => d.alerts));
  return (
    <section aria-labelledby="fb-t" className={`${card} space-y-3`}>
      <h2 id="fb-t" className="text-sm font-semibold">Analyst feedback: last {fb.since_days} days</h2>
      {fb.alerts_total === 0 ? (
        <p className="text-sm text-mute">No alerts were raised in this period, so there is no feedback yet. Close real alerts with an honest resolution (false positive / not reportable / resolved) and this fills in.</p>
      ) : (
        <>
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat k="Alerts raised" v={String(fb.alerts_total)} />
            <Stat k="False-positive rate" v={pct(fb.false_positive_rate)} sub={`${fb.resolutions.false_positive ?? 0} of ${fb.closed} closed`} />
            <Stat k="Reported on time" v={pct(fb.cert_in.on_time_rate)} sub={`${fb.cert_in.on_time} of ${fb.cert_in.reported} reported to CERT-In`} />
            <Stat k="Running now" v={String(fb.cert_in.active_now)} sub={fb.cert_in.overdue_now ? `${fb.cert_in.overdue_now} OVERDUE` : "none overdue"} />
          </dl>
          {fb.synthetic_alerts_excluded > 0 && <p className="text-xs text-warn">{fb.synthetic_alerts_excluded} alert(s) raised by synthetic test sources are not counted here.</p>}
          {fb.closed < 20 && <p className="text-xs text-warn">Only {fb.closed} closed alert(s): rates this small swing wildly. Treat them as hints, not measurements.</p>}
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-sm">
                <caption className="mb-1 text-left text-xs uppercase tracking-wider text-mute">By technique</caption>
                <thead className="text-xs text-mute"><tr><th scope="col" className="py-1 pr-2">Technique</th><th scope="col">Closed</th><th scope="col">False pos.</th><th scope="col">Not rep.</th><th scope="col">Resolved</th><th scope="col">FP rate</th></tr></thead>
                <tbody>{fb.techniques.map((t) => <tr key={t.technique} className="border-t border-line"><th scope="row" className="py-1 pr-2 font-mono text-xs font-normal">{t.technique}</th><td className="tabular">{t.closed}</td><td className="tabular">{t.false_positive}</td><td className="tabular">{t.not_reportable}</td><td className="tabular">{t.resolved}</td><td className="tabular">{pct(t.fp_rate)}</td></tr>)}</tbody>
              </table>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-sm">
                <caption className="mb-1 text-left text-xs uppercase tracking-wider text-mute">Noisiest assets</caption>
                <thead className="text-xs text-mute"><tr><th scope="col" className="py-1 pr-2">Technique · asset</th><th scope="col">False pos.</th><th scope="col">Real</th><th scope="col"><span className="sr-only">Action</span></th></tr></thead>
                <tbody>
                  {fb.noisiest_assets.map((a) => (
                    <tr key={`${a.technique}-${a.asset}`} className="border-t border-line">
                      <td className="py-1 pr-2 text-xs"><span className="font-mono">{a.technique}</span> · {a.asset}</td>
                      <td className="tabular">{a.false_positive}</td>
                      <td className="tabular">{a.resolved}</td>
                      <td>{a.candidate ? (canTune ? <button className={btn} onClick={() => onSuppress(a)} aria-label={`Prepare a suppression for ${a.technique} on ${a.asset}`}>Suppress…</button> : <span className="text-xs text-warn">candidate (admin)</span>) : null}</td>
                    </tr>
                  ))}
                  {fb.noisiest_assets.length === 0 && <tr><td colSpan={4} className="py-2 text-xs text-mute">No asset has false positives yet.</td></tr>}
                </tbody>
              </table>
              <p className="mt-1 text-[11px] text-mute">A “candidate” has 3+ false positives and never a real incident. Suppress only after a person confirmed the cause.</p>
            </div>
          </div>
          <figure>
            <figcaption className="mb-1 text-xs uppercase tracking-wider text-mute">Alerts raised per day (IST): your analysts&apos; workload</figcaption>
            <div className="flex h-20 items-end gap-1" role="img" aria-label={`Alerts per day: ${fb.per_day.map((d) => `${d.day} ${d.alerts}`).join(", ")}`}>
              {fb.per_day.map((d) => (
                <div key={d.day} className="flex flex-1 flex-col items-center justify-end" title={`${d.day}: ${d.alerts} alerts`}>
                  <span className="tabular text-[10px] text-mute">{d.alerts}</span>
                  <div className="w-full max-w-6 rounded-t bg-accent/80" style={{ height: `${Math.max(3, (d.alerts / maxDay) * 52)}px` }} />
                </div>
              ))}
            </div>
          </figure>
        </>
      )}
    </section>
  );
}

function Stat({ k, v, sub }: { k: string; v: string; sub?: string }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wider text-mute">{k}</dt>
      <dd className="text-xl font-semibold tabular">{v}</dd>
      {sub && <dd className="text-xs text-mute">{sub}</dd>}
    </div>
  );
}

function Suppressions({ data, canTune, prefill, onChanged, onError }: {
  data: Calibration; canTune: boolean; prefill: { technique: string; asset: string } | null; onChanged: (m: string) => void; onError: (m: string) => void;
}) {
  const [f, setF] = useState({ technique: "", asset: "", reason: "", days: "30" });
  useEffect(() => {
    if (prefill) setF((p) => ({ ...p, ...prefill, reason: p.reason }));
  }, [prefill]);
  const fail = (e: unknown) => onError(e instanceof Error ? e.message : String(e));
  return (
    <section aria-labelledby="sup-t" className={`${card} space-y-3`}>
      <h2 id="sup-t" className="text-sm font-semibold">Suppression rules</h2>
      <p className="text-xs text-mute">
        A rule stops new alerts for one technique on assets matching a pattern, for at most 90 days. The events are still stored and traceable; only the alert is skipped, and every
        hit is counted here. Rules cannot be edited or deleted, only revoked, so the history stays. A suppressed incident does not start a CERT-In clock: use sparingly.
      </p>
      {data.suppressions.length === 0 ? <p className="text-sm text-mute">No suppression rules.</p> : (
        <ul className="space-y-2">
          {data.suppressions.map((s) => (
            <li key={s.id} className={`rounded border p-2 text-sm ${s.active ? "border-warn/40" : "border-line text-mute"}`}>
              <p>
                <span className="font-mono text-xs">{s.id}</span> · <b>{s.technique}</b> on <b>{s.asset}</b>{" "}
                <span className="rounded border border-line px-1.5 text-[11px]">{s.revoked_at ? "revoked" : s.active ? "active" : "expired"}</span>
              </p>
              <p className="text-xs">{s.reason} · by {s.created_by} · until {day(s.expires_at)} · {s.hits} alert(s) suppressed since the last restart</p>
              {s.active && canTune && <button className={`${btn} mt-1`} onClick={() => api.revokeSuppression(s.id).then(() => onChanged(`Revoked ${s.id}.`)).catch(fail)}>Revoke</button>}
            </li>
          ))}
        </ul>
      )}
      {canTune ? (
        <form
          aria-label="New suppression rule"
          className="grid gap-3 rounded border border-line bg-bg p-3 sm:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            api.createSuppression({ technique: f.technique, asset: f.asset, reason: f.reason, days: Number(f.days) })
              .then((r) => { onChanged(`Created ${r.id}: ${r.technique} on ${r.asset}.`); setF({ technique: "", asset: "", reason: "", days: "30" }); })
              .catch(fail);
          }}
        >
          <div>
            <label htmlFor="s-tech" className={label}>Technique (e.g. T1070, or * for any)</label>
            <input id="s-tech" required value={f.technique} onChange={(e) => setF({ ...f, technique: e.target.value })} className={input} maxLength={12} />
          </div>
          <div>
            <label htmlFor="s-asset" className={label}>Asset pattern (e.g. backup-*)</label>
            <input id="s-asset" required value={f.asset} onChange={(e) => setF({ ...f, asset: e.target.value })} className={input} maxLength={100} />
          </div>
          <div className="sm:col-span-2">
            <label htmlFor="s-reason" className={label}>Reason (audited, 10+ characters)</label>
            <input id="s-reason" required minLength={10} value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })} className={input} maxLength={500} />
          </div>
          <div>
            <label htmlFor="s-days" className={label}>Expires after (days, max 90)</label>
            <input id="s-days" type="number" min={1} max={90} value={f.days} onChange={(e) => setF({ ...f, days: e.target.value })} className={input} />
          </div>
          <div className="flex items-end"><button type="submit" className={btnPrimary}>Create rule</button></div>
        </form>
      ) : <p className="text-xs text-mute">Creating or revoking rules needs the admin role.</p>}
    </section>
  );
}
