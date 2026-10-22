"use client";

import { AlertTriangle, CheckCircle2, ClipboardCopy, Download, Link2, Send, ShieldAlert, XCircle } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useActor } from "@/lib/session";
import type { AlertEvent, AlertNote, AlertStatus, AlertSummary, AlertView, CertReport } from "@/lib/types-app";
import { usePoll } from "@/lib/usePoll";
import { StatusPill } from "./Badges";
import Countdown from "./Countdown";

const FILTERS = [
  { v: "active", l: "Active" },
  { v: "open", l: "Open" },
  { v: "acknowledged", l: "Acknowledged" },
  { v: "reported", l: "Reported" },
  { v: "closed", l: "Closed" },
  { v: "all", l: "All" },
] as const;

const OWNERS = [
  { v: "", l: "Anyone" },
  { v: "me", l: "Mine" },
  { v: "unassigned", l: "Unassigned" },
] as const;

const TONE: Record<AlertStatus, "crit" | "warn" | "ok" | "mute"> = { open: "crit", acknowledged: "warn", reported: "ok", closed: "mute" };
const input = "w-full rounded border border-line bg-bg px-3 py-2 text-sm placeholder:text-mute";
const label = "mb-1 block text-xs font-medium uppercase tracking-wider text-mute";
const btn = "inline-flex items-center gap-1.5 rounded border border-line bg-panel2 px-3 py-2 text-sm hover:border-accent disabled:opacity-50";
const btnPrimary = "inline-flex items-center gap-1.5 rounded bg-accent px-3 py-2 text-sm font-medium text-bg hover:opacity-90 disabled:opacity-50";

const fmtEpoch = (s: number) => new Date(s * 1000).toLocaleString();

export default function AlertsView() {
  const router = useRouter();
  const params = useSearchParams();
  const selected = params.get("id");
  const actor = useActor();
  const [filter, setFilter] = useState<string>("active");
  const [owner, setOwner] = useState<string>("");
  const assignee = owner === "me" ? actor : owner;
  const { data, error } = usePoll((s) => api.alerts(filter, s, assignee), 5000, true, 0);
  const items = data?.items ?? [];

  const select = (id: string | null) => router.replace(id ? `/alerts?id=${encodeURIComponent(id)}` : "/alerts");

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="mr-auto text-lg font-semibold">Alerts · CERT-In 6-hour workflow</h1>
        <div role="group" aria-label="Filter by owner" className="flex flex-wrap gap-1">
          {OWNERS.map((o) => (
            <button
              key={o.v}
              onClick={() => setOwner(o.v)}
              aria-pressed={owner === o.v}
              disabled={o.v === "me" && !actor}
              className={`rounded border px-3 py-1.5 text-sm disabled:opacity-40 ${owner === o.v ? "border-accent bg-accent/15 text-accent" : "border-line text-mute hover:text-fg"}`}
            >
              {o.l}
            </button>
          ))}
        </div>
        <div role="group" aria-label="Filter by status" className="flex flex-wrap gap-1">
          {FILTERS.map((f) => (
            <button
              key={f.v}
              onClick={() => setFilter(f.v)}
              aria-pressed={filter === f.v}
              className={`rounded border px-3 py-1.5 text-sm ${filter === f.v ? "border-accent bg-accent/15 text-accent" : "border-line text-mute hover:text-fg"}`}
            >
              {f.l}
            </button>
          ))}
        </div>
      </div>
      <p className="rounded border border-line bg-panel p-3 text-xs text-mute">
        LogUnify drafts the incident report and keeps the clock. <b className="text-fg">It never files with CERT-In for you</b>: you submit by email, phone
        or fax and then record it here. Partial information is acceptable within 6 hours (FAQ Q30).
      </p>

      {error && !data && (
        <p role="alert" className="rounded border border-crit/40 bg-crit/10 p-3 text-sm text-crit">
          Could not load alerts: {error}
        </p>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <section className="rounded-lg border border-line bg-panel" aria-label="Alert list">
          {items.length === 0 ? (
            <p className="px-4 py-12 text-center text-sm text-mute">
              {data ? (filter === "active" ? "No active alerts: nothing is running against the 6-hour clock." : "No alerts match this filter.") : "Loading…"}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[560px] border-collapse text-left text-sm">
                <caption className="sr-only">Alerts, newest first. Select one to open its CERT-In workflow.</caption>
                <thead className="bg-panel2 text-xs uppercase tracking-wider text-mute">
                  <tr>
                    <th scope="col" className="px-3 py-2 font-medium">Alert</th>
                    <th scope="col" className="px-3 py-2 font-medium">Clock</th>
                    <th scope="col" className="px-3 py-2 font-medium">Status</th>
                    <th scope="col" className="px-3 py-2 font-medium">Owner</th>
                    <th scope="col" className="px-3 py-2 font-medium">Technique</th>
                    <th scope="col" className="hidden px-3 py-2 font-medium xl:table-cell">Where</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((a: AlertSummary) => (
                    <tr key={a.id} className={`border-t border-line ${selected === a.id ? "bg-accent/10" : "hover:bg-panel2/60"}`}>
                      <td className="px-3 py-2">
                        <button onClick={() => select(a.id)} aria-current={selected === a.id ? "true" : undefined} className="font-mono text-xs text-accent underline-offset-2 hover:underline">
                          {a.id}
                        </button>
                        {a.occurrences > 1 && <span className="ml-2 text-xs text-mute">×{a.occurrences}</span>}
                        {a.synthetic && <span title="Raised by a synthetic (test) source: not a real incident" className="ml-2 rounded border border-warn/50 px-1.5 text-[11px] text-warn">TEST</span>}
                      </td>
                      <td className="px-3 py-2"><Countdown dueAt={a.due_at} active={a.status === "open" || a.status === "acknowledged"} /></td>
                      <td className="px-3 py-2"><StatusPill tone={TONE[a.status]}>{a.status}</StatusPill></td>
                      <td className="px-3 py-2 text-xs">{a.assignee ?? <span className="text-mute">unassigned</span>}</td>
                      <td className="px-3 py-2">
                        <span className="font-mono text-xs">{a.technique}</span> <span className="text-mute">{a.technique_name}</span>
                        <span className="ml-2 tabular text-xs text-mute">{a.score.toFixed(2)}</span>
                      </td>
                      <td className="hidden px-3 py-2 text-xs text-mute xl:table-cell">{a.host ?? a.affected_ip ?? a.remote_ip ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section aria-label="Alert detail" className="min-w-0">
          {selected ? <AlertDetail key={selected} id={selected} onClose={() => select(null)} /> : (
            <p className="rounded-lg border border-dashed border-line px-4 py-16 text-center text-sm text-mute">Select an alert to work on it.</p>
          )}
        </section>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------------------------------------------------------------
function AlertDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const actor = useActor();
  const [view, setView] = useState<AlertView | null>(null);
  const [report, setReport] = useState<CertReport | null>(null);
  const [events, setEvents] = useState<AlertEvent[]>([]);
  const [notes, setNotes] = useState<AlertNote[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [v, r, e, n] = await Promise.all([api.alert(id), api.alertReport(id), api.alertEvents(id), api.alertNotes(id)]);
      setView(v);
      setReport(r);
      setEvents(e.items);
      setNotes(n.items);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [id]);

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  async function act(fn: () => Promise<unknown>, done: string) {
    setNotice(null);
    try {
      await fn();
      setNotice(done);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  if (error && !view) {
    return (
      <p role="alert" className="rounded-lg border border-crit/40 bg-crit/10 p-4 text-sm text-crit">
        {error}
      </p>
    );
  }
  if (!view || !report) return <p className="rounded-lg border border-line p-6 text-sm text-mute">Loading alert…</p>;

  const a = view.summary;
  const running = a.status === "open" || a.status === "acknowledged";
  const gaps = report.completeness;

  return (
    <article className="space-y-4 rounded-lg border border-line bg-panel p-4" aria-labelledby="alert-title">
      <header className="flex flex-wrap items-start gap-3">
        <div className="mr-auto min-w-0">
          <h2 id="alert-title" className="break-all font-mono text-sm font-semibold">{a.id}</h2>
          <p className="mt-1 text-sm">
            <ShieldAlert size={14} className="mr-1 inline text-crit" aria-hidden />
            {a.technique} {a.technique_name} · score {view.trigger.score.toFixed(2)} (threshold {view.trigger.threshold}) · {view.trigger.tactic}
          </p>
          <p className="mt-0.5 text-xs text-mute">Rule basis: {view.trigger.basis}</p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <StatusPill tone={TONE[a.status]}>{a.status}</StatusPill>
          <Countdown dueAt={a.due_at} active={running} />
        </div>
        <button onClick={onClose} className="rounded border border-line px-2 py-1 text-xs text-mute hover:text-fg lg:hidden">Close panel</button>
      </header>

      {notice && <p role="status" className="rounded border border-ok/40 bg-ok/10 p-2 text-sm text-ok">{notice}</p>}
      {error && <p role="alert" className="rounded border border-crit/40 bg-crit/10 p-2 text-sm text-crit">{error}</p>}
      {a.synthetic && (
        <p role="status" className="rounded border border-warn/40 bg-warn/10 p-2 text-sm text-warn">
          This alert came from a <b>synthetic (test) source</b>: it is a drill, not an incident. Close it as “not reportable” with that reason; do not report it to CERT-In.
        </p>
      )}
      {a.overdue && running && (
        <p role="alert" className="flex items-center gap-2 rounded border border-crit/50 bg-crit/10 p-2 text-sm text-crit">
          <AlertTriangle size={16} aria-hidden /> The 6-hour window has passed. Report now with whatever you have; late is still better than never.
        </p>
      )}

      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-3">
        <Fact k="Remote IP" v={a.remote_ip} />
        <Fact k="Affected IP" v={a.affected_ip} />
        <Fact k="Host" v={a.host} />
        <Fact k="Occurrences" v={String(a.occurrences)} />
        <Fact k="Notification" v={a.notification} />
        <Fact k="Report due (IST)" v={report.deadline.report_due_at.ist} />
      </dl>
      {view.evidence.event_id && (
        <p className="text-sm">
          <Link2 size={14} className="mr-1 inline" aria-hidden />
          Evidence record: <Link className="font-mono text-xs text-accent underline" href={`/trace?id=${encodeURIComponent(view.evidence.event_id)}`}>{view.evidence.event_id}</Link>
          <span className="ml-2 text-xs text-mute">SHA-256 {view.evidence.record_sha256?.slice(0, 12)}…</span>
        </p>
      )}

      <Workflow view={view} actor={actor} act={act} />

      <Assignment view={view} actor={actor} act={act} />
      <Notes id={id} notes={notes} actor={actor} act={act} />

      <section aria-labelledby="gaps-title" className="space-y-2">
        <h3 id="gaps-title" className="text-sm font-semibold">CERT-In report: what is still missing</h3>
        <Gap title="You must supply" items={gaps.needs_analyst} tone="text-warn" />
        <Gap title="Needs administrator configuration" items={gaps.needs_configuration} tone="text-crit" />
        <Gap title="Derived by LogUnify: please confirm" items={gaps.to_confirm} tone="text-accent" />
        <p className="text-xs text-mute">{gaps.note}</p>
        {report.data_quality_warnings?.map((w) => <p key={w} className="text-xs text-warn">⚠ {w}</p>)}
        {running || a.status === "reported" ? <DetailsForm id={id} actor={actor} act={act} /> : null}
      </section>

      <ReportActions id={id} email={report.deadline.submit_via.email} phone={report.deadline.submit_via.phone} />

      <section aria-labelledby="tl-title">
        <h3 id="tl-title" className="mb-2 text-sm font-semibold">Timeline (append-only)</h3>
        <ol className="space-y-1.5 border-l border-line pl-3 text-sm">
          {events.map((e) => (
            <li key={e.seq}>
              <span className="tabular text-xs text-mute">{fmtEpoch(e.at)}</span> <b>{e.kind.replace(/_/g, " ")}</b>
              <span className="text-mute"> · {e.actor}</span>
              <EventData data={e.data} />
            </li>
          ))}
        </ol>
      </section>
    </article>
  );
}

function Fact({ k, v }: { k: string; v: string | null | undefined }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wider text-mute">{k}</dt>
      <dd className="break-words">{v || "—"}</dd>
    </div>
  );
}

function Gap({ title, items, tone }: { title: string; items: { field: string; label: string }[]; tone: string }) {
  if (!items.length) return null;
  return (
    <div>
      <p className={`text-xs font-medium ${tone}`}>{title} ({items.length})</p>
      <ul className="ml-4 list-disc text-xs text-mute">
        {items.map((i) => <li key={i.field}>{i.label}</li>)}
      </ul>
    </div>
  );
}

function EventData({ data }: { data: Record<string, unknown> }) {
  const bits = Object.entries(data).filter(([, v]) => v !== null && v !== "" && typeof v !== "object").slice(0, 4);
  if (!bits.length) return null;
  return <span className="text-xs text-mute"> ({bits.map(([k, v]) => `${k}: ${String(v)}`).join(", ")})</span>;
}

// ---- workflow actions ---------------------------------------------------------------------------------------------------
type Act = (fn: () => Promise<unknown>, done: string) => Promise<void>;

function Workflow({ view, actor, act }: { view: AlertView; actor: string; act: Act }) {
  const s = view.summary;
  const [mode, setMode] = useState<"ack" | "report" | "close" | null>(null);
  const [note, setNote] = useState("");
  const [via, setVia] = useState("email");
  const [reference, setReference] = useState("");
  const [resolution, setResolution] = useState("resolved");
  const steps: { key: AlertStatus; text: string; at?: number; by?: string }[] = [
    { key: "open", text: "Detected" },
    { key: "acknowledged", text: "Acknowledged", at: view.ack?.at, by: view.ack?.by },
    { key: "reported", text: "Reported to CERT-In", at: view.reported?.at, by: view.reported?.by },
    { key: "closed", text: "Closed", at: view.closed?.at, by: view.closed?.by },
  ];
  const reached = (k: AlertStatus) => ({ open: 0, acknowledged: 1, reported: 2, closed: 3 })[k] <= ({ open: 0, acknowledged: 1, reported: 2, closed: 3 })[s.status];

  return (
    <section aria-labelledby="wf-title" className="space-y-3">
      <h3 id="wf-title" className="text-sm font-semibold">Workflow</h3>
      <ol className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {steps.map((st) => (
          <li key={st.key} className={`rounded border p-2 text-xs ${reached(st.key) ? "border-ok/40 bg-ok/10" : "border-line text-mute"}`} aria-current={s.status === st.key ? "step" : undefined}>
            <span className="flex items-center gap-1 font-medium">
              {reached(st.key) ? <CheckCircle2 size={13} className="text-ok" aria-hidden /> : <XCircle size={13} aria-hidden />} {st.text}
            </span>
            {st.at && <span className="block text-mute">{fmtEpoch(st.at)} · {st.by}</span>}
          </li>
        ))}
      </ol>

      {s.status !== "closed" && (
        <div className="flex flex-wrap gap-2">
          {s.status === "open" && <button className={btnPrimary} onClick={() => setMode(mode === "ack" ? null : "ack")}>Acknowledge</button>}
          {(s.status === "open" || s.status === "acknowledged") && (
            <button className={btn} onClick={() => setMode(mode === "report" ? null : "report")}><Send size={14} aria-hidden /> Record: reported to CERT-In</button>
          )}
          <button className={btn} onClick={() => setMode(mode === "close" ? null : "close")}>Close alert</button>
        </div>
      )}

      {mode && (
        <form
          className="space-y-3 rounded border border-line bg-bg p-3"
          onSubmit={(e) => {
            e.preventDefault();
            const done = () => { setMode(null); setNote(""); setReference(""); };
            if (mode === "ack") act(() => api.alertAck(s.id, actor, note), "Acknowledged.").then(done);
            if (mode === "report") act(() => api.alertReported(s.id, actor, via, reference, note), "Recorded as reported to CERT-In.").then(done);
            if (mode === "close") act(() => api.alertClose(s.id, actor, resolution, note), "Alert closed.").then(done);
          }}
        >
          <p className="text-xs text-mute">
            {mode === "report"
              ? "Only record this AFTER you have sent the report to CERT-In yourself (email incident@cert-in.org.in, phone 1800-11-4949). LogUnify does not send it."
              : mode === "close"
                ? "Closing stops the clock and cannot be undone. Choose why."
                : "Acknowledging records that a person has taken ownership. It does not stop the clock."}
          </p>
          {mode === "report" && (
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label htmlFor="via" className={label}>Sent via</label>
                <select id="via" value={via} onChange={(e) => setVia(e.target.value)} className={input}>
                  {["email", "phone", "fax", "portal", "other"].map((v) => <option key={v}>{v}</option>)}
                </select>
              </div>
              <div>
                <label htmlFor="ref" className={label}>CERT-In reference (if any)</label>
                <input id="ref" value={reference} onChange={(e) => setReference(e.target.value)} className={input} maxLength={200} />
              </div>
            </div>
          )}
          {mode === "close" && (
            <div>
              <label htmlFor="res" className={label}>Resolution</label>
              <select id="res" value={resolution} onChange={(e) => setResolution(e.target.value)} className={input}>
                <option value="resolved">Resolved</option>
                <option value="false_positive">False positive</option>
                <option value="not_reportable">Not reportable</option>
              </select>
            </div>
          )}
          <div>
            <label htmlFor="note" className={label}>Note (recorded in the audit trail)</label>
            <textarea id="note" value={note} onChange={(e) => setNote(e.target.value)} rows={2} maxLength={1000} className={input} />
          </div>
          <div className="flex gap-2">
            <button type="submit" className={mode === "close" ? "rounded bg-crit px-3 py-2 text-sm font-medium text-bg" : btnPrimary}>
              {mode === "ack" ? "Confirm acknowledge" : mode === "report" ? "Confirm: it was sent" : "Confirm close"}
            </button>
            <button type="button" className={btn} onClick={() => setMode(null)}>Cancel</button>
          </div>
        </form>
      )}
    </section>
  );
}

function Assignment({ view, actor, act }: { view: AlertView; actor: string; act: Act }) {
  const s = view.summary;
  const [to, setTo] = useState("");
  const closed = s.status === "closed";
  return (
    <section aria-labelledby="own-title" className="space-y-2">
      <h3 id="own-title" className="text-sm font-semibold">Owner</h3>
      <p className="text-sm">
        {view.assignee ? <>Assigned to <b>{view.assignee.to}</b> <span className="text-xs text-mute">by {view.assignee.by}, {fmtEpoch(view.assignee.at)}</span></> : <span className="text-mute">Nobody owns this alert yet.</span>}
      </p>
      {!closed && (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (to.trim()) act(() => api.alertAssign(s.id, actor, to.trim()), `Assigned to ${to.trim()}.`).then(() => setTo(""));
          }}
        >
          <div className="min-w-[10rem] flex-1">
            <label htmlFor="assign-to" className={label}>Assign to (username or email)</label>
            <input id="assign-to" value={to} onChange={(e) => setTo(e.target.value)} className={input} maxLength={100} />
          </div>
          <button type="submit" className={btn} disabled={!to.trim()}>Assign</button>
          {actor && view.assignee?.to !== actor && (
            <button type="button" className={btnPrimary} onClick={() => act(() => api.alertAssign(s.id, actor, actor), "Assigned to you.")}>Take it</button>
          )}
          {view.assignee && <button type="button" className={btn} onClick={() => act(() => api.alertAssign(s.id, actor, null), "Owner cleared.")}>Unassign</button>}
        </form>
      )}
      <p className="text-xs text-mute">Assigning notifies your configured channels (and mails the assignee if it is an email address). It does not change the CERT-In clock.</p>
    </section>
  );
}

function Notes({ id, notes, actor, act }: { id: string; notes: AlertNote[]; actor: string; act: Act }) {
  const [text, setText] = useState("");
  return (
    <section aria-labelledby="notes-title" className="space-y-2">
      <h3 id="notes-title" className="text-sm font-semibold">Investigation notes ({notes.length})</h3>
      {notes.length === 0 ? <p className="text-xs text-mute">No notes yet. Notes are permanent: they cannot be edited or deleted.</p> : (
        <ul className="space-y-2">
          {notes.map((n) => (
            <li key={n.seq} className="rounded border border-line bg-bg p-2 text-sm">
              <p className="whitespace-pre-wrap break-words">{n.text}</p>
              <p className="mt-1 text-xs text-mute">{n.by} · {fmtEpoch(n.at)}</p>
            </li>
          ))}
        </ul>
      )}
      <form
        className="space-y-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (text.trim()) act(() => api.alertAddNote(id, actor, text.trim()), "Note added.").then(() => setText(""));
        }}
      >
        <label htmlFor="new-note" className={label}>Add a note</label>
        <textarea id="new-note" value={text} onChange={(e) => setText(e.target.value)} rows={3} maxLength={4000} className={input} />
        <button type="submit" className={btn} disabled={!text.trim()}>Add note</button>
      </form>
    </section>
  );
}

function DetailsForm({ id, actor, act }: { id: string; actor: string; act: Act }) {
  const [types, setTypes] = useState<{ id: string; label: string }[]>([]);
  const [f, setF] = useState<Record<string, string>>({});
  const [chosen, setChosen] = useState<string[]>([]);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open || types.length) return;
    fetch("/api/v1/alerts/reference/annexure", { headers: authHeader() }).then((r) => r.json()).then((d) => setTypes(d.items)).catch(() => {});
  }, [open, types.length]);

  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => setF((p) => ({ ...p, [k]: e.target.value }));
  const field = (k: string, text: string, ta = false) => (
    <div key={k} className={ta ? "sm:col-span-2" : ""}>
      <label htmlFor={`d-${k}`} className={label}>{text}</label>
      {ta ? <textarea id={`d-${k}`} rows={2} value={f[k] ?? ""} onChange={set(k)} className={input} /> : <input id={`d-${k}`} value={f[k] ?? ""} onChange={set(k)} className={input} />}
    </div>
  );

  if (!open) return <button className={btn} onClick={() => setOpen(true)}>Complete the CERT-In details…</button>;
  return (
    <form
      className="space-y-3 rounded border border-line bg-bg p-3"
      onSubmit={(e) => {
        e.preventDefault();
        const body: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(f)) if (v.trim() !== "") body[k] = v.trim();
        if (chosen.length) body.incident_type_ids = chosen;
        if (f.critical === "yes" || f.critical === "no") body.critical = f.critical === "yes";
        else delete body.critical;
        if (!Object.keys(body).length) return;
        act(() => api.alertDetails(id, actor, body), "Details saved.").then(() => { setF({}); setChosen([]); });
      }}
    >
      <fieldset>
        <legend className={label}>Incident type (CERT-In Annexure I)</legend>
        <div className="grid max-h-40 gap-1 overflow-y-auto sm:grid-cols-2">
          {types.map((t) => (
            <label key={t.id} className="flex items-start gap-2 text-xs">
              <input type="checkbox" checked={chosen.includes(t.id)} onChange={(e) => setChosen((c) => (e.target.checked ? [...c, t.id] : c.filter((x) => x !== t.id)))} className="mt-0.5" />
              <span>{t.label}</span>
            </label>
          ))}
        </div>
      </fieldset>
      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <label htmlFor="d-critical" className={label}>Critical to the organization's mission?</label>
          <select id="d-critical" value={f.critical ?? ""} onChange={set("critical")} className={input}>
            <option value="">Not set</option><option value="yes">Yes</option><option value="no">No</option>
          </select>
        </div>
        {field("ip_address", "Affected system IP address")}
        {field("operating_system", "Operating system")}
        {field("make_model_cloud", "Make / model / cloud details")}
        {field("location", "Location (city, region, country)")}
        {field("network_isp", "Network and ISP")}
        {field("impact", "Impact", true)}
        {field("actions_taken", "Actions taken", true)}
      </div>
      <div className="flex gap-2">
        <button type="submit" className={btnPrimary}>Save details</button>
        <button type="button" className={btn} onClick={() => setOpen(false)}>Hide</button>
      </div>
    </form>
  );
}

function authHeader(): Record<string, string> {
  try {
    const t = sessionStorage.getItem("logunify_token");
    return t ? { authorization: `Bearer ${t}` } : {};
  } catch {
    return {};
  }
}

function ReportActions({ id, email, phone }: { id: string; email: string; phone: string }) {
  const [state, setState] = useState<"idle" | "copied" | "error">("idle");
  const get = () => api.alertReportText(id);
  return (
    <section aria-labelledby="rep-title" className="space-y-2">
      <h3 id="rep-title" className="text-sm font-semibold">Draft incident report</h3>
      <p className="text-xs text-mute">
        A draft aligned with the CERT-In form. Review it, then send to <b className="text-fg">{email}</b> or call <b className="text-fg">{phone}</b>.
      </p>
      <div className="flex flex-wrap gap-2">
        <button
          className={btn}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(await get());
              setState("copied");
            } catch {
              setState("error");
            }
          }}
        >
          <ClipboardCopy size={14} aria-hidden /> Copy report text
        </button>
        <button
          className={btn}
          onClick={async () => {
            const blob = new Blob([await get()], { type: "text/plain" });
            const a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = `${id}-cert-in-draft.txt`;
            a.click();
            URL.revokeObjectURL(a.href);
          }}
        >
          <Download size={14} aria-hidden /> Download .txt
        </button>
        <span role="status" className="self-center text-xs text-mute">{state === "copied" ? "Copied to clipboard." : state === "error" ? "Copy was blocked by the browser; use Download." : ""}</span>
      </div>
    </section>
  );
}
