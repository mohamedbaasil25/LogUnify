"use client";

import { Download, FileCheck2, ScrollText, UserX } from "lucide-react";
import { useState } from "react";
import { StatusPill } from "@/components/Badges";
import RoleGate from "@/components/RoleGate";
import { api } from "@/lib/api";
import type { ComplianceControl } from "@/lib/types-app";
import { usePoll } from "@/lib/usePoll";

const card = "rounded-lg border border-line bg-panel";
const input = "rounded border border-line bg-bg px-3 py-2 text-sm placeholder:text-mute";
const btn = "inline-flex items-center gap-1.5 rounded border border-line bg-panel2 px-3 py-2 text-sm hover:border-accent disabled:opacity-50";
const STATUS_TONE = { met: "ok", partial: "warn", gap: "crit", manual: "mute" } as const;

function AuditCard() {
  const [action, setAction] = useState("");
  const [applied, setApplied] = useState("");
  const [verdict, setVerdict] = useState<string | null>(null);
  const [tone, setTone] = useState<"ok" | "crit">("ok");
  const { data, error } = usePoll((s) => api.auditLog(applied, s), 10_000, true, 0);

  async function verify() {
    setVerdict(null);
    try {
      const r = await api.auditVerify();
      setTone(r.valid ? "ok" : "crit");
      setVerdict(r.valid ? `Chain valid: ${r.records} records${r.keyed ? " (keyed HMAC)" : " (unkeyed: detects accidents, not a database-level attacker)"}.` : `CHAIN BROKEN at record ${r.broken_at}: ${r.reason}`);
    } catch (e) {
      setTone("crit");
      setVerdict(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <section className={card} aria-labelledby="audit">
      <h2 id="audit" className="flex items-center gap-2 border-b border-line px-4 py-3 text-sm font-semibold"><ScrollText size={15} aria-hidden /> Audit log</h2>
      <div className="space-y-3 p-4">
        <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); setApplied(action.trim()); }}>
          <div>
            <label htmlFor="audit-action" className="mb-1 block text-xs uppercase tracking-wider text-mute">Action contains / equals</label>
            <input id="audit-action" value={action} onChange={(e) => setAction(e.target.value)} placeholder="e.g. alerts.close" className={input} />
          </div>
          <button type="submit" className={btn}>Filter</button>
          <button type="button" className={btn} onClick={verify}>Verify hash chain</button>
        </form>
        {verdict && <p role="status" className={`rounded border p-2 text-sm ${tone === "ok" ? "border-ok/40 bg-ok/10 text-ok" : "border-crit/50 bg-crit/10 text-crit"}`}>{verdict}</p>}
        {error && <p role="alert" className="text-sm text-crit">{error}</p>}
        <div className="max-h-96 overflow-auto" tabIndex={0} role="region" aria-label="Audit records">
          <table className="w-full min-w-[720px] border-collapse text-left text-xs">
            <caption className="sr-only">Most recent audit records, newest first</caption>
            <thead className="sticky top-0 bg-panel2 text-mute">
              <tr>{["#", "Time", "Actor", "Role", "Action", "Outcome", "Client"].map((h) => <th key={h} scope="col" className="px-2 py-2 font-medium">{h}</th>)}</tr>
            </thead>
            <tbody>
              {data?.items.map((r) => (
                <tr key={r.seq} className="border-t border-line">
                  <td className="px-2 py-1.5 font-mono text-mute">{r.seq}</td>
                  <td className="tabular whitespace-nowrap px-2 py-1.5 text-mute">{new Date(r.ts * 1000).toLocaleString()}</td>
                  <td className="px-2 py-1.5">{r.actor}</td><td className="px-2 py-1.5 text-mute">{r.role}</td>
                  <td className="px-2 py-1.5 font-mono">{r.action}</td>
                  <td className={`px-2 py-1.5 ${r.outcome.startsWith("denied") ? "text-crit" : "text-ok"}`}>{r.outcome}</td>
                  <td className="px-2 py-1.5 text-mute">{r.client ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-mute">Every guarded call is recorded, including denials. Polled reads and repeated failures are sampled (one row per window, the rest counted).</p>
      </div>
    </section>
  );
}

function ComplianceCard() {
  const { data, error } = usePoll((s) => api.compliance(s), 60_000);
  const [fw, setFw] = useState("");
  const [pdfErr, setPdfErr] = useState<string | null>(null);

  async function pdf() {
    setPdfErr(null);
    try {
      const blob = await api.compliancePdf();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `logunify-compliance-${new Date().toISOString().slice(0, 10)}.pdf`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      setPdfErr(e instanceof Error ? e.message : String(e));
    }
  }

  const controls: ComplianceControl[] = (data?.controls ?? []).filter((c) => !fw || c.framework === fw);
  return (
    <section className={card} aria-labelledby="comp">
      <h2 id="comp" className="flex items-center gap-2 border-b border-line px-4 py-3 text-sm font-semibold"><FileCheck2 size={15} aria-hidden /> Compliance mapping</h2>
      <div className="space-y-3 p-4">
        {error && <p role="alert" className="text-sm text-crit">{error}</p>}
        <p className="text-xs text-mute">
          Evidence for an assessor, not a certification. <b className="text-fg">Gap</b> = the current configuration does not satisfy it; <b className="text-fg">partial</b> = LogUnify
          contributes but part lies elsewhere or rests on a mock/heuristic; <b className="text-fg">manual</b> = needs human attestation.
        </p>
        {data && (
          <>
            <div className="flex flex-wrap gap-2" role="group" aria-label="Framework filter">
              <button onClick={() => setFw("")} aria-pressed={fw === ""} className={`rounded border px-3 py-1.5 text-sm ${fw === "" ? "border-accent bg-accent/15 text-accent" : "border-line text-mute"}`}>All</button>
              {Object.entries(data.summary).map(([name, c]) => (
                <button key={name} onClick={() => setFw(name)} aria-pressed={fw === name} className={`rounded border px-3 py-1.5 text-left text-sm ${fw === name ? "border-accent bg-accent/15" : "border-line"}`}>
                  <span className="block font-medium">{name}</span>
                  <span className="text-xs text-mute">{c.met} met · {c.partial} partial · <span className={c.gap ? "text-crit" : ""}>{c.gap} gap</span> · {c.manual} manual</span>
                </button>
              ))}
            </div>
            <ul tabIndex={0} aria-label="Controls" className="max-h-[28rem] space-y-2 overflow-auto">
              {controls.map((c) => (
                <li key={c.framework + c.id} className="rounded border border-line p-3 text-sm">
                  <p className="flex flex-wrap items-center gap-2">
                    <StatusPill tone={STATUS_TONE[c.status]}>{c.status}</StatusPill>
                    <b>{c.framework} {c.id}</b> <span>{c.title}</span>
                  </p>
                  <p className="mt-1 text-xs text-mute">{c.evidence}</p>
                </li>
              ))}
            </ul>
            <div className="flex flex-wrap items-center gap-3">
              <button className={btn} onClick={pdf}><Download size={14} aria-hidden /> Download PDF report</button>
              <span className="font-mono text-xs text-mute">report SHA-256 {data.report_sha256.slice(0, 16)}…</span>
            </div>
            {pdfErr && <p role="alert" className="text-sm text-crit">{pdfErr}</p>}
          </>
        )}
      </div>
    </section>
  );
}

function AccessCard() {
  const [sub, setSub] = useState("");
  const [tick, setTick] = useState(0);
  const [msg, setMsg] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const { data, error } = usePoll((s) => api.revoked(s), 15_000, true, tick);

  async function run(fn: () => Promise<unknown>, ok: string) {
    setMsg(null);
    try {
      await fn();
      setMsg(ok);
      setTick((t) => t + 1);
      setSub("");
      setConfirm(false);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <section className={card} aria-labelledby="access">
      <h2 id="access" className="flex items-center gap-2 border-b border-line px-4 py-3 text-sm font-semibold"><UserX size={15} aria-hidden /> Access: revoke tokens</h2>
      <div className="space-y-3 p-4">
        <p className="text-xs text-mute">
          Revokes every token this API has seen for a subject that was issued before now. It takes effect within seconds on all replicas, but it does <b className="text-fg">not</b> sign the
          person out of your identity provider: disable the account there as well.
        </p>
        <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); if (sub.trim()) setConfirm(true); }}>
          <div>
            <label htmlFor="rev-sub" className="mb-1 block text-xs uppercase tracking-wider text-mute">Subject (token `sub`)</label>
            <input id="rev-sub" value={sub} onChange={(e) => setSub(e.target.value)} className={input} />
          </div>
          {confirm ? (
            <span className="flex gap-2">
              <button type="button" onClick={() => run(() => api.revokeSubject(sub.trim()), `Revoked all current tokens of ${sub.trim()}.`)} className="rounded bg-crit px-3 py-2 text-sm font-medium text-bg">Confirm revoke</button>
              <button type="button" onClick={() => setConfirm(false)} className={btn}>Cancel</button>
            </span>
          ) : (
            <button type="submit" disabled={!sub.trim()} className={btn}>Revoke…</button>
          )}
        </form>
        {msg && <p role="status" className="text-sm text-ok">{msg}</p>}
        {error && <p role="alert" className="text-sm text-crit">{error}</p>}
        {data && Object.keys(data.subjects).length > 0 && (
          <ul className="space-y-1 text-sm">
            {Object.entries(data.subjects).map(([s, nb]) => (
              <li key={s} className="flex items-center gap-3">
                <span className="font-mono text-xs">{s}</span>
                <span className="text-xs text-mute">tokens issued before {new Date(nb * 1000).toLocaleString()} are rejected</span>
                <button onClick={() => run(() => api.unrevokeSubject(s), `Restored access for ${s}.`)} className="text-xs text-accent underline">Restore</button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

export default function GovernancePage() {
  return (
    <RoleGate min="admin" what="Governance">
      <h1 className="text-lg font-semibold">Governance</h1>
      <div className="grid gap-4 xl:grid-cols-2">
        <AuditCard />
        <div className="space-y-4">
          <ComplianceCard />
          <AccessCard />
        </div>
      </div>
    </RoleGate>
  );
}
