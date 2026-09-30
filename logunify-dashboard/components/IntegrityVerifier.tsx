"use client";

import { CheckCircle2, FileSearch, ShieldCheck, XCircle } from "lucide-react";
import { useState } from "react";
import { api } from "@/lib/api";
import { shortHash } from "@/lib/format";
import type { AuditResult, VerifyResult } from "@/lib/types";
import { usePoll } from "@/lib/usePoll";

const field = "w-full rounded border border-line bg-bg px-3 py-2 text-sm";
const labelCls = "mb-1 block text-xs font-medium uppercase tracking-wider text-mute";

function Row({ k, v, ok }: { k: string; v: React.ReactNode; ok?: boolean | null }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-line/60 py-1.5 text-sm last:border-0">
      <span className="text-mute">{k}</span>
      <span className={`break-all text-right font-mono text-xs ${ok === true ? "text-ok" : ok === false ? "text-crit" : ""}`}>{v}</span>
    </div>
  );
}

export default function IntegrityVerifier() {
  const { data: list } = usePoll((s) => api.batches(s, 20), 5000);
  const [batchId, setBatchId] = useState("");
  const [index, setIndex] = useState("0");
  const [record, setRecord] = useState("");
  const [proof, setProof] = useState("");
  const [root, setRoot] = useState("");
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [audit, setAudit] = useState<AuditResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const batches = list?.items ?? [];
  const selected = batchId || batches[0]?.id || "";
  const chosen = batches.find((b) => b.id === selected);

  async function guard(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  const load = () =>
    guard(async () => {
      const i = Number(index);
      if (!selected) throw new Error("No sealed batch yet: wait for 100 records to accumulate.");
      if (!Number.isInteger(i) || i < 0) throw new Error("Record index must be a non-negative whole number.");
      const b = await api.proof(selected, i);
      setBatchId(selected);          // pin: the newest batch changes every few seconds under live traffic
      setRecord(JSON.stringify(b.record, null, 2));
      setProof(JSON.stringify(b.proof, null, 2));
      setRoot(b.merkle_root);
      setResult(null);
      setAudit(null);
    });

  const verify = () =>
    guard(async () => {
      let rec: unknown, prf: unknown;
      try {
        rec = JSON.parse(record);
        prf = JSON.parse(proof);
      } catch {
        throw new Error("Record and proof must be valid JSON.");
      }
      if (typeof rec !== "object" || rec === null || Array.isArray(rec)) throw new Error("Record must be a JSON object.");
      if (!Array.isArray(prf)) throw new Error("Proof must be a JSON array of {hash, position} steps.");
      setAudit(null);
      setResult(await api.verify({ record: rec, proof: prf, merkle_root: root.trim(), batch_id: selected || undefined }));
    });

  const runAudit = () =>
    guard(async () => {
      if (!selected) throw new Error("Choose a batch first.");
      setResult(null);
      setAudit(await api.audit(selected));
    });

  return (
    <section className="rounded-lg border border-line bg-panel" aria-label="Ledger verification">
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <ShieldCheck size={16} className="text-accent" aria-hidden />
        <h2 className="text-sm font-semibold">Ledger verification</h2>
        <span className="text-xs text-mute">SHA-256 Merkle proof check against the anchored root</span>
      </header>

      <div className="grid gap-4 p-4 lg:grid-cols-2">
        <div className="space-y-3">
          <div className="grid grid-cols-[1fr_110px_auto] items-end gap-2">
            <div>
              <label htmlFor="v-batch" className={labelCls}>Batch</label>
              <select id="v-batch" value={selected} onChange={(e) => setBatchId(e.target.value)} className={field}>
                {batches.length === 0 && <option value="">No sealed batches yet</option>}
                {batches.map((b) => (
                  <option key={b.id} value={b.id}>{b.id} · {b.count} records{b.anchor ? " · anchored" : ""}</option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="v-idx" className={labelCls}>Record #</label>
              <input id="v-idx" inputMode="numeric" value={index} onChange={(e) => setIndex(e.target.value)} className={field} />
            </div>
            <button onClick={load} disabled={busy || !selected} className="rounded border border-line bg-panel2 px-3 py-2 text-sm hover:border-accent disabled:opacity-50">
              Load proof
            </button>
          </div>
          {chosen && (
            <p className="truncate text-xs text-mute">
              Batch root <span className="font-mono text-fg">{shortHash(chosen.merkle_root, 12)}</span>
              {chosen.anchor ? <> · tx <span className="font-mono text-fg">{shortHash(chosen.anchor.tx_id)}</span> (mock)</> : " · not anchored"}
            </p>
          )}
          <div>
            <label htmlFor="v-rec" className={labelCls}>Record (ECS JSON): edit any field to simulate tampering</label>
            <textarea id="v-rec" value={record} onChange={(e) => setRecord(e.target.value)} rows={8} spellCheck={false}
              placeholder="Load a proof, or paste an ECS record" className={`${field} font-mono text-xs`} />
          </div>
        </div>

        <div className="space-y-3">
          <div>
            <label htmlFor="v-root" className={labelCls}>Merkle root claimed</label>
            <input id="v-root" value={root} onChange={(e) => setRoot(e.target.value)} spellCheck={false} className={`${field} font-mono text-xs`} />
          </div>
          <div>
            <label htmlFor="v-proof" className={labelCls}>Merkle proof</label>
            <textarea id="v-proof" value={proof} onChange={(e) => setProof(e.target.value)} rows={5} spellCheck={false}
              className={`${field} font-mono text-xs`} />
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={verify} disabled={busy || !record || !proof || !root}
              className="inline-flex items-center gap-1.5 rounded bg-accent px-4 py-2 text-sm font-medium text-bg hover:opacity-90 disabled:opacity-50">
              <ShieldCheck size={15} aria-hidden /> Verify record
            </button>
            <button onClick={runAudit} disabled={busy || !selected}
              className="inline-flex items-center gap-1.5 rounded border border-line bg-panel2 px-3 py-2 text-sm hover:border-accent disabled:opacity-50"
              title="Rehash every record stored on the server and compare with the sealed root and the ledger anchor">
              <FileSearch size={15} aria-hidden /> Audit whole batch
            </button>
          </div>
        </div>
      </div>

      <div aria-live="polite" className="px-4 pb-4">
        {error && <p role="alert" className="rounded border border-crit/40 bg-crit/10 p-3 text-sm text-crit">{error}</p>}

        {result && (
          <div className={`rounded border p-3 ${result.valid ? "border-ok/40 bg-ok/5" : "border-crit/40 bg-crit/5"}`}>
            <p className={`mb-2 flex items-center gap-2 font-medium ${result.valid ? "text-ok" : "text-crit"}`}>
              {result.valid ? <CheckCircle2 size={18} aria-hidden /> : <XCircle size={18} aria-hidden />}
              {result.valid ? "Verified: this record is part of the anchored batch" : "Verification failed: the record, proof or root does not match"}
            </p>
            <Row k="Record SHA-256 leaf hash" v={result.leaf_hash} />
            <Row k="Root recomputed from proof" v={result.computed_root} ok={result.proof_valid} />
            <Row k="Root claimed" v={root} />
            <Row k="Ledger anchor" v={result.anchored ? `${result.tx_id?.slice(0, 16)}… (mock Fabric)` : "batch not anchored"}
              ok={result.anchored ? result.anchor_root_matches : null} />
          </div>
        )}

        {audit && (
          <div className={`rounded border p-3 ${audit.sealed_root_intact && audit.ledger_root_matches !== false ? "border-ok/40 bg-ok/5" : "border-crit/40 bg-crit/5"}`}>
            <p className={`mb-2 flex items-center gap-2 font-medium ${audit.sealed_root_intact && audit.ledger_root_matches !== false ? "text-ok" : "text-crit"}`}>
              {audit.sealed_root_intact && audit.ledger_root_matches !== false ? <CheckCircle2 size={18} aria-hidden /> : <XCircle size={18} aria-hidden />}
              {audit.sealed_root_intact ? `All ${audit.records} stored records match the sealed root` : `Tampering detected in ${audit.altered_indexes.length} record(s): #${audit.altered_indexes.join(", #")}`}
            </p>
            <Row k="Recomputed root" v={audit.recomputed_root} ok={audit.sealed_root_intact} />
            <Row k="Sealed root" v={audit.sealed_root} />
            <Row k="Matches ledger anchor" v={audit.ledger_root_matches === null ? "not anchored" : String(audit.ledger_root_matches)} ok={audit.ledger_root_matches} />
          </div>
        )}
      </div>
    </section>
  );
}
