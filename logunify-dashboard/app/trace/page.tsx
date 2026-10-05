"use client";

import { CheckCircle2, EyeOff, Fingerprint, ShieldAlert, XCircle } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import { StatusPill } from "@/components/Badges";
import RoleGate from "@/components/RoleGate";
import { api } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { TraceResult } from "@/lib/types-app";

const CHECK_LABEL: Record<string, string> = {
  raw_hash_matches_event_hash: "SHA-256 of the archived raw bytes equals the event.hash stamped when the log was received",
  archive_intact: "The archive's stored record is intact (decrypts and matches its own index)",
  doc_matches_archive_index: "The normalized document we hold is byte-identical to the one archived alongside the raw bytes",
};

function TraceInner() {
  const router = useRouter();
  const params = useSearchParams();
  const initial = params.get("id") ?? "";
  const { can } = useSession();
  const [id, setId] = useState(initial);
  const [res, setRes] = useState<TraceResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = useCallback(async (eventId: string, raw = false) => {
    if (!eventId.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setRes(await api.trace(eventId.trim(), raw));
    } catch (e) {
      setRes(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (initial) run(initial);
  }, [initial, run]);

  return (
    <div className="space-y-4">
      <h1 className="flex items-center gap-2 text-lg font-semibold"><Fingerprint size={20} className="text-accent" aria-hidden /> Trace a record to the bytes received</h1>
      <p className="text-sm text-mute">
        Every normalized record carries an <code className="font-mono">event.id</code> and the SHA-256 of the exact bytes received. This page proves the chain:
        raw log → normalized record → Merkle batch → ledger anchor (the ledger is a <b>mock</b> in this deployment).
      </p>
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          router.replace(`/trace?id=${encodeURIComponent(id.trim())}`);
          run(id);
        }}
      >
        <div className="min-w-[280px] flex-1">
          <label htmlFor="eid" className="mb-1 block text-xs font-medium uppercase tracking-wider text-mute">event.id</label>
          <input id="eid" value={id} onChange={(e) => setId(e.target.value)} placeholder="0192f3a4-…" spellCheck={false}
                 className="w-full rounded border border-line bg-bg px-3 py-2 font-mono text-sm placeholder:text-mute" />
        </div>
        <button type="submit" disabled={busy || !id.trim()} className="rounded bg-accent px-4 py-2 text-sm font-medium text-bg hover:opacity-90 disabled:opacity-50">
          {busy ? "Tracing…" : "Trace"}
        </button>
      </form>

      {error && <p role="alert" className="rounded border border-crit/40 bg-crit/10 p-3 text-sm text-crit">{error}</p>}

      {res && (
        <div className="space-y-4">
          <section className="rounded-lg border border-line bg-panel p-4" aria-labelledby="verdict">
            <h2 id="verdict" className="mb-2 flex items-center gap-2 text-sm font-semibold">
              Verdict{" "}
              <StatusPill tone={res.verdict === "verified" ? "ok" : res.verdict === "mismatch" ? "crit" : "warn"}>
                {res.verdict === "verified" ? "verified" : res.verdict === "mismatch" ? "MISMATCH" : "raw not archived"}
              </StatusPill>
            </h2>
            {res.verdict === "raw_not_archived" && (
              <p className="mb-2 text-sm text-warn">
                The original bytes are not archived (LOGUNIFY_RAW_ARCHIVE_ENABLED is off), so this record cannot be proven against what was received. The record
                itself and its batch are still shown.
              </p>
            )}
            <ul className="space-y-1 text-sm">
              {Object.entries(res.checks).map(([k, v]) => (
                <li key={k} className="flex items-start gap-2">
                  {v === true ? <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-ok" aria-label="passed" /> : v === false ? <XCircle size={16} className="mt-0.5 shrink-0 text-crit" aria-label="failed" /> : <EyeOff size={16} className="mt-0.5 shrink-0 text-mute" aria-label="not checked" />}
                  <span className={v === null ? "text-mute" : ""}>{CHECK_LABEL[k] ?? k}{v === null ? " (not checked)" : ""}</span>
                </li>
              ))}
            </ul>
          </section>

          <section className="grid gap-4 md:grid-cols-2">
            <div className="rounded-lg border border-line bg-panel p-4">
              <h2 className="mb-2 text-sm font-semibold">Integrity reference</h2>
              {res.integrity_reference ? (
                <dl className="space-y-1 text-sm">
                  <Row k="Merkle batch" v={`${res.integrity_reference.batch_id} · position ${res.integrity_reference.index}`} />
                  <Row k="Merkle root" v={res.integrity_reference.merkle_root} mono />
                  <Row k="Ledger anchor (mock)" v={res.integrity_reference.anchor_tx_id ?? "not anchored"} mono />
                </dl>
              ) : (
                <p className="text-sm text-mute">Not sealed into a batch yet (still in the open batch) or the batch aged out of memory.</p>
              )}
              {res.record_sha256 && <Row k="Record SHA-256" v={res.record_sha256} mono />}
            </div>
            <div className="rounded-lg border border-line bg-panel p-4">
              <h2 className="mb-2 text-sm font-semibold">Origin</h2>
              <dl className="space-y-1 text-sm">
                {Object.entries(res.envelope ?? {}).filter(([, v]) => v !== null && v !== undefined && v !== "").map(([k, v]) => (
                  <Row key={k} k={k.replace(/_/g, " ")} v={typeof v === "object" ? JSON.stringify(v) : String(v)} mono={k === "hash"} />
                ))}
              </dl>
            </div>
          </section>

          {res.raw && (
            <section className="rounded-lg border border-line bg-panel p-4" aria-labelledby="raw">
              <h2 id="raw" className="mb-2 text-sm font-semibold">Original bytes</h2>
              <p className="text-sm text-mute">{res.raw.size} bytes · SHA-256 <span className="font-mono text-xs text-fg">{res.raw.sha256}</span></p>
              {res.raw.text !== undefined ? (
                <>
                  <p className="mt-2 flex items-center gap-1 text-xs text-warn"><ShieldAlert size={13} aria-hidden /> Unredacted content: may contain personal data or secrets. This view was written to the audit log.</p>
                  <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded border border-line bg-bg p-3 font-mono text-xs">{res.raw.text}</pre>
                </>
              ) : can("admin") ? (
                <button onClick={() => run(res.event_id, true)} className="mt-2 rounded border border-warn/50 bg-warn/10 px-3 py-2 text-sm text-warn hover:bg-warn/20">
                  Reveal unredacted raw log (audited)
                </button>
              ) : (
                <p className="mt-2 text-xs text-mute">Revealing the unredacted text needs the admin role.</p>
              )}
            </section>
          )}

          <details className="rounded-lg border border-line bg-panel">
            <summary className="cursor-pointer px-4 py-3 text-sm font-semibold">Normalized record (ECS JSON{res.normalized?.logunify?.raw?.redacted ? ", PII redacted" : ""})</summary>
            <pre tabIndex={0} className="max-h-96 overflow-auto border-t border-line p-4 font-mono text-xs">{JSON.stringify(res.normalized, null, 2)}</pre>
          </details>
        </div>
      )}
    </div>
  );
}

function Row({ k, v, mono = false }: { k: string; v: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wider text-mute">{k}</dt>
      <dd className={`break-all ${mono ? "font-mono text-xs" : ""}`}>{v}</dd>
    </div>
  );
}

export default function TracePage() {
  return (
    <RoleGate min="analyst" what="Tracing">
      <Suspense fallback={<p className="text-mute">Loading…</p>}>
        <TraceInner />
      </Suspense>
    </RoleGate>
  );
}
