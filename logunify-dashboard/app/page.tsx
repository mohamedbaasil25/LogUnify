"use client";

import { Biohazard, Plus, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { StatusPill } from "@/components/Badges";
import IntegrityVerifier from "@/components/IntegrityVerifier";
import LogStream from "@/components/LogStream";
import MetricCards from "@/components/MetricCards";
import SourceConfigurator from "@/components/SourceConfigurator";
import SourceList from "@/components/SourceList";
import { api, auth } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";

export default function Dashboard() {
  const [modal, setModal] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const { data: sources } = usePoll((s) => api.sources(s), 5000, true, refresh);
  const { data: metrics, error } = usePoll((s) => api.metrics(s), 5000);

  const askToken = () => {
    const t = window.prompt("Paste your LogUnify access token (JWT). Leave empty to sign out.", "");
    if (t !== null) {
      auth.set(t.trim());
      setRefresh((n) => n + 1);
      window.location.reload();
    }
  };

  return (
    <div className="mx-auto max-w-[1600px] space-y-4 px-4 py-4 sm:px-6">
      <header className="flex flex-wrap items-center gap-3">
        <div className="mr-auto flex items-center gap-2.5">
          <ShieldCheck className="text-accent" size={26} aria-hidden />
          <div>
            <h1 className="text-lg font-semibold leading-tight">LogUnify SOC Console</h1>
            <p className="text-xs text-mute">Log pre-processing · anomaly detection · integrity ledger</p>
          </div>
        </div>
        {metrics?.threat_intel?.enabled && (
          <StatusPill tone={metrics.threat_intel.matches ? "crit" : "mute"}>
            <Biohazard size={12} aria-hidden /> {metrics.threat_intel.iocs.toLocaleString()} IOCs · {metrics.threat_intel.matches.toLocaleString()} hits
          </StatusPill>
        )}
        <StatusPill tone={error ? "crit" : "ok"}>{error ? "API offline" : "API connected"}</StatusPill>
        <button onClick={askToken} className="rounded border border-line px-3 py-2 text-xs text-mute hover:text-fg">
          Access token
        </button>
        <button
          onClick={() => setModal(true)}
          className="inline-flex items-center gap-1.5 rounded bg-accent px-3.5 py-2 text-sm font-medium text-bg hover:opacity-90"
        >
          <Plus size={16} aria-hidden /> Add source
        </button>
      </header>

      {error && !sources && (
        <p role="alert" className="rounded border border-crit/40 bg-crit/10 p-3 text-sm text-crit">
          Can’t reach the LogUnify API ({error}). Start it with <code className="font-mono">python -m uvicorn app.main:app</code> in
          logunify-backend, or set <code className="font-mono">LOGUNIFY_API_URL</code>.
        </p>
      )}

      <MetricCards />
      <LogStream />
      <IntegrityVerifier />
      <SourceList sources={sources?.items} onChanged={() => setRefresh((n) => n + 1)} />

      {modal && <SourceConfigurator onClose={() => setModal(false)} onCreated={() => setRefresh((n) => n + 1)} />}
    </div>
  );
}
