"use client";

import { Biohazard, Plus } from "lucide-react";
import { useState } from "react";
import { StatusPill } from "@/components/Badges";
import IntegrityVerifier from "@/components/IntegrityVerifier";
import LogStream from "@/components/LogStream";
import MetricCards from "@/components/MetricCards";
import RoleGate from "@/components/RoleGate";
import SourceConfigurator from "@/components/SourceConfigurator";
import SourceList from "@/components/SourceList";
import { api } from "@/lib/api";
import { useSession } from "@/lib/session";
import { usePoll } from "@/lib/usePoll";

export default function Overview() {
  const { can } = useSession();
  const [modal, setModal] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const { data: sources } = usePoll((s) => api.sources(s), 5000, can("analyst"), refresh);
  const { data: metrics, error } = usePoll((s) => api.metrics(s), 5000);

  return (
    <>
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="mr-auto text-lg font-semibold">Overview</h1>
        {metrics?.threat_intel?.enabled && (
          <StatusPill tone={metrics.threat_intel.matches ? "crit" : "mute"}>
            <Biohazard size={12} aria-hidden /> {metrics.threat_intel.iocs.toLocaleString()} IOCs · {metrics.threat_intel.matches.toLocaleString()} hits
          </StatusPill>
        )}
        <StatusPill tone={error ? "crit" : "ok"}>{error ? "API offline" : "API connected"}</StatusPill>
        {can("admin") && (
          <button
            onClick={() => setModal(true)}
            className="inline-flex items-center gap-1.5 rounded bg-accent px-3.5 py-2 text-sm font-medium text-bg hover:opacity-90"
          >
            <Plus size={16} aria-hidden /> Add source
          </button>
        )}
      </div>

      {error && !metrics && (
        <p role="alert" className="rounded border border-crit/40 bg-crit/10 p-3 text-sm text-crit">
          Can’t reach the LogUnify API ({error}). Start it with <code className="font-mono">python -m uvicorn app.main:app</code> in logunify-backend,
          or set <code className="font-mono">LOGUNIFY_API_URL</code>.
        </p>
      )}

      <MetricCards />
      <RoleGate min="analyst" what="The live log stream, integrity proofs and sources">
        <LogStream />
        <IntegrityVerifier />
        <SourceList sources={sources?.items} onChanged={() => setRefresh((n) => n + 1)} canManage={can("admin")} />
      </RoleGate>

      {modal && <SourceConfigurator onClose={() => setModal(false)} onCreated={() => setRefresh((n) => n + 1)} />}
    </>
  );
}
