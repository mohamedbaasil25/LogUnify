"use client";

import { Suspense } from "react";
import AlertsView from "@/components/AlertsView";
import RoleGate from "@/components/RoleGate";

export default function AlertsPage() {
  return (
    <RoleGate min="analyst" what="Alerts and the CERT-In workflow">
      <Suspense fallback={<p className="text-mute">Loading…</p>}>
        <AlertsView />
      </Suspense>
    </RoleGate>
  );
}
