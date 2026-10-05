"use client";

import { Lock } from "lucide-react";
import { useSession } from "@/lib/session";
import type { Role } from "@/lib/types-app";

/** Renders children only when the signed-in role is at least `min`; otherwise a clear explanation instead of a broken, 403-ing page.
 *  This is a convenience: the backend enforces every permission regardless of what the UI shows. */
export default function RoleGate({ min, children, what }: { min: Role; children: React.ReactNode; what?: string }) {
  const { can, state } = useSession();
  if (can(min)) return <>{children}</>;
  return (
    <section role="status" className="flex items-start gap-3 rounded-lg border border-line bg-panel p-5 text-sm text-mute">
      <Lock size={18} className="mt-0.5 shrink-0 text-warn" aria-hidden />
      <div>
        <p className="font-medium text-fg">{what ?? "This section"} needs the “{min}” role.</p>
        <p className="mt-1">
          You are signed in as <span className="text-fg">{state.status === "authed" ? `${state.me.sub} (${state.me.role})` : "nobody"}</span>. Ask an
          administrator for access if you need it.
        </p>
      </div>
    </section>
  );
}
