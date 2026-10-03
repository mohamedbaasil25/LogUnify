"use client";

import { Bell, ClipboardList, Fingerprint, LayoutDashboard, LogOut, Search, Settings2, ShieldCheck, Timer } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { SessionProvider, useSession } from "@/lib/session";
import type { Role } from "@/lib/types-app";
import { usePoll } from "@/lib/usePoll";

const NAV: { href: string; label: string; icon: typeof Bell; min: Role }[] = [
  { href: "/", label: "Overview", icon: LayoutDashboard, min: "viewer" },
  { href: "/alerts", label: "Alerts", icon: Bell, min: "analyst" },
  { href: "/search", label: "Search", icon: Search, min: "analyst" },
  { href: "/trace", label: "Trace", icon: Fingerprint, min: "analyst" },
  { href: "/operations", label: "Operations", icon: Settings2, min: "analyst" },
  { href: "/governance", label: "Governance", icon: ClipboardList, min: "admin" },
];

function fmtRemaining(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s >= 3600) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}

function SessionMenu() {
  const { state, signOut } = useSession();
  const [, tick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);
  const left = state.status === "authed" && state.expiresAt !== null ? state.expiresAt - Date.now() : null;
  useExpiry(left, signOut);                                   // hooks must run on every render, before any early return
  if (state.status !== "authed") return null;
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="hidden text-mute sm:inline">
        <span className="font-medium text-fg">{state.me.sub}</span> · {state.me.role}
      </span>
      {left !== null && (
        <span
          className={`inline-flex items-center gap-1 rounded border px-2 py-1 ${left < 300_000 ? "border-warn/50 bg-warn/10 text-warn" : "border-line text-mute"}`}
          title="Your access token expires at this time; sign in again with a fresh token"
          role={left < 300_000 ? "status" : undefined}
        >
          <Timer size={12} aria-hidden /> {fmtRemaining(left)}
        </span>
      )}
      {state.me.auth !== "disabled" && (
        <button onClick={signOut} className="inline-flex items-center gap-1 rounded border border-line px-2 py-1 text-mute hover:text-fg">
          <LogOut size={12} aria-hidden /> Sign out
        </button>
      )}
    </div>
  );
}

function useExpiry(left: number | null, signOut: () => void) {
  useEffect(() => {
    if (left !== null && left <= 0) signOut();
  }, [left, signOut]);
}

function ActiveAlertsBadge() {
  const { can } = useSession();
  const enabled = can("analyst");
  const { data } = usePoll((s) => api.alerts("active", s), 10_000, enabled);
  const n = data?.items.length ?? 0;
  if (!enabled || n === 0) return null;
  const overdue = data!.items.some((a) => a.overdue);
  return (
    <span
      className={`ml-1 rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${overdue ? "bg-crit text-bg" : "bg-warn text-bg"}`}
      aria-label={`${n} active alert${n === 1 ? "" : "s"}${overdue ? ", at least one overdue" : ""}`}
    >
      {n}
    </span>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  const { state, can } = useSession();
  const path = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (state.status === "anon" && path !== "/login") router.replace("/login");
    if (state.status === "authed" && path === "/login") router.replace("/");
  }, [state.status, path, router]);

  const showNav = state.status === "authed";
  return (
    <>
      <header className="border-b border-line bg-panel">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="text-accent" size={24} aria-hidden />
            <div>
              <p className="text-base font-semibold leading-tight">LogUnify SOC Console</p>
              <p className="hidden text-xs text-mute sm:block">Log pre-processing · anomaly detection · integrity ledger</p>
            </div>
          </div>
          {showNav && (
            <nav aria-label="Main" className="order-last flex w-full gap-1 overflow-x-auto sm:order-none sm:w-auto">
              {NAV.filter((n) => can(n.min)).map((n) => {
                const active = n.href === "/" ? path === "/" : path.startsWith(n.href);
                return (
                  <Link
                    key={n.href}
                    href={n.href}
                    aria-current={active ? "page" : undefined}
                    className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded px-3 py-2 text-sm ${active ? "bg-panel2 text-fg" : "text-mute hover:text-fg"}`}
                  >
                    <n.icon size={15} aria-hidden /> {n.label}
                    {n.href === "/alerts" && <ActiveAlertsBadge />}
                  </Link>
                );
              })}
            </nav>
          )}
          <div className="ml-auto">
            <SessionMenu />
          </div>
        </div>
        {state.status === "authed" && state.me.auth === "disabled" && (
          <p role="status" className="border-t border-warn/30 bg-warn/10 px-4 py-1.5 text-center text-xs text-warn">
            Authentication is disabled on this backend (development mode): everyone is an administrator. Set LOGUNIFY_AUTH_MODE=jwt.
          </p>
        )}
      </header>
      <main id="main" className="mx-auto max-w-[1600px] space-y-4 px-4 py-4 sm:px-6">
        {state.status === "loading" && <p className="py-16 text-center text-mute">Connecting…</p>}
        {state.status === "offline" && (
          <p role="alert" className="rounded border border-crit/40 bg-crit/10 p-3 text-sm text-crit">
            Can’t reach the LogUnify API ({state.error}). Check that the backend is running and LOGUNIFY_API_URL is correct.
          </p>
        )}
        {(state.status === "authed" || (state.status === "anon" && path === "/login")) && children}
      </main>
    </>
  );
}

export default function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <SessionProvider>
      <Shell>{children}</Shell>
    </SessionProvider>
  );
}
