"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api, ApiError, auth } from "./api";
import type { Me, Role } from "./types-app";

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };

type State =
  | { status: "loading" }
  | { status: "anon" }
  | { status: "offline"; error: string }
  | { status: "authed"; me: Me; expiresAt: number | null };

interface Ctx {
  state: State;
  /** true when the signed-in role is at least `role` (always false while loading / signed out). */
  can: (role: Role) => boolean;
  signIn: (token: string) => Promise<void>;
  signOut: () => void;
  refresh: () => Promise<void>;
}

const SessionCtx = createContext<Ctx | null>(null);

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<State>({ status: "loading" });

  const refresh = useCallback(async () => {
    try {
      const me = await api.me();
      setState({ status: "authed", me, expiresAt: me.expires_in_s === null ? null : Date.now() + me.expires_in_s * 1000 });
    } catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.status === 403)) setState({ status: "anon" });
      else setState((s) => (s.status === "authed" ? s : { status: "offline", error: e instanceof Error ? e.message : String(e) }));
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 60_000);
    const onUnauthorized = () => setState({ status: "anon" });
    window.addEventListener("logunify:unauthorized", onUnauthorized);
    return () => {
      clearInterval(t);
      window.removeEventListener("logunify:unauthorized", onUnauthorized);
    };
  }, [refresh]);

  const value = useMemo<Ctx>(
    () => ({
      state,
      can: (role) => state.status === "authed" && RANK[state.me.role] >= RANK[role],
      signIn: async (token) => {
        auth.set(token.trim());
        const me = await api.me(); // throws (and clears the token) on 401
        setState({ status: "authed", me, expiresAt: me.expires_in_s === null ? null : Date.now() + me.expires_in_s * 1000 });
      },
      signOut: () => {
        auth.set("");
        setState({ status: "anon" });
      },
      refresh,
    }),
    [state, refresh],
  );
  return <SessionCtx.Provider value={value}>{children}</SessionCtx.Provider>;
}

export function useSession(): Ctx {
  const c = useContext(SessionCtx);
  if (!c) throw new Error("useSession outside SessionProvider");
  return c;
}

/** Display name for audit trails: the authenticated subject (never free text typed by the user). */
export function useActor(): string {
  const { state } = useSession();
  return state.status === "authed" ? state.me.sub : "";
}
