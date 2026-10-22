"use client";

import { Eye, EyeOff, KeyRound } from "lucide-react";
import { useState } from "react";
import { useSession } from "@/lib/session";

export default function LoginPage() {
  const { signIn } = useSession();
  const [token, setToken] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!token.trim()) return setError("Paste your access token first.");
    setBusy(true);
    setError(null);
    try {
      await signIn(token);
    } catch (err) {
      setError(err instanceof Error ? err.message.replace(/^Invalid token: /, "") : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="mx-auto mt-10 max-w-md rounded-lg border border-line bg-panel p-6" aria-labelledby="login-title">
      <div className="mb-4 flex items-center gap-2">
        <KeyRound size={20} className="text-accent" aria-hidden />
        <h1 id="login-title" className="text-lg font-semibold">
          Sign in
        </h1>
      </div>
      <p className="mb-4 text-sm text-mute">
        Paste the access token (JWT) issued to you by your identity provider or administrator. It is kept only in this browser tab (session storage)
        and is cleared when you sign out, when it expires, or when the tab closes.
      </p>
      <form onSubmit={submit} className="space-y-3" noValidate>
        <div>
          <label htmlFor="token" className="mb-1 block text-xs font-medium uppercase tracking-wider text-mute">
            Access token
          </label>
          <div className="flex gap-2">
            <input
              id="token"
              name="token"
              type={show ? "text" : "password"}
              autoComplete="off"
              spellCheck={false}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              aria-describedby={error ? "login-error" : undefined}
              aria-invalid={error ? true : undefined}
              className="w-full rounded border border-line bg-bg px-3 py-2 font-mono text-sm placeholder:text-mute"
              placeholder="eyJhbGciOi…"
            />
            <button
              type="button"
              onClick={() => setShow((s) => !s)}
              className="rounded border border-line px-3 text-mute hover:text-fg"
              aria-label={show ? "Hide token" : "Show token"}
              aria-pressed={show}
            >
              {show ? <EyeOff size={16} aria-hidden /> : <Eye size={16} aria-hidden />}
            </button>
          </div>
        </div>
        {error && (
          <p id="login-error" role="alert" className="rounded border border-crit/40 bg-crit/10 p-2 text-sm text-crit">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded bg-accent px-4 py-2.5 text-sm font-medium text-bg hover:opacity-90 disabled:opacity-60"
        >
          {busy ? "Checking…" : "Sign in"}
        </button>
      </form>
      <p className="mt-4 text-xs text-mute">
        Roles: <b className="text-fg">viewer</b> sees metrics, <b className="text-fg">analyst</b> adds logs, alerts and tracing,{" "}
        <b className="text-fg">admin</b> adds sources, operations and governance. The server enforces them, not this page.
      </p>
    </section>
  );
}
