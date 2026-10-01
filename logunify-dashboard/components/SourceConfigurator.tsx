"use client";

import { AlertTriangle, Check, Copy, Globe, Plug, Radio, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import type { LogSource, SourceCreate, SourceFormat, SourceType } from "@/lib/types";

const TYPES: { value: SourceType; label: string; icon: typeof Radio; hint: string }[] = [
  { value: "syslog", label: "Syslog", icon: Radio, hint: "Devices that forward syslog over UDP/TCP" },
  { value: "http", label: "HTTP push", icon: Globe, hint: "Your app POSTs logs to a generated URL" },
  { value: "api", label: "API pull", icon: Plug, hint: "LogUnify polls a vendor REST API" },
];

const AUTO_FORMAT = { value: "auto", label: "Auto-detect" };

const input = "w-full rounded border border-line bg-bg px-3 py-2 text-sm placeholder:text-mute";
const labelCls = "mb-1 block text-xs font-medium uppercase tracking-wider text-mute";

function CopyButton({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* clipboard blocked: user can still select the text */
        }
      }}
      className="inline-flex items-center gap-1 rounded border border-line bg-panel2 px-2 py-1 text-xs hover:border-accent"
      aria-label={`Copy ${label}`}
    >
      {done ? <Check size={12} aria-hidden /> : <Copy size={12} aria-hidden />}
      {done ? "Copied" : "Copy"}
    </button>
  );
}

function Created({ src, onClose }: { src: LogSource; onClose: () => void }) {
  const path = String(src.config.ingest_path ?? "");
  const url = typeof window !== "undefined" ? `${window.location.origin}${path}` : path;
  const curl = `curl -X POST "${url}" \\\n  -H "Content-Type: application/json" \\\n  -H "X-Source-Token: ${src.token}" \\\n  -d '{"logs":["<your log line>"]}'`;
  return (
    <div className="space-y-4 p-5">
      <p className="flex items-center gap-2 text-sm text-ok">
        <Check size={16} aria-hidden /> Source “{src.name}” created
      </p>
      {src.type === "http" && src.token ? (
        <>
          <div className="rounded border border-warn/40 bg-warn/10 p-3 text-xs text-warn">
            Copy the token now. It is shown only once and can’t be retrieved later.
          </div>
          <div>
            <span className={labelCls}>Ingest URL</span>
            <div className="flex items-center gap-2">
              <code className="flex-1 truncate rounded border border-line bg-bg px-2 py-1.5 font-mono text-xs">{url}</code>
              <CopyButton text={url} label="ingest URL" />
            </div>
          </div>
          <div>
            <span className={labelCls}>Token (X-Source-Token header)</span>
            <div className="flex items-center gap-2">
              <code className="flex-1 truncate rounded border border-line bg-bg px-2 py-1.5 font-mono text-xs">{src.token}</code>
              <CopyButton text={src.token} label="token" />
            </div>
          </div>
          <div>
            <div className="mb-1 flex items-center justify-between">
              <span className={labelCls + " mb-0"}>Test it</span>
              <CopyButton text={curl} label="curl command" />
            </div>
            <pre className="overflow-x-auto rounded border border-line bg-bg p-3 font-mono text-xs">{curl}</pre>
          </div>
        </>
      ) : (
        <div className="flex gap-2 rounded border border-warn/40 bg-warn/10 p-3 text-xs text-warn">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden />
          <p>
            Configuration saved with status <b>registered</b>. This build stores {src.type === "syslog" ? "syslog listener" : "API poller"}{" "}
            settings but doesn’t open the listener or start polling yet, so no data will arrive from this feed until that worker is deployed.
          </p>
        </div>
      )}
      <div className="flex justify-end">
        <button onClick={onClose} className="rounded bg-accent px-4 py-2 text-sm font-medium text-bg hover:opacity-90">
          Done
        </button>
      </div>
    </div>
  );
}

export default function SourceConfigurator({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [type, setType] = useState<SourceType>("syslog");
  const [name, setName] = useState("");
  const [format, setFormat] = useState<SourceFormat>("auto");
  const [tz, setTz] = useState("");
  const [formats, setFormats] = useState<{ value: string; label: string }[]>([AUTO_FORMAT]);

  useEffect(() => {
    api.parsers().then((r) => setFormats([AUTO_FORMAT, ...r.items.map((p) => ({ value: p.name, label: `${p.name} (v${p.version})` }))])).catch(() => {});
  }, []);
  const [tags, setTags] = useState("");
  const [protocol, setProtocol] = useState<"udp" | "tcp">("udp");
  const [port, setPort] = useState("5514");
  const [url, setUrl] = useState("");
  const [interval, setInterval_] = useState("60");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<LogSource | null>(null);
  const dialog = useRef<HTMLDivElement>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  });

  // focus first field, close on Esc, keep Tab inside the dialog, lock background scroll.
  // Runs once: the parent re-renders on every poll and must not re-steal focus while the user types.
  useEffect(() => {
    nameRef.current?.focus();
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCloseRef.current();
      if (e.key !== "Tab" || !dialog.current) return;
      const f = dialog.current.querySelectorAll<HTMLElement>("button, input, select, a[href], [tabindex]:not([tabindex='-1'])");
      const list = Array.from(f).filter((el) => !el.hasAttribute("disabled"));
      if (!list.length) return;
      const first = list[0];
      const last = list[list.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, []);

  function clientError(): string | null {
    if (name.trim().length < 2) return "Give the source a name (at least 2 characters).";
    if (type === "syslog") {
      const p = Number(port);
      if (!Number.isInteger(p) || p < 1 || p > 65535) return "Port must be a whole number between 1 and 65535.";
    }
    if (type === "api" && !/^https:\/\/[^\s/]+/i.test(url.trim())) return "API URL must start with https://";
    return null;
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const bad = clientError();
    if (bad) return setError(bad);
    const body: SourceCreate = {
      name: name.trim(),
      type,
      format,
      tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
      ...(tz.trim() && { timezone: tz.trim() }),
      ...(type === "syslog" && { protocol, port: Number(port) }),
      ...(type === "api" && { url: url.trim(), poll_interval_s: Number(interval) || 60 }),
    };
    setBusy(true);
    setError(null);
    try {
      const src = await api.createSource(body);
      setCreated(src);
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the source.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4 sm:items-center"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        ref={dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby="src-title"
        className="w-full max-w-xl rounded-lg border border-line bg-panel shadow-2xl"
      >
        <header className="flex items-center justify-between border-b border-line px-5 py-3">
          <h2 id="src-title" className="text-base font-semibold">
            {created ? "Source created" : "Add log source"}
          </h2>
          <button onClick={onClose} className="rounded p-1 text-mute hover:text-fg" aria-label="Close">
            <X size={18} aria-hidden />
          </button>
        </header>

        {created ? (
          <Created src={created} onClose={onClose} />
        ) : (
          <form onSubmit={submit} onChange={() => error && setError(null)} className="space-y-4 p-5" noValidate>
            <fieldset>
              <legend className={labelCls}>Feed type</legend>
              <div className="grid grid-cols-3 gap-2">
                {TYPES.map((t) => (
                  <label
                    key={t.value}
                    className={`cursor-pointer rounded border p-2.5 text-center text-sm has-[:focus-visible]:outline has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent ${
                      type === t.value ? "border-accent bg-accent/10 text-accent" : "border-line hover:border-mute"
                    }`}
                  >
                    <input type="radio" name="type" value={t.value} checked={type === t.value} onChange={() => setType(t.value)} className="sr-only" />
                    <t.icon size={18} className="mx-auto mb-1" aria-hidden />
                    {t.label}
                  </label>
                ))}
              </div>
              <p className="mt-1.5 text-xs text-mute">{TYPES.find((t) => t.value === type)?.hint}</p>
            </fieldset>

            <div>
              <label htmlFor="src-name" className={labelCls}>Source name</label>
              <input id="src-name" ref={nameRef} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Edge firewall FW-01" maxLength={64} className={input} />
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="src-format" className={labelCls}>Log format</label>
                <select id="src-format" value={format} onChange={(e) => setFormat(e.target.value as SourceFormat)} className={input}>
                  {formats.map((f) => (
                    <option key={f.value} value={f.value}>{f.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="src-tz" className={labelCls}>Timestamp time zone (optional)</label>
                <input id="src-tz" value={tz} onChange={(e) => setTz(e.target.value)} placeholder="UTC, or e.g. Asia/Kolkata" className={input} />
                <p className="mt-1 text-xs text-mute">For logs whose timestamps carry no UTC offset (most syslog).</p>
              </div>
              <div>
                <label htmlFor="src-tags" className={labelCls}>Tags (comma-separated)</label>
                <input id="src-tags" value={tags} onChange={(e) => setTags(e.target.value)} placeholder="firewall, dmz" className={input} />
              </div>
            </div>

            {type === "syslog" && (
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label htmlFor="src-proto" className={labelCls}>Protocol</label>
                  <select id="src-proto" value={protocol} onChange={(e) => setProtocol(e.target.value as "udp" | "tcp")} className={input}>
                    <option value="udp">UDP</option>
                    <option value="tcp">TCP</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="src-port" className={labelCls}>Listen port</label>
                  <input id="src-port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} className={input} />
                </div>
              </div>
            )}

            {type === "api" && (
              <div className="grid gap-4 sm:grid-cols-[1fr_140px]">
                <div>
                  <label htmlFor="src-url" className={labelCls}>Endpoint URL (https)</label>
                  <input id="src-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://api.vendor.com/v1/events" className={input} />
                </div>
                <div>
                  <label htmlFor="src-int" className={labelCls}>Poll every (s)</label>
                  <input id="src-int" inputMode="numeric" value={interval} onChange={(e) => setInterval_(e.target.value)} className={input} />
                </div>
              </div>
            )}

            {type === "http" && (
              <p className="rounded border border-line bg-bg p-3 text-xs text-mute">
                A unique ingest URL and secret token are generated when you save. Nothing to configure here.
              </p>
            )}

            {error && (
              <p role="alert" className="flex gap-2 rounded border border-crit/40 bg-crit/10 p-3 text-sm text-crit">
                <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden /> {error}
              </p>
            )}

            <div className="flex justify-end gap-2 pt-1">
              <button type="button" onClick={onClose} className="rounded border border-line px-4 py-2 text-sm hover:border-mute">
                Cancel
              </button>
              <button type="submit" disabled={busy} className="rounded bg-accent px-4 py-2 text-sm font-medium text-bg hover:opacity-90 disabled:opacity-50">
                {busy ? "Saving…" : "Add source"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
