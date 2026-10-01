"use client";

import { useEffect, useRef, useState } from "react";
import { api, auth } from "./api";
import type { EcsDoc } from "./types";

const MAX = 200;

/** Minimal Server-Sent-Events reader over fetch(): EventSource cannot send the Authorization header. */
async function readSse(url: string, signal: AbortSignal, onEvent: (event: string, data: string) => void) {
  const token = auth.get();
  const res = await fetch(url, { signal, cache: "no-store", headers: token ? { authorization: `Bearer ${token}` } : {} });
  if (!res.ok || !res.body) throw new Error(`stream ${res.status}`);
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buf += dec.decode(value, { stream: true });
    let i: number;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, i);
      buf = buf.slice(i + 2);
      let ev = "message";
      const data: string[] = [];
      for (const line of block.split("\n")) {
        if (line.startsWith("event:")) ev = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
      }
      if (data.length) onEvent(ev, data.join("\n"));
    }
  }
}

const idOf = (d: EcsDoc) => d.event?.id ?? `${d["@timestamp"]}|${d.message ?? d.event?.original ?? ""}`;

/**
 * Live log list: an initial fetch, then the backend PUSHES each new document (SSE) instead of the browser polling every 2 s.
 * A slow poll (15 s) stays on as a safety net (also covers a proxy that buffers the stream); duplicates are merged by event.id.
 */
export function useLiveLogs(paused: boolean) {
  const [items, setItems] = useState<EcsDoc[]>([]);
  const [live, setLive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lagged, setLagged] = useState(0);
  const pending = useRef<EcsDoc[]>([]);

  const merge = (incoming: EcsDoc[]) =>
    setItems((cur) => {
      const seen = new Set<string>();
      const out: EcsDoc[] = [];
      for (const d of [...incoming, ...cur]) {
        const k = idOf(d);
        if (!seen.has(k)) {
          seen.add(k);
          out.push(d);
        }
        if (out.length >= MAX) break;
      }
      return out;
    });

  useEffect(() => {
    if (paused) return;
    let stopped = false;
    const ac = new AbortController();
    let flush: ReturnType<typeof setInterval> | undefined;

    const poll = async () => {
      try {
        const r = await api.recent(100, ac.signal);
        if (!stopped) {
          merge(r.items);
          setError(null);
        }
      } catch (e) {
        if (!stopped && !(e instanceof DOMException && e.name === "AbortError")) setError(e instanceof Error ? e.message : String(e));
      }
    };
    poll();
    const slow = setInterval(poll, 15000);

    // batch UI updates to ~5/s so a fast stream does not re-render the table per event
    flush = setInterval(() => {
      if (pending.current.length) {
        const batch = pending.current.reverse();
        pending.current = [];
        merge(batch);
      }
    }, 200);

    (async () => {
      let delay = 1000;
      while (!stopped) {
        try {
          await readSse("/api/v1/stream/logs", ac.signal, (ev, data) => {
            setLive(true);
            delay = 1000;
            if (ev === "log") pending.current.push(JSON.parse(data) as EcsDoc);
            else if (ev === "lagged") setLagged(JSON.parse(data).dropped ?? 0);
          });
        } catch (e) {
          if (stopped || (e instanceof DOMException && e.name === "AbortError")) return;
        }
        setLive(false);
        await new Promise((r) => setTimeout(r, delay));
        delay = Math.min(delay * 2, 15000);
      }
    })();

    return () => {
      stopped = true;
      ac.abort();
      clearInterval(slow);
      if (flush) clearInterval(flush);
    };
  }, [paused]);

  return { items, live, error, lagged };
}
