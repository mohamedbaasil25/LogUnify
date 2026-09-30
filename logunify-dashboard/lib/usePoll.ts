"use client";

import { useEffect, useRef, useState } from "react";

/** Polls `fn` every `ms` (sequentially, never overlapping). Keeps the last good data when a poll fails. */
export function usePoll<T>(fn: (signal: AbortSignal) => Promise<T>, ms: number, enabled = true, refreshKey = 0) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string | null>(null);
  const fnRef = useRef(fn);
  useEffect(() => {
    fnRef.current = fn;
  });

  useEffect(() => {
    if (!enabled) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const ac = new AbortController();
    const tick = async () => {
      try {
        const d = await fnRef.current(ac.signal);
        if (!stopped) {
          setData(d);
          setError(null);
        }
      } catch (e) {
        if (!stopped && !(e instanceof DOMException && e.name === "AbortError")) {
          setError(e instanceof Error ? e.message : String(e));
        }
      } finally {
        if (!stopped) timer = setTimeout(tick, ms);
      }
    };
    tick();
    return () => {
      stopped = true;
      ac.abort();
      clearTimeout(timer);
    };
  }, [ms, enabled, refreshKey]);   // bumping refreshKey restarts the loop = immediate refetch

  return { data, error };
}
