"""Dead-letter store for logs the pipeline could not turn into a normalized document.

A log that fails parsing or crashes a stage is NOT dropped: its raw bytes and envelope are appended here (JSONL, one record per
line, raw bytes base64-encoded so binary garbage round-trips), counted in the metrics and visible through the API, and can be replayed after
the parser is fixed (`take()` / POST /api/v1/dlq/replay). Replays keep the original event.id, so they are idempotent downstream.

Writing is off the event loop: `put()` is a non-blocking queue push; a daemon thread appends and fsyncs in batches.
The file is capped (`max_mb`); beyond the cap records are counted as `lost_full` (and logged), which means a sustained flood of
unparseable input: alert on it. Nothing here is encrypted: the raw bytes are exactly what was received, so protect the file
like the raw topic (it can contain what PII redaction would have masked).
"""
import base64
import json
import logging
import os
import queue
import threading
import time
from pathlib import Path

log = logging.getLogger("logunify.dlq")
_STOP = object()


class DeadLetterFile:
    def __init__(self, path: str, max_mb: int = 512, queue_max: int = 100_000):
        self.path, self.max_bytes = Path(path), max_mb * 1024 * 1024
        self._q: queue.Queue = queue.Queue(maxsize=queue_max)
        self._lock = threading.Lock()                    # serialises the writer thread with take()
        self.stats_c = {"written": 0, "lost_full": 0, "lost_queue": 0, "lost_io": 0}
        self._thread: threading.Thread | None = None      # started on the first record: most pipelines never dead-letter anything
        self._start_lock = threading.Lock()

    # ---- producer side (called from the pipeline, never blocks) ---------------------------------------------------
    def put(self, raw: bytes, *, reason: str, stage: str, event_id: str, hint: str | None = None, source_id: str | None = None,
            transport: str | None = None, tz: str | None = None, error: str = "", received_at: float | None = None) -> None:
        rec = {"v": 1, "ts": round(time.time(), 3), "event_id": event_id, "reason": reason, "stage": stage, "error": error[:300],
               "hint": hint, "source_id": source_id, "transport": transport, "tz": tz, "received_at": received_at,
               "raw_b64": base64.b64encode(raw).decode("ascii")}
        self._ensure_thread()
        try:
            self._q.put_nowait((json.dumps(rec, separators=(",", ":")) + "\n").encode())
        except queue.Full:
            self.stats_c["lost_queue"] += 1
            log.error("dead-letter queue full: record for %s LOST", event_id)

    def _ensure_thread(self) -> None:
        if self._thread is None:
            with self._start_lock:
                if self._thread is None:
                    self._thread = threading.Thread(target=self._writer, name="dlq-writer", daemon=True)
                    self._thread.start()

    # ---- writer thread -------------------------------------------------------------------------------------------
    def _writer(self) -> None:
        while True:
            item = self._q.get()
            batch, stop = [item], item is _STOP
            while not stop and len(batch) < 500:
                try:
                    nxt = self._q.get_nowait()
                except queue.Empty:
                    break
                stop = nxt is _STOP
                batch.append(nxt)
            lines = [b for b in batch if b is not _STOP]
            if lines:
                self._append(lines)
            for _ in batch:
                self._q.task_done()                       # lets flush() know these bytes are on disk
            if stop:
                return

    def _append(self, lines: list[bytes]) -> None:
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                    self.stats_c["lost_full"] += len(lines)
                    log.error("dead-letter file is full (%d MB): %d records LOST", self.max_bytes // 2**20, len(lines))
                    return
                with open(self.path, "ab") as f:
                    f.write(b"".join(lines))
                    f.flush()
                    os.fsync(f.fileno())
                self.stats_c["written"] += len(lines)
            except OSError as e:
                self.stats_c["lost_io"] += len(lines)
                log.error("cannot write dead-letter file %s: %s (%d records LOST)", self.path, e, len(lines))

    def close(self, timeout_s: float = 10.0) -> None:
        if self._thread is not None:
            self._q.put(_STOP)
            self._thread.join(timeout_s)

    def flush(self, timeout_s: float = 10.0) -> None:
        """Wait until everything queued so far is on disk (tests, shutdown, replay)."""
        end = time.monotonic() + timeout_s
        while self._q.unfinished_tasks and time.monotonic() < end:
            time.sleep(0.005)

    # ---- inspection / replay -------------------------------------------------------------------------------------
    def stats(self) -> dict:
        size = self.path.stat().st_size if self.path.exists() else 0
        return {**self.stats_c, "queued": self._q.qsize(), "file_bytes": size, "path": str(self.path)}

    def peek(self, limit: int = 20) -> list[dict]:
        self.flush()
        with self._lock:
            if not self.path.exists():
                return []
            out = []
            with open(self.path, "rb") as f:
                for line in f:
                    if len(out) >= limit:
                        break
                    try:
                        r = json.loads(line)
                        r["raw_b64"] = r["raw_b64"][:200]               # a preview, not the payload
                        out.append(r)
                    except ValueError:
                        out.append({"corrupt": line[:80].decode("utf-8", "replace")})
            return out

    def take(self, limit: int = 1000) -> list[dict]:
        """Remove up to `limit` records from the front of the file and return them (decoded). The rest stays in order."""
        self.flush()
        with self._lock:
            if not self.path.exists():
                return []
            taken, keep = [], []
            with open(self.path, "rb") as f:
                for line in f:
                    if len(taken) < limit:
                        try:
                            r = json.loads(line)
                            r["raw"] = base64.b64decode(r.pop("raw_b64"))
                            taken.append(r)
                            continue
                        except (ValueError, KeyError):
                            pass
                    keep.append(line)
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "wb") as f:
                f.write(b"".join(keep))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            return taken

    def give_back(self, recs: list[dict]) -> None:
        """Put records that could not be re-submitted back (replay failed part-way)."""
        for r in recs:
            self.put(r["raw"], reason=r.get("reason", "replay_failed"), stage=r.get("stage", "replay"), event_id=r["event_id"],
                     hint=r.get("hint"), source_id=r.get("source_id"), transport=r.get("transport"), tz=r.get("tz"),
                     error=r.get("error", ""), received_at=r.get("received_at"))
