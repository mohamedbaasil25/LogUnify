"""Forward ECS documents to Elasticsearch with the Bulk API (aiohttp): batching, retries, dead-letter file.

Delivery guarantee: AT-LEAST-ONCE with idempotent writes. Every document is sent as a `create` action with a deterministic `_id`
(SHA-256 of its JSON), so a retry after a lost response cannot create a duplicate: Elasticsearch answers 409 for the copy it
already has and that is counted as success. `create` is also what data streams (`logs-logunify-*`) require.

What is retried (whole request, exponential backoff with full jitter, `Retry-After` honoured):
  connection refused / reset / dropped mid-request, timeouts, truncated responses, HTTP 408/429/500/502/503/504,
  and an unparsable response body (a proxy's HTML error page).
Partial failures are handled per item: only the items Elasticsearch rejected with 429/5xx are resent; 409 = already there = done;
other 4xx (e.g. mapper_parsing_exception) will never succeed and go straight to the dead-letter file, marked `rejected`.
HTTP 413 splits the batch in half and retries. 401/403 (bad or expired key) keeps the batch and retries slowly WITHOUT consuming
its retry budget, and flips `healthy` to false, so a rotated key does not turn into data loss.

Where a document can end up: Elasticsearch, or the dead-letter JSONL file (`dlq_path`), never silently nowhere, except the two
cases counted in `stats()`: `lost_spill_full` (queue full AND the in-memory spill cap reached) and `lost_dlq_full` (the dead-letter
file hit `dlq_max_mb`). Both mean a sustained outage far beyond the configured buffers: alert on those counters.
`replay_dlq()` feeds retryable records back in.

The event loop is never blocked: serialisation and gzip run in a worker thread per batch, sockets are aiohttp, file writes go
through `asyncio.to_thread`. `submit()` is synchronous and O(1), safe to call from the pipeline's `process()`.

Security: https required unless the host is loopback (or `allow_insecure_http`); TLS verification on by default, optional CA file;
the API key goes only into the Authorization header and is never logged; the URL is logged as scheme://host:port.
NOT verified against a real Elasticsearch in this repository's environment (it cannot run there): behaviour is tested against
a protocol stub that mimics the Bulk API responses documented for 8.x.
"""
import asyncio
import gzip
import hashlib
import json
import logging
import os
import random
import ssl
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

log = logging.getLogger("logunify.forwarding.es")

_RETRY_HTTP = {408, 429, 500, 502, 503, 504}
_NET_ERRORS = (aiohttp.ClientConnectionError, aiohttp.ClientPayloadError, asyncio.TimeoutError, ConnectionError, OSError)
_FILTER = "errors,items.*.status,items.*.error.type,items.*.error.reason"     # keeps the response small
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class Item:
    """One document, pre-serialised so retries cost nothing. Not a dataclass: 500 of these are built per batch."""
    __slots__ = ("id", "action", "src", "attempts", "last")

    def __init__(self, doc_id: str, action: bytes, src: bytes):
        self.id, self.action, self.src, self.attempts, self.last = doc_id, action, src, 0, ""

    @property
    def size(self) -> int:
        return len(self.action) + len(self.src) + 2


class Outcome:
    def __init__(self):
        self.ok: list[Item] = []
        self.duplicates = 0
        self.retry: list[tuple[Item, str]] = []
        self.dead: list[tuple[Item, str, bool]] = []      # (item, reason, retryable)
        self.retry_after: float | None = None
        self.auth_error = False
        self.too_large = False
        self.error: str | None = None


def build_items(docs: list[dict], index: str) -> tuple[list[Item], list[tuple[dict, str]]]:
    """Serialise documents (runs in a worker thread). Returns (items, [(doc, reason)] for documents that cannot be JSON-encoded)."""
    items, bad = [], []
    head = b'{"create":{"_index":' + json.dumps(index).encode() + b',"_id":"'
    for d in docs:
        try:
            src = json.dumps(d, separators=(",", ":"), ensure_ascii=False, default=str, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as e:
            bad.append((d, f"unserializable:{e}"[:200]))
            continue
        did = hashlib.sha256(src).hexdigest()[:40]
        items.append(Item(did, head + did.encode() + b'"}}', src))
    return items, bad


def _body(items: list[Item]) -> bytes:
    return b"".join(i.action + b"\n" + i.src + b"\n" for i in items)


def _retry_after(v: str | None) -> float | None:
    try:
        return min(float(v), 300.0) if v is not None else None
    except ValueError:
        return None                                          # HTTP-date form: ignore, backoff applies


async def bulk_send(session: aiohttp.ClientSession, url: str, items: list[Item], *, headers: dict | None = None,
                    timeout_s: float = 30.0, gzip_min_bytes: int = 1024) -> Outcome:
    """POST one Bulk request and classify every item. Never raises for network / HTTP problems: they come back as `retry`."""
    out = Outcome()
    hdrs = {"Content-Type": "application/x-ndjson", **(headers or {})}
    body = _body(items)
    if len(body) >= gzip_min_bytes:
        body = await asyncio.to_thread(gzip.compress, body, 3)
        hdrs["Content-Encoding"] = "gzip"
    try:
        async with session.post(url, data=body, headers=hdrs, params={"filter_path": _FILTER},
                                timeout=aiohttp.ClientTimeout(total=timeout_s, connect=min(10.0, timeout_s))) as resp:
            raw = await resp.read()
            status, out.retry_after = resp.status, _retry_after(resp.headers.get("Retry-After"))
    except _NET_ERRORS as e:                                 # refused, reset, dropped mid-request, timeout, truncated body
        out.error = f"network:{type(e).__name__}"
        out.retry = [(i, out.error) for i in items]
        return out

    if status in (401, 403):
        out.auth_error, out.error = True, f"http_{status}:auth"
        out.retry = [(i, out.error) for i in items]
    elif status == 413:
        out.too_large, out.error = True, "http_413"
        out.retry = [(i, out.error) for i in items]
    elif status in _RETRY_HTTP:
        out.error = f"http_{status}"
        out.retry = [(i, out.error) for i in items]
    elif status != 200:                                      # 400 / 404 / ...: the request itself is wrong; retrying cannot help
        out.error = f"http_{status}:{raw[:200].decode('utf-8', 'replace')}"
        out.dead = [(i, out.error, True) for i in items]     # retryable=True for replay: usually a config problem fixed later
    else:
        try:
            data = json.loads(raw)
            results = data.get("items", []) if data.get("errors") else None
        except (ValueError, AttributeError):
            out.error = "bad_response"
            out.retry = [(i, out.error) for i in items]
            return out
        if results is None:
            out.ok = list(items)
        elif len(results) != len(items):
            out.error = "bad_response:item_count"
            out.retry = [(i, out.error) for i in items]      # safe: `create` + deterministic _id makes a resend idempotent
        else:
            for it, res in zip(items, results):
                r = next(iter(res.values()), {})
                st = r.get("status", 0)
                if 200 <= st < 300:
                    out.ok.append(it)
                elif st == 409:
                    out.ok.append(it)                        # already indexed by an earlier attempt
                    out.duplicates += 1
                elif st in _RETRY_HTTP:
                    out.retry.append((it, f"item_{st}:{(r.get('error') or {}).get('type', '')}"))
                else:
                    e = r.get("error") or {}
                    out.dead.append((it, f"rejected_{st}:{e.get('type', '')}:{str(e.get('reason', ''))[:160]}", False))
    return out


class ElasticsearchForwarder:
    def __init__(self, url: str, api_key: str | None = None, index: str = "logs-logunify-prod", *, workers: int = 2,
                 batch_max_docs: int = 500, batch_max_bytes: int = 5 * 1024 * 1024, flush_interval_s: float = 1.0,
                 queue_max: int = 50_000, spill_max: int = 100_000, max_retries: int = 6, backoff_base_s: float = 0.5,
                 backoff_max_s: float = 30.0, auth_retry_s: float = 60.0, request_timeout_s: float = 30.0, verify_ssl: bool = True,
                 ca_file: str = "", allow_insecure_http: bool = False, dlq_path: str = "data/es-dlq.jsonl",
                 dlq_max_mb: int = 512):
        u = urlparse(url)
        if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
            raise ValueError("Elasticsearch URL must be http(s)://host[:port] without embedded credentials")
        if u.scheme == "http" and u.hostname not in _LOOPBACK and not allow_insecure_http:
            raise ValueError("refusing plain http to a non-loopback Elasticsearch (logs and the API key would be readable on the "
                             "wire): use https, or set allow_insecure_http for a trusted network")
        self.label = f"{u.scheme}://{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"
        self._bulk_url = url.rstrip("/") + "/_bulk"
        self._headers = {"Authorization": f"ApiKey {api_key}"} if api_key else {}
        self.index, self.workers = index, max(1, workers)
        self.batch_docs, self.batch_bytes, self.flush_s = batch_max_docs, batch_max_bytes, flush_interval_s
        self.max_retries, self.b_base, self.b_max, self.timeout = max_retries, backoff_base_s, backoff_max_s, request_timeout_s
        self.auth_retry_s = auth_retry_s
        self._ssl = None if u.scheme == "http" else (ssl.create_default_context(cafile=ca_file or None) if verify_ssl else False)
        self.dlq_path, self.dlq_max = Path(dlq_path), dlq_max_mb * 1024 * 1024
        self._q: asyncio.Queue[dict] = asyncio.Queue(maxsize=queue_max)
        self._spill: list[bytes] = []
        self._spill_max = spill_max
        self._spill_evt = asyncio.Event()
        self._session: aiohttp.ClientSession | None = None
        self._tasks: list[asyncio.Task] = []
        self._inflight: dict[int, dict[str, Item]] = {}
        self._closing = False
        self._stop_evt = asyncio.Event()
        self.c: Counter[str] = Counter()
        self.consecutive_failures = 0
        self.last_error: str | None = None
        self.last_success_at: float | None = None

    # ---- lifecycle ----------------------------------------------------------------------------------------------------
    async def start(self) -> None:
        self._session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=self.workers * 2, ssl=self._ssl))
        self._tasks = [asyncio.create_task(self._worker(n), name=f"es-forward-{n}") for n in range(self.workers)]
        self._tasks.append(asyncio.create_task(self._spill_loop(), name="es-forward-spill"))
        log.info("Elasticsearch forwarding to %s index=%s workers=%d", self.label, self.index, self.workers)

    async def stop(self, drain_timeout_s: float = 10.0) -> None:
        """Stop intake, give queued documents `drain_timeout_s` to be delivered, then dead-letter whatever is left."""
        self._closing = True
        try:
            await asyncio.wait_for(self._q.join(), drain_timeout_s)
        except asyncio.TimeoutError:
            log.warning("forwarder drain timed out with %d queued documents; dead-lettering them", self._q.qsize())
        self._stop_evt.set()                                # interrupts backoff sleeps
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        left = []
        while not self._q.empty():
            left.append(self._q.get_nowait())
        if left:
            items, bad = build_items(left, self.index)
            self._dlq_sync([(i, "shutdown", True) for i in items] + [(_bad_item(d), r, False) for d, r in bad])
        if self._spill:
            self._write_dlq_sync(self._spill)
            self._spill = []
        if self._session:
            await self._session.close()
        self._session = None

    # ---- intake -------------------------------------------------------------------------------------------------------
    def submit(self, doc: dict) -> bool:
        """Non-blocking. True = queued for delivery. False = did not fit in the queue: it was spilled to the dead-letter file
        (or counted as lost if even the spill buffer is full). Never raises, never blocks."""
        if self._closing:
            return self._spill_doc(doc, "shutdown")
        try:
            self._q.put_nowait(doc)
            self.c["submitted"] += 1
            return True
        except asyncio.QueueFull:
            return self._spill_doc(doc, "queue_full")

    def _spill_doc(self, doc: dict, reason: str) -> bool:
        if len(self._spill) >= self._spill_max:
            self.c["lost_spill_full"] += 1
            return False
        items, bad = build_items([doc], self.index)                 # one document: microseconds
        if items:
            self._spill.append(_dlq_line(items[0], reason, True))
            self.c["spilled"] += 1
            self._spill_evt.set()
        return False

    # ---- workers ------------------------------------------------------------------------------------------------------
    async def _worker(self, n: int) -> None:
        while True:
            docs: list[dict] = []
            try:
                docs.append(await self._q.get())
                deadline = time.monotonic() + self.flush_s
                while len(docs) < self.batch_docs and (left := deadline - time.monotonic()) > 0:
                    try:
                        docs.append(await asyncio.wait_for(self._q.get(), left))
                    except asyncio.TimeoutError:
                        break
                items, bad = await asyncio.to_thread(build_items, docs, self.index)
                if bad:
                    await self._dlq([(_bad_item(d), r, False) for d, r in bad])
                for chunk in _chunks(items, self.batch_bytes):
                    self._inflight[n] = {i.id: i for i in chunk}
                    await self._deliver(chunk, n)
                    self._inflight.pop(n, None)
            except asyncio.CancelledError:
                # shutdown mid-batch: whatever is not confirmed yet is written to the dead-letter file (replay is idempotent)
                rest = list(self._inflight.pop(n, {}).values())
                if not rest and docs:
                    rest = build_items(docs, self.index)[0]
                self._dlq_sync([(i, "shutdown", True) for i in rest])
                raise
            except Exception:                                   # a bug here must not kill the worker or lose the batch
                log.exception("forwarder worker error; dead-lettering the batch")
                self.c["worker_errors"] += 1
                rest = list(self._inflight.pop(n, {}).values()) or build_items(docs, self.index)[0]
                await self._dlq([(i, "worker_error", True) for i in rest])
            finally:
                for _ in docs:
                    self._q.task_done()

    def _settle(self, n: int, items) -> None:
        live = self._inflight.get(n, {})
        for i in items:
            live.pop(i.id, None)

    async def _deliver(self, items: list[Item], n: int) -> None:
        pending = items
        while pending:
            out = await bulk_send(self._session, self._bulk_url, pending, headers=self._headers, timeout_s=self.timeout)
            self.c["requests"] += 1
            self.c["indexed"] += len(out.ok)
            self.c["duplicates_ok"] += out.duplicates
            self._settle(n, out.ok)
            if out.dead:
                self.c["rejected"] += sum(1 for _, _, r in out.dead if not r)
                await self._dlq(out.dead)
                self._settle(n, [i for i, _, _ in out.dead])
            if out.too_large and len(pending) > 1:              # 413: halve and resend; each half retries independently
                mid = len(pending) // 2
                self.c["split_413"] += 1
                await self._deliver(pending[:mid], n)
                await self._deliver(pending[mid:], n)
                return
            nxt = []
            for it, why in out.retry:
                it.last = why
                if not out.auth_error:                          # auth problems don't spend the retry budget
                    it.attempts += 1
                if it.attempts > self.max_retries or out.too_large:
                    await self._dlq([(it, f"retries_exhausted:{why}", True)])
                    self._settle(n, [it])
                    self.c["retries_exhausted"] += 1
                else:
                    nxt.append(it)
            problem = out.error or (out.retry[0][1] if out.retry else None)      # request-level, or an item-level 429/5xx
            if problem is None:
                self._note_success()                            # the cluster answered 200 and accepted the batch
            else:
                self._note_failure(problem)
            if not nxt:
                return
            self.c["retried_items"] += len(nxt)
            pending = nxt
            delay = out.retry_after if out.retry_after is not None else self._backoff(max(i.attempts for i in pending), out.auth_error)
            try:
                await asyncio.wait_for(self._stop_evt.wait(), delay)    # sleep, but wake at shutdown
            except asyncio.TimeoutError:
                pass
            if self._stop_evt.is_set():                         # shutting down: stop retrying, keep the documents
                await self._dlq([(i, "shutdown", True) for i in pending])
                self._settle(n, pending)
                return

    def _backoff(self, attempt: int, slow: bool = False) -> float:
        """Exponential with full jitter (so many workers do not retry in lockstep); auth failures wait the slow cap."""
        if slow:
            return self.auth_retry_s
        return random.uniform(min(0.05, self.b_base), min(self.b_max, self.b_base * 2 ** max(attempt - 1, 0)))

    def _note_success(self) -> None:
        if self.consecutive_failures:
            log.info("Elasticsearch forwarding recovered after %d failed attempts", self.consecutive_failures)
        self.consecutive_failures, self.last_error, self.last_success_at = 0, None, time.time()

    def _note_failure(self, why: str) -> None:
        self.consecutive_failures += 1
        self.last_error = why
        if self.consecutive_failures in (1, 5) or self.consecutive_failures % 20 == 0:     # not one line per retry
            log.warning("Elasticsearch forwarding to %s failing (%s), attempt streak %d; documents are held/retried",
                        self.label, why, self.consecutive_failures)

    # ---- dead-letter file -----------------------------------------------------------------------------------------------
    async def _dlq(self, recs: list[tuple[Item, str, bool]]) -> None:
        await asyncio.to_thread(self._dlq_sync, recs)

    def _dlq_sync(self, recs: list[tuple[Item, str, bool]]) -> None:
        self._write_dlq_sync([_dlq_line(i, why, retryable) for i, why, retryable in recs])

    def _write_dlq_sync(self, lines: list[bytes]) -> None:
        if not lines:
            return
        try:
            self.dlq_path.parent.mkdir(parents=True, exist_ok=True)
            if self.dlq_path.exists() and self.dlq_path.stat().st_size >= self.dlq_max:
                self.c["lost_dlq_full"] += len(lines)
                log.error("dead-letter file is full (%d MB): %d documents LOST", self.dlq_max // 2**20, len(lines))
                return
            with open(self.dlq_path, "ab") as f:
                f.write(b"".join(lines))
                f.flush()
                os.fsync(f.fileno())
            self.c["dead_lettered"] += len(lines)
        except OSError as e:
            self.c["lost_dlq_error"] += len(lines)
            log.error("cannot write dead-letter file %s: %s (%d documents LOST)", self.dlq_path, e, len(lines))

    async def _spill_loop(self) -> None:
        while True:
            await self._spill_evt.wait()
            self._spill_evt.clear()
            lines, self._spill = self._spill, []
            await asyncio.to_thread(self._write_dlq_sync, lines)

    async def replay_dlq(self, include_rejected: bool = False) -> dict:
        """Feed dead-lettered documents back into the queue (awaits queue space, so it back-pressures instead of spilling again).
        Records `rejected` by Elasticsearch (bad documents) are skipped and kept unless include_rejected."""
        if not self.dlq_path.exists():
            return {"replayed": 0, "kept": 0}
        work = self.dlq_path.with_suffix(f".replay-{int(time.time())}")
        await asyncio.to_thread(os.replace, self.dlq_path, work)
        replayed, keep = 0, []
        lines = await asyncio.to_thread(work.read_bytes)
        for line in lines.splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                keep.append(line + b"\n")
                continue
            if rec.get("retryable", True) or include_rejected:
                await self._q.put(rec["doc"])
                replayed += 1
            else:
                keep.append(line + b"\n")
        await asyncio.to_thread(self._write_dlq_sync, keep)
        await asyncio.to_thread(work.unlink)
        return {"replayed": replayed, "kept": len(keep)}

    # ---- status -----------------------------------------------------------------------------------------------------------
    @property
    def healthy(self) -> bool:
        return self.consecutive_failures == 0

    def stats(self) -> dict:
        zero = dict.fromkeys(("submitted", "requests", "indexed", "duplicates_ok", "retried_items", "retries_exhausted", "rejected",
                              "dead_lettered", "spilled", "split_413", "lost_spill_full", "lost_dlq_full", "lost_dlq_error",
                              "worker_errors"), 0)
        return {**zero, "target": self.label, "index": self.index, "healthy": self.healthy, "last_error": self.last_error,
                "last_success_at": self.last_success_at, "queue_depth": self._q.qsize(), "queue_max": self._q.maxsize,
                "spill_buffered": len(self._spill), "consecutive_failures": self.consecutive_failures, **self.c}


def _bad_item(doc: dict) -> Item:
    return Item("unserializable", b"", repr(doc)[:2000].encode("utf-8", "replace").replace(b'"', b"'"))


def _chunks(items: list[Item], max_bytes: int):
    cur, size = [], 0
    for i in items:
        if cur and size + i.size > max_bytes:
            yield cur
            cur, size = [], 0
        cur.append(i)
        size += i.size
    if cur:
        yield cur


def _dlq_line(item: Item, reason: str, retryable: bool) -> bytes:
    """One JSON line; `doc` embeds the original serialised document verbatim."""
    src = item.src if item.action else json.dumps(item.src.decode("utf-8", "replace")).encode()
    return (b'{"ts":' + str(round(time.time(), 3)).encode() + b',"id":"' + item.id.encode() + b'","reason":' +
            json.dumps(reason).encode() + b',"retryable":' + (b"true" if retryable else b"false") + b',"doc":' + src + b"}\n")
