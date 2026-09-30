"""Forwarder tests run against an in-process STUB of the Elasticsearch Bulk API (aiohttp.web). It implements create-with-_id
semantics (201 / 409), gzip request bodies, per-item errors and the failure modes below. A real cluster was not available."""
import asyncio
import json
import time
from pathlib import Path

import pytest
from aiohttp import web

from app.config import Settings
from app.forwarding.elasticsearch import ElasticsearchForwarder
from app.pipeline.bus import InMemoryBus
from app.pipeline.metrics import MetricsRegistry
from app.pipeline.processor import Pipeline
from tests.alert_helpers import run


class StubEs:
    def __init__(self):
        self.docs: dict[str, dict] = {}
        self.requests: list[dict] = []
        self.script: list = []                  # one behaviour per request, consumed in order; then normal service
        self.runner = None
        self.port = 0

    async def start(self):
        app = web.Application(client_max_size=64 * 1024 * 1024)
        app.router.add_post("/_bulk", self._bulk)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = self.runner.addresses[0][1]
        return self

    async def stop(self):
        await self.runner.cleanup()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def store(self, pairs, skip=()):
        items, errors = [], False
        for act, src in pairs:
            meta = act["create"]
            if meta["_id"] in skip:
                items.append({"create": {"_index": meta["_index"], "_id": meta["_id"], "status": 429,
                                         "error": {"type": "es_rejected_execution_exception", "reason": "queue full"}}})
                errors = True
            elif meta["_id"] in self.docs:
                items.append({"create": {"_index": meta["_index"], "_id": meta["_id"], "status": 409,
                                         "error": {"type": "version_conflict_engine_exception", "reason": "exists"}}})
                errors = True
            else:
                self.docs[meta["_id"]] = src
                items.append({"create": {"_index": meta["_index"], "_id": meta["_id"], "status": 201}})
        return web.json_response({"took": 1, "errors": errors, **({"items": items} if errors else {})})

    async def _bulk(self, request: web.Request):
        raw = await request.read()
        body = raw                               # aiohttp's server already inflates Content-Encoding: gzip bodies
        assert body.endswith(b"\n"), "bulk body must end with a newline"
        lines = body.split(b"\n")[:-1]
        assert len(lines) % 2 == 0
        pairs = [(json.loads(lines[i]), json.loads(lines[i + 1])) for i in range(0, len(lines), 2)]
        self.requests.append({"n": len(pairs), "headers": dict(request.headers), "wire": request.content_length, "query": dict(request.query),
                              "ids": [a["create"]["_id"] for a, _ in pairs], "index": {a["create"]["_index"] for a, _ in pairs}})
        beh = self.script.pop(0) if self.script else None
        if beh:
            r = await beh(self, request, pairs)
            if r is not None:
                return r
        return self.store(pairs)


def status(code, headers=None, text=None):
    async def b(stub, request, pairs):
        return web.Response(status=code, headers=headers or {}, text=text if text is not None else "{}")
    return b


def drop_before():
    async def b(stub, request, pairs):
        request.transport.close()
        return web.Response()
    return b


def drop_after_store():
    """The dangerous one: Elasticsearch indexed the batch but the client never saw the answer."""
    async def b(stub, request, pairs):
        stub.store(pairs)
        request.transport.close()
        return web.Response()
    return b


def partial_429(ids):
    async def b(stub, request, pairs):
        return stub.store(pairs, skip=set(ids))
    return b


def mapping_error(pred):
    async def b(stub, request, pairs):
        items, errors = [], False
        for act, src in pairs:
            m = act["create"]
            if pred(src):
                errors = True
                items.append({"create": {"_index": m["_index"], "_id": m["_id"], "status": 400, "error": {
                    "type": "document_parsing_exception", "reason": "bad field"}}})
            else:
                stub.docs[m["_id"]] = src
                items.append({"create": {"_index": m["_index"], "_id": m["_id"], "status": 201}})
        return web.json_response({"errors": errors, "items": items})
    return b


def slow(seconds):
    async def b(stub, request, pairs):
        await asyncio.sleep(seconds)
    return b


def doc(i, **kw):
    return {"@timestamp": "2026-09-30T10:00:00Z", "message": f"event {i}", "event": {"original": f"raw {i}"}, "n": i, **kw}


def fw(stub, tmp_path, **kw):
    base = dict(index="logs-logunify-test", workers=1, flush_interval_s=0.05, backoff_base_s=0.01, backoff_max_s=0.05,
                request_timeout_s=2, dlq_path=str(tmp_path / "dlq.jsonl"))
    base.update(kw)
    return ElasticsearchForwarder(stub.url, kw.pop("api_key", "test-key") if False else base.pop("api_key", "test-key"), **base)


async def settle(f, timeout=10.0):
    await asyncio.wait_for(f._q.join(), timeout)


def dlq(tmp_path):
    p = Path(tmp_path / "dlq.jsonl")
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def test_happy_path_batches_gzip_auth_and_ids(tmp_path):
    async def go():
        s = await StubEs().start()
        f = fw(s, tmp_path, batch_max_docs=500)
        await f.start()
        for i in range(1200):
            assert f.submit(doc(i))
        await settle(f)
        await f.stop()
        await s.stop()
        assert len(s.docs) == 1200
        assert sum(r["n"] for r in s.requests) == 1200 and max(r["n"] for r in s.requests) <= 500
        r = s.requests[0]
        assert r["headers"]["Authorization"] == "ApiKey test-key" and r["headers"]["Content-Type"] == "application/x-ndjson"
        assert r["headers"]["Content-Encoding"] == "gzip" and r["index"] == {"logs-logunify-test"}
        assert "filter_path" in r["query"]
        assert f.stats()["indexed"] == 1200 and f.healthy and not dlq(tmp_path)
    run(go())


def test_connection_drops_before_and_after_indexing_never_lose_or_duplicate(tmp_path):
    async def go():
        s = await StubEs().start()
        s.script = [drop_before(), drop_after_store(), drop_before()]
        f = fw(s, tmp_path, batch_max_docs=1000)
        await f.start()
        for i in range(300):
            f.submit(doc(i))
        await settle(f)
        await f.stop()
        await s.stop()
        assert len(s.docs) == 300                                     # exactly one copy of each
        assert f.stats()["duplicates_ok"] == 300                      # the "lost response" batch came back as 409s = success
        assert not dlq(tmp_path) and f.healthy
        assert len(s.requests) == 4
    run(go())


def test_http_503_and_html_error_page_are_retried_and_retry_after_is_honoured(tmp_path):
    async def go():
        s = await StubEs().start()
        s.script = [status(503, {"Retry-After": "0.3"}), status(200, text="<html>bad gateway</html>"), status(502)]
        f = fw(s, tmp_path)
        await f.start()
        t0 = time.monotonic()
        for i in range(10):
            f.submit(doc(i))
        await settle(f)
        took = time.monotonic() - t0
        await f.stop()
        await s.stop()
        assert len(s.docs) == 10 and took >= 0.3 and f.stats()["retried_items"] >= 20
    run(go())


def test_partial_429_resends_only_rejected_items(tmp_path):
    async def go():
        s = await StubEs().start()
        f = fw(s, tmp_path, flush_interval_s=0.3)
        await f.start()
        docs = [doc(i) for i in range(20)]
        ids = []
        for d in docs:
            ids.append(json.dumps(d, separators=(",", ":"), ensure_ascii=False))
        import hashlib
        rejected = {hashlib.sha256(x.encode()).hexdigest()[:40] for x in ids[:5]}
        s.script = [partial_429(rejected)]
        for d in docs:
            f.submit(d)
        await settle(f)
        await f.stop()
        await s.stop()
        assert len(s.docs) == 20
        assert len(s.requests) == 2 and s.requests[1]["n"] == 5 and set(s.requests[1]["ids"]) == rejected
        assert f.stats()["duplicates_ok"] == 0
    run(go())


def test_mapping_rejection_goes_to_dlq_once_and_does_not_block_others(tmp_path):
    async def go():
        s = await StubEs().start()
        s.script = [mapping_error(lambda src: src["n"] % 10 == 0)]
        f = fw(s, tmp_path, flush_interval_s=0.3)
        await f.start()
        for i in range(30):
            f.submit(doc(i))
        await settle(f)
        await f.stop()
        await s.stop()
        assert len(s.docs) == 27 and len(s.requests) == 1               # rejected docs were not retried
        recs = dlq(tmp_path)
        assert len(recs) == 3 and all(r["retryable"] is False and "document_parsing_exception" in r["reason"] for r in recs)
        assert sorted(r["doc"]["n"] for r in recs) == [0, 10, 20]
    run(go())


def test_retries_exhausted_go_to_dlq_then_replay_succeeds(tmp_path):
    async def go():
        s = await StubEs().start()
        s.script = [status(503)] * 20
        f = fw(s, tmp_path, max_retries=2)
        await f.start()
        for i in range(15):
            f.submit(doc(i))
        await settle(f)
        assert not s.docs and len(dlq(tmp_path)) == 15 and all(r["retryable"] for r in dlq(tmp_path))
        assert f.stats()["retries_exhausted"] == 15 and not f.healthy
        s.script.clear()                                                  # the outage is over
        r = await f.replay_dlq()
        assert r == {"replayed": 15, "kept": 0}
        await settle(f)
        await f.stop()
        await s.stop()
        assert len(s.docs) == 15 and not dlq(tmp_path) and f.healthy
    run(go())


def test_413_splits_the_batch(tmp_path):
    async def go():
        s = await StubEs().start()

        async def too_big(stub, request, pairs):
            return web.Response(status=413) if len(pairs) > 8 else None
        s.script = [too_big] * 50
        f = fw(s, tmp_path, flush_interval_s=0.3)
        await f.start()
        for i in range(40):
            f.submit(doc(i))
        await settle(f)
        await f.stop()
        await s.stop()
        assert len(s.docs) == 40 and f.stats()["split_413"] >= 3 and not dlq(tmp_path)
    run(go())


def test_auth_failure_holds_documents_without_burning_retries(tmp_path):
    async def go():
        s = await StubEs().start()
        s.script = [status(401)] * 6                                       # far more than max_retries=2
        f = fw(s, tmp_path, max_retries=2, auth_retry_s=0.05)
        await f.start()
        for i in range(10):
            f.submit(doc(i))
        await settle(f)
        await f.stop()
        await s.stop()
        assert len(s.docs) == 10 and not dlq(tmp_path) and f.stats()["retries_exhausted"] == 0
        assert len(s.requests) == 7
    run(go())


def test_queue_overflow_spills_to_dlq_nothing_lost(tmp_path):
    async def go():
        s = await StubEs().start()
        s.script = [slow(0.5)]
        f = fw(s, tmp_path, queue_max=5, batch_max_docs=5, flush_interval_s=0.01)
        await f.start()
        accepted = sum(f.submit(doc(i)) for i in range(60))
        assert accepted < 60                                               # some did not fit
        await asyncio.sleep(0.2)
        await settle(f)
        await f.stop()
        await s.stop()
        assert len(s.docs) + len(dlq(tmp_path)) == 60
        assert f.stats().get("lost_spill_full", 0) == 0 and f.stats()["spilled"] == 60 - accepted
    run(go())


def test_shutdown_during_outage_dead_letters_everything(tmp_path):
    async def go():
        s = await StubEs().start()
        s.script = [status(503)] * 100
        f = fw(s, tmp_path, max_retries=50, backoff_base_s=0.05, backoff_max_s=0.2)
        await f.start()
        for i in range(25):
            f.submit(doc(i))
        await asyncio.sleep(0.3)
        await f.stop(drain_timeout_s=0.2)
        await s.stop()
        assert not s.docs
        assert sorted(r["doc"]["n"] for r in dlq(tmp_path)) == list(range(25))          # every document is on disk, once
    run(go())


def test_server_unreachable_then_recovers_without_loss(tmp_path):
    async def go():
        s = await StubEs().start()
        port = s.port
        await s.stop()                                                     # nothing listening: connection refused
        f = ElasticsearchForwarder(f"http://127.0.0.1:{port}", None, "logs-logunify-test", workers=1, flush_interval_s=0.05,
                                   backoff_base_s=0.05, backoff_max_s=0.1, request_timeout_s=1, max_retries=200,
                                   dlq_path=str(tmp_path / "dlq.jsonl"))
        await f.start()
        for i in range(40):
            f.submit(doc(i))
        for _ in range(100):                                               # Windows can take ~2 s to report a refused loopback connect
            if not f.healthy:
                break
            await asyncio.sleep(0.1)
        assert not f.healthy and f.stats()["last_error"].startswith("network:")
        s2 = StubEs()
        app = web.Application()
        app.router.add_post("/_bulk", s2._bulk)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", port).start()               # the "network blip" ends
        await settle(f, 15)
        await f.stop()
        await runner.cleanup()
        assert len(s2.docs) == 40 and f.healthy and not dlq(tmp_path)
    run(go())


def test_request_timeout_is_retried(tmp_path):
    async def go():
        s = await StubEs().start()
        s.script = [slow(3)]
        f = fw(s, tmp_path, request_timeout_s=0.3)
        await f.start()
        for i in range(5):
            f.submit(doc(i))
        await settle(f)
        await f.stop()
        await s.stop()
        assert len(s.docs) == 5 and f.stats()["retried_items"] >= 5
    run(go())


def test_unserializable_document_is_dead_lettered_not_fatal(tmp_path):
    async def go():
        s = await StubEs().start()
        f = fw(s, tmp_path)
        await f.start()
        f.submit(doc(1))
        f.submit(doc(2, bad=float("nan")))                                 # NaN is not valid JSON for Elasticsearch
        f.submit(doc(3))
        await settle(f)
        await f.stop()
        await s.stop()
        assert len(s.docs) == 2 and len(dlq(tmp_path)) == 1 and dlq(tmp_path)[0]["retryable"] is False
    run(go())


def test_url_and_transport_safety():
    with pytest.raises(ValueError):
        ElasticsearchForwarder("http://es.example.org:9200", "k")
    with pytest.raises(ValueError):
        ElasticsearchForwarder("https://user:pw@es.example.org:9200", "k")
    with pytest.raises(ValueError):
        ElasticsearchForwarder("ftp://es.example.org", "k")
    ElasticsearchForwarder("http://localhost:9200", "k")
    ElasticsearchForwarder("https://es.example.org:9200", "k")
    f = ElasticsearchForwarder("https://es.example.org:9200", "secret-key-123")
    assert "secret-key-123" not in json.dumps(f.stats()) and "secret" not in f.label


def test_event_loop_is_not_blocked_by_serialising_and_compressing_big_batches(tmp_path):
    async def go():
        s = await StubEs().start()
        f = fw(s, tmp_path, batch_max_docs=5000, flush_interval_s=0.2, workers=2)
        await f.start()
        gaps, stop = [], False

        async def ticker():
            last = time.perf_counter()
            while not stop:
                await asyncio.sleep(0.005)
                n = time.perf_counter()
                gaps.append(n - last)
                last = n
        t = asyncio.create_task(ticker())
        big = "x" * 1500
        for i in range(20_000):
            f.submit(doc(i, blob=big))
        await settle(f, 60)
        stop = True
        await t
        await f.stop()
        await s.stop()
        assert len(s.docs) == 20_000
        assert max(gaps) < 0.3, f"loop stalled {max(gaps):.3f}s"
    run(go())


def test_pipeline_forwards_redacted_docs_and_a_broken_forwarder_never_drops_logs(tmp_path):
    async def go():
        s = await StubEs().start()
        st = Settings(alert_db_path=":memory:", mock_enabled=False, es_forward_enabled=True, es_url=s.url,
                      es_forward_flush_interval_s=0.05, es_forward_dlq_path=str(tmp_path / "dlq.jsonl"))
        p = Pipeline(InMemoryBus(100), MetricsRegistry(), st)
        await p.start()
        line = "<38>Oct 11 22:14:15 web-01 sshd[41]: paid by carol@example.com card 4111111111111111 from 185.220.101.4"
        assert p.process(line.encode()) is not None
        await settle(p.forwarder)
        stored = json.dumps(list(s.docs.values()))
        assert "carol@example.com" not in stored and "4111111111111111" not in stored and "[PII:card]" in stored

        def boom(_):
            raise RuntimeError("forwarder bug")
        p.forwarder.submit = boom
        assert p.process(line.encode()) is not None and p.metrics.processed == 2       # log survived the forwarder failure
        await p.stop()
        await s.stop()
    run(go())


def test_pipeline_requires_url_when_enabled():
    with pytest.raises(ValueError):
        Pipeline(InMemoryBus(10), MetricsRegistry(), Settings(alert_db_path=":memory:", es_forward_enabled=True))
