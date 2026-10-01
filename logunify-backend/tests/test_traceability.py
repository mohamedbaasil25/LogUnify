import base64
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.ecs.normalizer import parse_ts, to_iso
from app.ecs.taxonomy import categorize
from app.intel.anomaly import AnomalyScorer
from app.main import create_app
from app.pipeline.bus import InMemoryBus, Item
from app.pipeline.envelope import IngestMeta, kafka_event_id, uuid7
from app.pipeline.metrics import MetricsRegistry
from app.pipeline.processor import Pipeline
from tests.alert_helpers import run

SYSLOG = b"<38>Oct 11 22:14:15 web-01 sshd[41]: Failed password for bob from 185.220.101.4 port 22 ssh2"
JSON = b'{"timestamp":"2026-10-01T10:00:00Z","host":"web-01","src_ip":"8.8.8.8","method":"GET","status":500,"path":"/admin"}'
CEF = b"CEF:0|Acme|IDS|1.0|100|scan detected|5|src=10.0.0.1 dst=10.0.0.2 dpt=22 act=blocked"


def pipe(tmp_path, **kw):
    base = dict(alert_db_path=":memory:", mock_enabled=False, dlq_path=str(tmp_path / "dlq.jsonl"))
    base.update(kw)
    return Pipeline(InMemoryBus(base.pop("bus", 1000)), MetricsRegistry(), Settings(**base))


# ---- envelope ---------------------------------------------------------------------------------------------------
def test_uuid7_shape_and_ordering():
    a = uuid7(1_700_000_000_000)
    b = uuid7(1_700_000_000_001)
    u = uuid.UUID(a)
    assert u.version == 7 and u.variant == uuid.RFC_4122
    assert a < b and len({uuid7() for _ in range(1000)}) == 1000


def test_kafka_ids_are_deterministic_and_header_wins():
    assert kafka_event_id("t", 0, 5) == kafka_event_id("t", 0, 5) != kafka_event_id("t", 1, 5)
    assert IngestMeta.from_headers([], ("t", 2, 9)).event_id == kafka_event_id("t", 2, 9)
    m = IngestMeta(event_id="abc", source_id="s1", tz="Asia/Kolkata", peer="1.2.3.4")
    back = IngestMeta.from_headers(m.to_headers(), ("t", 0, 1))
    assert (back.event_id, back.source_id, back.tz, back.peer, back.kafka) == ("abc", "s1", "Asia/Kolkata", "1.2.3.4", ("t", 0, 1))


@pytest.mark.parametrize("raw,fmt", [(SYSLOG, "syslog"), (JSON, "json"), (CEF, "cef")])
def test_every_document_links_to_its_raw_bytes(tmp_path, raw, fmt):
    d = pipe(tmp_path).process(raw)
    assert uuid.UUID(d["event"]["id"]).version == 7
    assert d["event"]["hash"] == hashlib.sha256(raw).hexdigest()
    assert d["event"]["original"] == raw.decode()
    assert d["event"]["created"] and d["logunify"]["transport"] == "api" and d["logunify"]["parser"]["name"] == fmt
    assert "redacted" not in d["logunify"].get("raw", {})


def test_hash_covers_the_unredacted_raw_while_original_is_redacted(tmp_path):
    raw = b"<38>Oct 11 22:14:15 app[1]: user bob@example.com paid with 4111111111111111"
    d = pipe(tmp_path).process(raw)
    assert "bob@example.com" not in d["event"]["original"] and "4111111111111111" not in json.dumps(d)
    assert d["logunify"]["raw"]["redacted"] is True
    assert d["event"]["hash"] == hashlib.sha256(raw).hexdigest()           # proves what was received, not what is stored


def test_replayed_log_keeps_its_identity(tmp_path):
    p = pipe(tmp_path)
    m = IngestMeta(event_id=uuid7(), source_id="src-1", transport="replay")
    d1, d2 = p.process(SYSLOG, meta=m), p.process(SYSLOG, meta=m)
    assert d1["event"]["id"] == d2["event"]["id"] == m.event_id and d1["logunify"]["source"]["id"] == "src-1"


def test_batch_leaf_changes_if_the_raw_link_is_tampered(tmp_path):
    from app.integrity.merkle import hash_record
    d = pipe(tmp_path).process(SYSLOG)
    leaf = hash_record(d)
    d["event"]["hash"] = "0" * 64
    assert hash_record(d) != leaf


# ---- no-loss: dead-letter + reconciliation --------------------------------------------------------------------
def test_unparseable_logs_are_dead_lettered_with_raw_intact_and_books_balance(tmp_path):
    p = pipe(tmp_path)
    binary = b"\xff\xfe{not json\x00\x01"
    assert p.process(binary, "json") is None and p.process(SYSLOG) is not None
    p.dlq.flush()
    recs = [json.loads(x) for x in (tmp_path / "dlq.jsonl").read_text().splitlines()]
    assert len(recs) == 1 and recs[0]["stage"] == "parse" and recs[0]["reason"].startswith("parse_error")
    assert base64.b64decode(recs[0]["raw_b64"]) == binary and recs[0]["event_id"]
    assert p.metrics.dead_lettered and not p.metrics.dropped
    # process() is called directly here (no submit), so account for the 2 logs the door never saw
    p.metrics.received = 2
    assert p.metrics.reconciliation()["unaccounted"] == 0


def test_one_bad_log_cannot_take_its_batch_down(tmp_path, monkeypatch):
    from app.enrich import geoip
    p = pipe(tmp_path)
    real = geoip.lookup

    def flaky(ip):
        if ip == "9.9.9.9":
            raise RuntimeError("boom")
        return real(ip)
    monkeypatch.setattr(geoip, "lookup", flaky)
    items = [Item(b"<38>Oct 11 22:14:15 h a[1]: from 1.1.1.1 ok", None), Item(b"<38>Oct 11 22:14:15 h a[1]: from 9.9.9.9 bad", None),
             Item(b"<38>Oct 11 22:14:15 h a[1]: from 2.2.2.2 ok", None)]
    out = p.process_batch(items)
    assert [d is not None for d in out] == [True, False, True]
    assert p.metrics.dead_lettered["internal_error"] == 1


def test_dlq_replay_resubmits_with_original_id(tmp_path):
    async def go():
        p = pipe(tmp_path)
        await p.start()
        p.dlq.put(SYSLOG, reason="parse_error:old_parser_bug", stage="parse", event_id="11111111-1111-7111-8111-111111111111",
                  source_id="src-9", transport="http")
        res = await p.replay_dlq()
        assert res == {"taken": 1, "resubmitted": 1, "returned_to_dlq": 0}
        for _ in range(100):
            if p.recent:
                break
            await asyncio.sleep(0.02)
        doc = p.recent[0]
        assert doc["event"]["id"] == "11111111-1111-7111-8111-111111111111" and doc["logunify"]["transport"] == "replay"
        assert doc["logunify"]["source"]["id"] == "src-9" and p.dlq.peek() == []
        await p.stop()
    import asyncio
    run(go())


def test_door_refusals_are_dropped_and_told(tmp_path):
    async def go():
        p = pipe(tmp_path, bus=2, max_raw_bytes=100)
        n = await p.submit_many([SYSLOG] * 5 + [b"x" * 500])
        assert n == 2
        assert p.metrics.dropped == {"queue_overflow": 3, "oversize": 1}
        assert p.metrics.reconciliation()["unaccounted"] == 0 or p.metrics.reconciliation(in_flight=2)["unaccounted"] == 0
    run(go())


def test_consumer_loop_batches_and_balances(tmp_path):
    async def go():
        p = pipe(tmp_path, process_chunk=7)
        await p.start()
        assert await p.submit_many([SYSLOG] * 50 + [b"{bad"] * 5, "json") == 55          # hint json: SYSLOG lines are invalid too
        for _ in range(200):
            if p.metrics.reconciliation(p.bus.depth())["unaccounted"] == 0 and p.metrics.dead_lettered:
                break
            await asyncio.sleep(0.02)
        await asyncio.sleep(0.1)
        r = p.metrics.reconciliation(p.bus.depth())
        assert r["accepted"] == 55 and r["unaccounted"] == 0 and r["dead_lettered"] == 55
        await p.stop()
    import asyncio
    run(go())


# ---- timestamps -------------------------------------------------------------------------------------------------------
def test_december_log_arriving_in_january_is_last_year():
    now = datetime(2027, 1, 1, 0, 0, 30, tzinfo=timezone.utc)
    assert to_iso("Dec 31 23:59:58", now).startswith("2026-12-31T23:59:58")
    assert to_iso("Jan  1 00:00:01", now).startswith("2027-01-01T00:00:01")
    far = datetime(2026, 6, 15, tzinfo=timezone.utc)
    assert to_iso("Jun 15 10:00:00", far).startswith("2026-06-15T10:00:00")
    assert to_iso("Feb 29 12:00:00", datetime(2028, 3, 1, tzinfo=timezone.utc)).startswith("2028-02-29")


def test_naive_timestamps_use_the_source_timezone_and_are_flagged():
    now = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    iso, note = parse_ts("2026-10-01T10:00:00", now, "Asia/Kolkata")
    assert iso.startswith("2026-10-01T04:30:00") and note == "assumed:Asia/Kolkata"
    assert parse_ts("2026-10-01T10:00:00", now)[1] == "assumed:UTC"
    assert parse_ts("2026-10-01T10:00:00+05:30", now, "America/New_York") == ("2026-10-01T04:30:00+00:00", None)
    assert parse_ts(1_790_000_000, now)[1] is None and parse_ts("garbage", now)[1] == "unparseable" and parse_ts(None, now)[1] == "missing"
    assert parse_ts("2026-10-01T10:00:00", now, "Not/AZone")[0].startswith("2026-10-01T10:00:00")        # unknown zone -> UTC, never a crash


def test_missing_event_time_falls_back_to_receive_time_and_says_so(tmp_path):
    p = pipe(tmp_path)
    t = time.time() - 3600
    d = p.process(b"plain text log with no timestamp at all", meta=IngestMeta(received_at=t))
    assert d["logunify"]["timestamp"]["source"] == "received"
    assert abs(datetime.fromisoformat(d["@timestamp"]).timestamp() - t) < 2


def test_per_source_timezone_end_to_end(tmp_path):
    s = Settings(mock_enabled=False, dlq_path=str(tmp_path / "d.jsonl"), alert_db_path=":memory:")
    with TestClient(create_app(s)) as c:
        r = c.post("/api/v1/sources", json={"name": "kolkata fw", "type": "http", "format": "syslog", "timezone": "Asia/Kolkata"})
        assert r.status_code == 201 and r.json()["config"]["timezone"] == "Asia/Kolkata"
        assert c.post("/api/v1/sources", json={"name": "bad tz", "type": "http", "timezone": "Mars/Base"}).status_code == 422
        sid, tok = r.json()["id"], r.json()["token"]
        log = "<38>Oct 11 22:14:15 web-01 sshd[41]: Failed password for bob from 185.220.101.4 port 22 ssh2"
        assert c.post(f"/api/v1/sources/{sid}/ingest", json={"logs": [log]}, headers={"X-Source-Token": tok}).status_code == 202
        for _ in range(100):
            items = c.get("/api/v1/logs/recent").json()["items"]
            if items:
                break
            time.sleep(0.05)
        d = items[0]
        assert d["event"]["timezone"] == "Asia/Kolkata" and d["logunify"]["source"]["id"] == sid and d["logunify"]["transport"] == "http"
        assert d["@timestamp"][11:19] == "16:44:15"                                          # 22:14:15 IST = 16:44:15 UTC


# ---- taxonomy ---------------------------------------------------------------------------------------------------------
def test_taxonomy_is_consistent_across_sources(tmp_path):
    p = pipe(tmp_path)
    sysd, js, cef = p.process(SYSLOG), p.process(JSON), p.process(CEF)
    assert sysd["event"]["category"] == ["authentication"] and sysd["event"]["type"] == ["start"] and sysd["event"]["outcome"] == "failure"
    assert js["event"]["category"] == ["web"] and js["event"]["type"] == ["access"] and js["event"]["outcome"] == "failure"
    assert cef["event"]["category"] == ["network"] and cef["event"]["type"] == ["connection"] and cef["event"]["outcome"] == "failure"
    assert {d["event"]["module"] for d in (sysd, js, cef)} == {"syslog", "json", "cef"}


def test_taxonomy_rules_never_override_and_normalise():
    f = {"event.category": "Authentication", "event.outcome": "Succeeded", "event.type": "Start", "process.name": "cron"}
    categorize(f, "x")
    assert f["event.category"] == ["authentication"] and f["event.outcome"] == "success" and f["event.type"] == ["start"]
    g = {"event.outcome": "weird"}
    categorize(g)
    assert g["event.outcome"] == "unknown"
    h = {"http.response.status_code": 200, "message": "ok"}
    categorize(h)
    assert h["event.outcome"] == "success" and h["event.category"] == ["web"]
    e = {"process.name": "sshd", "message": "session closed for user bob"}
    categorize(e)
    assert e["event.type"] == ["end"]


# ---- batch scoring ----------------------------------------------------------------------------------------------------
def test_batch_scoring_matches_single_scoring():
    import random
    r = random.Random(3)
    rows = [[r.random(), r.random() * -3, 6.0, 4.0 + r.random(), float(r.randint(0, 3)), 0.0, 1.0] for _ in range(400)]
    a, b = AnomalyScorer(warmup=100, refit_every=10_000), AnomalyScorer(warmup=100, refit_every=10_000)
    for sc in (a, b):
        for row in rows[:200]:
            sc._data.append(row)
        sc._fit(__import__("numpy").asarray(sc._data, dtype=float))
    single = [a.score(row, learn=False) for row in rows[200:]]
    many = b.score_many(rows[200:], [False] * 200)
    assert single == many and any(x > 0 for x in many)


# ---- supervision + readiness ------------------------------------------------------------------------------------------
def test_ready_is_503_when_nothing_is_consuming_and_200_when_running(tmp_path):
    s = Settings(mock_enabled=False, alert_db_path=":memory:", dlq_path=str(tmp_path / "d.jsonl"), audit_db_path=":memory:")
    app = create_app(s)
    stopped = TestClient(app).get("/ready")                      # no lifespan started: no consumer task
    assert stopped.status_code == 503 and "consumer loop is not running" in stopped.json()["problems"]
    with TestClient(app) as c:
        r = c.get("/ready")
        assert r.status_code == 200 and r.json()["ready"] and c.get("/health").json()["version"] == "1.0.0"


def test_supervisor_restarts_the_consumer_and_logs_flow_again(tmp_path):
    async def go():
        import asyncio
        p = pipe(tmp_path)
        real = p.bus.consume_batches
        calls = {"n": 0}

        async def flaky(max_records, wait_s=0.05):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("consumer library blew up")
            async for b in real(max_records, wait_s):
                yield b
        p.bus.consume_batches = flaky
        await p.start()
        for _ in range(100):
            if p.metrics.consumer_restarts:
                break
            await asyncio.sleep(0.05)
        assert p.metrics.consumer_restarts == 1
        await asyncio.sleep(1.3)                                   # first backoff is 1 s
        assert p.consumer_alive
        assert await p.submit(SYSLOG)
        for _ in range(100):
            if p.metrics.processed:
                break
            await asyncio.sleep(0.05)
        assert p.metrics.processed == 1
        await p.stop()
    run(go())
