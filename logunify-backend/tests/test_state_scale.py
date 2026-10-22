"""Model persistence (SQLite), the PostgreSQL state backend and the Redis-shared rate limit.

PostgreSQL / Redis tests run only when LOGUNIFY_TEST_PG_URL / LOGUNIFY_TEST_REDIS_URL point at a throwaway server
(CI starts both as service containers). They never touch anything outside their own schema / key prefix.
"""
import os
import sqlite3
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.state.backend import PostgresBackend, pg_schema_name
from tests.test_state import LOG, feed, flush, make

KEY = "k" * 32
PG_URL = os.environ.get("LOGUNIFY_TEST_PG_URL", "")
REDIS_URL = os.environ.get("LOGUNIFY_TEST_REDIS_URL", "")
needs_pg = pytest.mark.skipif(not PG_URL, reason="set LOGUNIFY_TEST_PG_URL")
needs_redis = pytest.mark.skipif(not REDIS_URL, reason="set LOGUNIFY_TEST_REDIS_URL")


def models_kw(tmp_path: Path, **kw):
    return dict(state_hmac_key=KEY, ml_warmup=100, **kw)


def intel_of(c):
    return c.app.state.pipeline.intel


def test_models_survive_restart(tmp_path):
    with TestClient(make(tmp_path, **models_kw(tmp_path))) as c:
        feed(c, 400)
        before = intel_of(c)
        templates, ready = before.miner.cluster_count, before.scorer.ready
        samples = before.scorer.samples
        assert ready and templates >= 1
    with TestClient(make(tmp_path, **models_kw(tmp_path))) as c2:
        after = intel_of(c2)
        assert after.miner.cluster_count == templates
        assert after.scorer.ready and after.scorer.samples == samples       # scoring is live straight after the restart
        assert after.miner.top_templates(1)[0]["template"] == before.miner.top_templates(1)[0]["template"]
        assert c2.get("/api/v1/state", headers={}).json()["loaded"]["models"]["templates"] == templates


def test_tampered_model_blob_is_ignored_not_loaded(tmp_path):
    with TestClient(make(tmp_path, **models_kw(tmp_path))) as c:
        feed(c, 300)
    db = sqlite3.connect(tmp_path / "state.db")
    db.execute("UPDATE models SET payload = payload || 'AA' WHERE name='drain3'")      # sig no longer matches
    db.commit()
    db.close()
    with TestClient(make(tmp_path, **models_kw(tmp_path))) as c2:
        st = c2.get("/api/v1/state").json()
        assert any("failed its signature check" in w for w in st["warnings"])
        assert intel_of(c2).miner.cluster_count == 0                                      # nothing from the bad blob was loaded
        feed(c2, 5)                                                                      # and the service works


def test_wrong_key_ignores_saved_models(tmp_path):
    with TestClient(make(tmp_path, **models_kw(tmp_path))) as c:
        feed(c, 300)
    with TestClient(make(tmp_path, state_hmac_key="z" * 32, ml_warmup=100)) as c2:
        assert intel_of(c2).miner.cluster_count == 0
        assert any("signature" in w for w in c2.get("/api/v1/state").json()["warnings"])


def test_models_not_persisted_without_a_key(tmp_path):
    with TestClient(make(tmp_path, ml_warmup=100)) as c:
        feed(c, 300)
        st = c.get("/api/v1/state").json()
        assert st["persist_models"] is False and any("NOT persisted" in w for w in st["notices"])
    assert sqlite3.connect(tmp_path / "state.db").execute("SELECT COUNT(*) FROM models").fetchone()[0] == 0


def test_v1_state_file_upgrades_in_place(tmp_path):
    with TestClient(make(tmp_path)) as c:
        c.post("/api/v1/sources", json={"name": "old", "type": "http", "format": "syslog"})
        flush(c)
    db = sqlite3.connect(tmp_path / "state.db")
    db.execute("DROP TABLE models")
    db.execute("PRAGMA user_version=1")
    db.commit()
    db.close()
    with TestClient(make(tmp_path)) as c2:
        assert c2.get("/api/v1/state").json()["loaded"]["sources"] == 1
    assert sqlite3.connect(tmp_path / "state.db").execute("PRAGMA user_version").fetchone()[0] == 2


# ---------------------------------------------------------------------------------------------- PostgreSQL
def pg_kw(worker: str, **kw):
    return dict(state_database_url=PG_URL, worker_id=worker, **kw)


@pytest.fixture
def worker():
    w = "t" + uuid.uuid4().hex[:8]
    yield w
    import asyncio
    import asyncpg

    async def drop():
        c = await asyncpg.connect(PG_URL)
        await c.execute(f'DROP SCHEMA IF EXISTS "{pg_schema_name(w)}" CASCADE')
        await c.close()
    asyncio.run(drop())


@needs_pg
def test_postgres_roundtrip_everything(tmp_path, worker):
    kw = pg_kw(worker, **models_kw(tmp_path))
    with TestClient(make(tmp_path, **kw)) as c:
        st = c.get("/api/v1/state").json()
        assert st["enabled"] and st["backend"] == "postgres"
        assert st["path"].endswith("#" + pg_schema_name(worker))
        src = c.post("/api/v1/sources", json={"name": "web feed", "type": "http", "format": "syslog"}).json()
        assert c.post("/api/v1/threatintel/iocs", json={"iocs": [
            {"type": "ip", "value": "185.220.101.9", "category": "tor", "threat_level": 1}]}).status_code in (200, 201)
        feed(c, 250)
        ids = [b["id"] for b in c.get("/api/v1/integrity/batches").json()["items"]]
        templates = intel_of(c).miner.cluster_count
        flush(c)
    assert not list(tmp_path.glob("state.db*"))                                          # nothing was written to a file
    with TestClient(make(tmp_path, **kw)) as c2:
        st = c2.get("/api/v1/state").json()
        assert st["enabled"] and st["loaded"]["sources"] == 1 and st["loaded"]["batches"] >= 2
        assert [b["id"] for b in c2.get("/api/v1/integrity/batches").json()["items"]] == ids
        assert intel_of(c2).miner.cluster_count == templates and intel_of(c2).scorer.ready
        assert any(s["id"] == src["id"] for s in c2.get("/api/v1/sources").json()["items"])
        assert c2.get(f"/api/v1/integrity/batches/{ids[0]}/audit").json()["sealed_root_intact"] is True


@needs_pg
def test_postgres_replicas_are_isolated_and_cannot_share_a_worker_id(tmp_path, worker):
    a = TestClient(make(tmp_path, **pg_kw(worker))).__enter__()
    try:
        a.post("/api/v1/sources", json={"name": "only-on-a", "type": "http", "format": "syslog"})
        flush(a)
        with TestClient(make(tmp_path, **pg_kw(worker))) as dup:                          # same worker id while a is running
            st = dup.get("/api/v1/state").json()
            assert st["enabled"] is False and "owned by another running instance" in st["last_error"]
        with TestClient(make(tmp_path, **pg_kw(worker + "b"))) as other:                  # a different replica: own schema, own data
            assert other.get("/api/v1/state").json()["enabled"]
            assert other.get("/api/v1/sources").json()["items"] == []
            import asyncio
            import asyncpg

            async def drop():
                conn = await asyncpg.connect(PG_URL)
                await conn.execute(f'DROP SCHEMA IF EXISTS "{pg_schema_name(worker + "b")}" CASCADE')
                await conn.close()
            asyncio.run(drop())
    finally:
        a.__exit__(None, None, None)


@needs_pg
def test_postgres_failed_flush_rolls_back_and_is_retried(tmp_path, worker):
    from tests.alert_helpers import run
    app = make(tmp_path, **pg_kw(worker))

    async def go():
        st = app.state.state
        await st.open()
        assert st.enabled
        for i in range(120):
            app.state.pipeline.process(LOG.format(i=i, j=1).encode())
        real = st._db.executemany
        calls = {"n": 0}

        async def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("connection reset")
            return await real(*a, **k)
        st._db.executemany = flaky
        with pytest.raises(RuntimeError):
            await st.flush()
        st._db.executemany = real
        assert (await st.flush())["rows_written"] > 100
        rows = await st._db.fetchall("SELECT COUNT(*) FROM docs WHERE kind='recent'")
        await st.close()
        return rows[0][0]
    assert run(go()) == 120


@needs_pg
def test_postgres_reconnects_after_the_connection_is_lost(tmp_path, worker):
    from tests.alert_helpers import run
    app = make(tmp_path, **pg_kw(worker))

    async def go():
        st = app.state.state
        await st.open()
        app.state.pipeline.process(LOG.format(i=1, j=1).encode())
        await st.flush()
        st._db._conn.terminate()                                                          # server went away
        app.state.pipeline.process(LOG.format(i=2, j=2).encode())
        r = await st.flush()
        n = (await st._db.fetchall("SELECT COUNT(*) FROM docs WHERE kind='recent'"))[0][0]
        await st.close()
        return r, n
    r, n = run(go())
    assert n == 2 and r["rows_written"] >= 2


def test_postgres_dsn_is_described_without_password():
    b = PostgresBackend("postgresql://svc:s3cret@db.internal:5432/logunify?sslmode=require", "w3")
    assert "s3cret" not in b.describe() and b.describe() == "postgresql://svc@db.internal:5432/logunify#logunify_w3"
    assert pg_schema_name("W-3; DROP") == "logunify_w_3__drop"


# ---------------------------------------------------------------------------------------------- Redis rate limit
@needs_redis
def test_rate_limit_is_shared_between_replicas():
    from app.config import Settings
    from app.security.hardening import Hardening
    from tests.alert_helpers import run
    prefix = uuid.uuid4().hex
    s = Settings(rate_limit_per_min=5, redis_url=REDIS_URL)
    a, b = Hardening(s).rate, Hardening(s).rate

    async def go():
        got = [(await (a if i % 2 else b).allow_async(prefix))[0] for i in range(8)]       # alternate replicas
        await a.close()
        await b.close()
        return got
    assert run(go()) == [True] * 5 + [False] * 3                                           # one limit of 5, not 5 per replica


def test_rate_limit_falls_back_to_local_when_redis_is_down():
    from app.config import Settings
    from app.security.hardening import Hardening
    from tests.alert_helpers import run
    r = Hardening(Settings(rate_limit_per_min=3, redis_url="redis://127.0.0.1:1/0")).rate

    async def go():
        t0 = time.monotonic()
        got = [(await r.allow_async("c"))[0] for _ in range(5)]
        return got, time.monotonic() - t0
    got, dt = run(go())
    assert got == [True, True, True, False, False] and r.errors == 5                        # still enforced per replica
    assert dt < 2.5                                                                          # and never hangs the API


# ---------------------------------------------------------------------------------------------- incremental recent-events log
def _positions(path):
    return [r[0] for r in sqlite3.connect(path).execute("SELECT pos FROM docs WHERE kind='recent' ORDER BY pos")]


def test_recent_log_is_saved_incrementally_and_pruned_to_the_buffer(tmp_path):
    with TestClient(make(tmp_path, recent_buffer=50, state_hmac_key=KEY)) as c:
        feed(c, 40)
        r1 = flush(c)
        feed(c, 10)
        r2 = flush(c)
        assert r2["rows_written"] < r1["rows_written"]                                         # not a rewrite of the buffer (the rest is the open Merkle batch)
        feed(c, 30)                                                                            # 80 seen, buffer holds 50
        flush(c)
        assert _positions(tmp_path / "state.db") == list(range(30, 80))                        # old rows pruned, positions never reused
        recent = c.get("/api/v1/logs/recent", params={"limit": 1000}).json()["items"]
        assert len(recent) == 50
    with TestClient(make(tmp_path, recent_buffer=50, state_hmac_key=KEY)) as c2:               # restart: same events back, numbering continues
        again = c2.get("/api/v1/logs/recent", params={"limit": 1000}).json()["items"]
        assert [d["event"]["original"] for d in again] == [d["event"]["original"] for d in recent]
        assert c2.app.state.pipeline.recent_total == 80
        feed(c2, 5)
        flush(c2)
        assert _positions(tmp_path / "state.db") == list(range(35, 85))


def test_recent_log_survives_a_burst_larger_than_the_buffer_between_flushes(tmp_path):
    with TestClient(make(tmp_path, recent_buffer=20)) as c:
        feed(c, 100)                                                                           # ring wrapped 5x before the first flush
        flush(c)
        assert _positions(tmp_path / "state.db") == list(range(80, 100))


def test_raising_the_buffer_keeps_what_was_saved(tmp_path):
    with TestClient(make(tmp_path, recent_buffer=30)) as c:
        feed(c, 30)
    with TestClient(make(tmp_path, recent_buffer=500)) as c2:
        assert len(c2.get("/api/v1/logs/recent", params={"limit": 1000}).json()["items"]) == 30
        feed(c2, 20)
    with TestClient(make(tmp_path, recent_buffer=500)) as c3:
        assert len(c3.get("/api/v1/logs/recent", params={"limit": 1000}).json()["items"]) == 50


def test_lowering_the_buffer_trims_on_load_and_prunes_on_disk(tmp_path):
    with TestClient(make(tmp_path, recent_buffer=100)) as c:
        feed(c, 60)
    with TestClient(make(tmp_path, recent_buffer=25)) as c2:
        assert len(c2.get("/api/v1/logs/recent", params={"limit": 1000}).json()["items"]) == 25
        flush(c2)
    assert _positions(tmp_path / "state.db") == list(range(35, 60))


def test_old_full_rewrite_state_files_still_load(tmp_path):
    with TestClient(make(tmp_path, recent_buffer=100)) as c:
        feed(c, 12)
    db = sqlite3.connect(tmp_path / "state.db")                                                # what a pre-incremental build wrote: positions 0..n-1
    assert _positions(tmp_path / "state.db") == list(range(12))
    db.close()
    with TestClient(make(tmp_path, recent_buffer=100)) as c2:
        assert len(c2.get("/api/v1/logs/recent", params={"limit": 1000}).json()["items"]) == 12
        assert c2.app.state.pipeline.recent_total == 12
