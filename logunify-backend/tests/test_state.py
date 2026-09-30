import asyncio
import json
import socket
import sqlite3
import time
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.state.store import StateStore
from tests.alert_helpers import run

LOG = "<38>Oct 11 22:14:15 web-01 sshd[41]: Failed password for user{i} from 185.220.101.{j} port 22 ssh2"


def make(tmp_path: Path, **kw):
    base = dict(mock_enabled=False, alert_db_path=str(tmp_path / "a.db"), audit_db_path=str(tmp_path / "au.db"),
                state_db_path=str(tmp_path / "state.db"), state_flush_interval_s=0.5, ti_mock_feed=False)
    base.update(kw)
    return create_app(Settings(**base))


def feed(c, n: int):
    for i in range(n):
        assert c.post("/api/v1/parse", json={"log": LOG.format(i=i, j=i % 200 + 1)}).status_code == 200


def flush(c):
    r = c.post("/api/v1/state/flush")
    assert r.status_code == 200, r.text
    return r.json()


def test_roundtrip_everything(tmp_path):
    with TestClient(make(tmp_path)) as c:
        src = c.post("/api/v1/sources", json={"name": "web feed", "type": "http", "format": "syslog", "tags": ["dmz"]}).json()
        token = src["token"]
        assert c.post("/api/v1/threatintel/iocs", json={"iocs": [
            {"type": "ip", "value": "203.0.113.50", "category": "C2", "threat_level": 1},
            {"type": "domain", "value": "evil.example.net", "threat_level": 2}]}).status_code in (200, 201)
        feed(c, 250)                                             # 2 sealed batches + 50 pending
        before_batches = c.get("/api/v1/integrity/batches").json()
        before_recent = c.get("/api/v1/logs/recent?limit=1000").json()["items"]
        c.app.state.pipeline.anomalies.append(before_recent[0])         # the model is still warming up: seed one anomaly
        before_anoms = c.get("/api/v1/anomalies?limit=200").json()["items"]
        assert [b["id"] for b in before_batches["items"]] == ["batch-000002", "batch-000001"]
        assert before_batches["pending_records"] == 50 and len(before_anoms) == 1
        flush(c)

    with TestClient(make(tmp_path)) as c2:                        # "restart"
        st = c2.get("/api/v1/state").json()
        assert st["loaded"]["sources"] == 1 and st["loaded"]["iocs"] == {"manual": 2} and st["loaded"]["batches"] == 2
        assert st["warnings"] == []
        # sources: listed, and the ORIGINAL token still authenticates although it was never stored
        items = c2.get("/api/v1/sources").json()["items"]
        assert items[0]["name"] == "web feed" and items[0]["has_token"] and items[0]["token"] is None
        ok = c2.post(f"/api/v1/sources/{src['id']}/ingest", json={"logs": [LOG.format(i=999, j=9)]}, headers={"X-Source-Token": token})
        assert ok.status_code == 202
        assert c2.post(f"/api/v1/sources/{src['id']}/ingest", json={"logs": ["x"]}, headers={"X-Source-Token": "nope"}).status_code == 401
        # IOCs
        assert c2.get("/api/v1/threatintel/lookup", params={"value": "203.0.113.50"}).json()["malicious"] is True
        # batches: same ids, roots, anchors, and proofs still verify
        after = c2.get("/api/v1/integrity/batches").json()
        assert after["items"] == before_batches["items"] and after["pending_records"] in (50, 51)   # +1 if the source ingest above was already processed
        proof = c2.get("/api/v1/integrity/batches/batch-000001/proof/7").json()
        v = c2.post("/api/v1/integrity/verify", json={"record": proof["record"], "proof": proof["proof"],
                                                      "merkle_root": proof["merkle_root"], "batch_id": "batch-000001"}).json()
        assert v["valid"] and v["anchored"] and v["anchor_root_matches"]
        assert c2.get("/api/v1/integrity/batches/batch-000001/audit").json()["sealed_root_intact"] is True
        # recent logs + anomalies
        assert [d["@timestamp"] for d in c2.get("/api/v1/logs/recent?limit=1000").json()["items"]][-250:] == \
               [d["@timestamp"] for d in before_recent][-250:]
        assert len(c2.get("/api/v1/anomalies?limit=200").json()["items"]) == len(before_anoms)
        # numbering continues: pending 50 + 50 more seals batch 3, no collision with anchored batches
        feed(c2, 50)
        assert c2.get("/api/v1/integrity/batches").json()["items"][0]["id"] == "batch-000003"


def test_token_and_demo_feed_never_reach_disk(tmp_path):
    with TestClient(make(tmp_path, ti_mock_feed=True)) as c:
        token = c.post("/api/v1/sources", json={"name": "web feed", "type": "http"}).json()["token"]
        flush(c)
        raw = (tmp_path / "state.db").read_bytes() + (tmp_path / "state.db-wal").read_bytes() if (tmp_path / "state.db-wal").exists() \
            else (tmp_path / "state.db").read_bytes()
    assert token.encode() not in raw
    db = sqlite3.connect(tmp_path / "state.db")
    assert db.execute("SELECT COUNT(*) FROM iocs WHERE feed LIKE 'mock%'").fetchone()[0] == 0


def test_unchanged_state_flushes_nothing_and_deletes_propagate(tmp_path):
    with TestClient(make(tmp_path)) as c:
        sid = c.post("/api/v1/sources", json={"name": "web feed", "type": "http"}).json()["id"]
        feed(c, 120)
        assert flush(c)["rows_written"] > 0
        assert flush(c)["rows_written"] == 0
        assert c.delete(f"/api/v1/sources/{sid}").status_code == 204
        flush(c)
    assert sqlite3.connect(tmp_path / "state.db").execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 0


def test_background_flush_survives_a_crash(tmp_path):
    """No explicit flush and no clean shutdown: the periodic task alone must have written the state."""
    with TestClient(make(tmp_path, state_flush_interval_s=0.5)) as c:
        c.post("/api/v1/sources", json={"name": "web feed", "type": "http"})
        feed(c, 100)
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                if sqlite3.connect(tmp_path / "state.db").execute("SELECT COUNT(*) FROM batches").fetchone()[0] == 1:
                    break
            except sqlite3.Error:
                pass
            time.sleep(0.1)
        snapshot = tmp_path / "crash.db"                          # copy while the app is still running = what a crash leaves
        src = sqlite3.connect(tmp_path / "state.db")
        dst = sqlite3.connect(snapshot)
        src.backup(dst)
        dst.close()
    with TestClient(make(tmp_path, state_db_path=str(snapshot))) as c2:
        assert c2.get("/api/v1/state").json()["loaded"]["batches"] == 1
        assert len(c2.get("/api/v1/sources").json()["items"]) == 1


def test_corrupt_file_is_moved_aside_and_service_starts(tmp_path):
    (tmp_path / "state.db").write_bytes(b"this is not a sqlite database" * 50)
    with TestClient(make(tmp_path)) as c:
        st = c.get("/api/v1/state").json()
        assert st["enabled"] and st["loaded"] == {"sources": 0, "iocs": {}, "batches": 0, "pending_records": 0, "recent": 0, "anomalies": 0}
        feed(c, 3)
    assert list(tmp_path.glob("state.db.corrupt-*"))


def test_unusable_path_disables_persistence_but_service_runs(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with TestClient(make(tmp_path, state_db_path=str(blocker / "sub" / "state.db"))) as c:
        st = c.get("/api/v1/state").json()
        assert st["enabled"] is False and "disabled" in st["last_error"]
        feed(c, 3)
        assert c.post("/api/v1/state/flush").status_code == 409


def test_tampered_batch_on_disk_is_detected_after_restore(tmp_path):
    with TestClient(make(tmp_path)) as c:
        feed(c, 100)
        flush(c)
    db = sqlite3.connect(tmp_path / "state.db")
    (payload,) = db.execute("SELECT payload FROM batches WHERE id='batch-000001'").fetchone()
    d = json.loads(payload)
    d["docs"][5]["message"] = "edited by an attacker"
    db.execute("UPDATE batches SET payload=? WHERE id='batch-000001'", (json.dumps(d),))
    db.commit()
    db.close()
    with TestClient(make(tmp_path)) as c2:
        st = c2.get("/api/v1/state").json()
        assert len(st["warnings"]) == 1 and "batch-000001" in st["warnings"][0]
        a = c2.get("/api/v1/integrity/batches/batch-000001/audit").json()
        assert a["sealed_root_intact"] is False and a["altered_indexes"] == [5]


def test_persist_logs_off_keeps_logs_out_of_the_file(tmp_path):
    with TestClient(make(tmp_path, state_persist_logs=False)) as c:
        feed(c, 100)
        flush(c)
    db = sqlite3.connect(tmp_path / "state.db")
    assert db.execute("SELECT COUNT(*) FROM docs WHERE kind IN ('recent','anomaly')").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM batches").fetchone()[0] == 1          # integrity data is still kept


def test_failed_flush_is_retried_without_loss(tmp_path):
    async def go():
        app = make(tmp_path)
        st = app.state.state
        await st.open()
        p = app.state.pipeline
        for i in range(120):
            p.process(LOG.format(i=i, j=1).encode())
        real = st._db.executemany
        calls = {"n": 0}

        async def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] == 2:
                raise sqlite3.OperationalError("disk I/O error")
            return await real(*a, **k)
        st._db.executemany = flaky
        try:
            await st.flush()
            raise AssertionError("expected failure")
        except sqlite3.OperationalError:
            pass
        st._db.executemany = real
        r = await st.flush()                                       # nothing was marked as written, so all of it is redone
        assert r["rows_written"] > 100
        await st.close()
        db = sqlite3.connect(tmp_path / "state.db")
        assert db.execute("SELECT COUNT(*) FROM batches").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM docs WHERE kind='recent'").fetchone()[0] == 120
    run(go())


def test_flush_does_not_block_the_event_loop(tmp_path):
    """Large state (60k IOCs + 50 full batches + 1000 recent logs): the loop keeps ticking while it is written."""
    async def go():
        app = make(tmp_path, integrity_max_batches=50)
        st = app.state.state
        await st.open()
        p = app.state.pipeline
        from app.threatintel.store import IOC
        p.ti.store.replace_feed("manual", [IOC("ip", f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}", "manual", "c", 2, "1", "d", ("t",))
                                           for i in range(1, 60_000)])
        for i in range(5100):
            p.process(LOG.format(i=i, j=i % 200 + 1).encode())
        gaps, stop = [], False

        async def ticker():
            last = time.perf_counter()
            while not stop:
                await asyncio.sleep(0.005)
                now = time.perf_counter()
                gaps.append(now - last)
                last = now
        t = asyncio.create_task(ticker())
        await asyncio.sleep(0.05)
        r = await st.flush()
        stop = True
        await t
        await st.close()
        assert r["rows_written"] > 60_000
        assert max(gaps) < 0.25, f"event loop stalled {max(gaps):.3f}s during flush ({r['ms']} ms total)"
        assert r["ms"] > 50                                          # it really was a big write, not a no-op
    run(go())


def test_misp_feed_only_restored_when_misp_is_configured(tmp_path):
    with TestClient(make(tmp_path)) as c:
        c.post("/api/v1/threatintel/iocs", json={"iocs": [{"type": "ip", "value": "203.0.113.50"}]})
        c.app.state.pipeline.ti.store.replace_feed("misp", c.app.state.pipeline.ti.store.feed_iocs("manual"))
        flush(c)
    with TestClient(make(tmp_path)) as c2:
        assert c2.get("/api/v1/state").json()["loaded"]["iocs"] == {"manual": 1}    # stale misp feed ignored: nothing would refresh it


def test_syslog_source_listener_rebinds_after_restart(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with TestClient(make(tmp_path)) as c:
        r = c.post("/api/v1/sources", json={"name": "fw syslog", "type": "syslog", "protocol": "tcp", "port": port}).json()
        assert r["status"] == "active"
        flush(c)
    with TestClient(make(tmp_path)) as c2:
        items = c2.get("/api/v1/sources").json()["items"]
        assert items[0]["status"] == "active" and items[0]["error"] is None
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)          # listening again without re-registering
        sock.sendall((LOG.format(i=1, j=1) + "\n").encode())
        sock.close()
        deadline = time.time() + 3
        while c2.get("/api/v1/metrics").json()["processed"] < 1 and time.time() < deadline:
            time.sleep(0.05)
        assert c2.get("/api/v1/metrics").json()["processed"] == 1


def test_state_endpoints_need_admin(tmp_path):
    from app.security import tokens
    secret = "s" * 40
    with TestClient(make(tmp_path, auth_mode="jwt", jwt_secret=secret)) as c:
        a = {"Authorization": "Bearer " + tokens.encode({"sub": "a", "exp": time.time() + 60, "roles": ["analyst"]}, secret)}
        assert c.get("/api/v1/state", headers=a).status_code == 403
        assert c.post("/api/v1/state/flush").status_code == 401


def test_store_direct_load_is_noop_when_disabled():
    st = StateStore(":memory:")
    assert run(st.load()) == {} and run(st.flush()) == {"skipped": "persistence disabled"}
