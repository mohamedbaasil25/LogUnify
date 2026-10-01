import base64
import hashlib
import os
import time

import pytest
from fastapi.testclient import TestClient

from app.archive.raw_store import ArchiveError, RawArchive, parse_key
from app.config import Settings
from app.main import create_app
from app.pipeline.bus import InMemoryBus
from app.pipeline.metrics import MetricsRegistry
from app.pipeline.processor import Pipeline
from app.security import tokens

KEY = base64.b64encode(os.urandom(32)).decode()
SECRET_TEXT = b"password=hunter2 card 4111111111111111 bob@example.com"


def arch(tmp_path, **kw):
    return RawArchive(str(tmp_path / "raw"), parse_key(KEY), **kw)


def test_key_validation():
    with pytest.raises(ArchiveError):
        parse_key("not-base64!!")
    with pytest.raises(ArchiveError):
        parse_key(base64.b64encode(b"short").decode())
    assert len(parse_key(KEY)) == 32


def test_roundtrip_is_encrypted_at_rest_and_verified(tmp_path):
    a = arch(tmp_path)
    binary = b"\x00\xff" + SECRET_TEXT + bytes(range(256))
    a.put("evt-1", binary, {"event": {"id": "evt-1"}})
    a.flush()
    got = a.get("evt-1")
    assert got["raw"] == binary and got["intact"] and got["sha256"] == hashlib.sha256(binary).hexdigest() and got["doc_sha256"]
    on_disk = b"".join(p.read_bytes() for p in (tmp_path / "raw").glob("seg-*.bin"))
    assert b"hunter2" not in on_disk and b"4111111111111111" not in on_disk and b"bob@example.com" not in on_disk
    assert (tmp_path / "raw" / "index.db").read_bytes().find(b"hunter2") < 0
    assert a.get("unknown") is None
    a.close()


def test_tampering_and_record_swapping_are_detected(tmp_path):
    a = arch(tmp_path)
    a.put("evt-a", b"first original log", None)
    a.put("evt-b", b"second original log", None)
    a.flush()
    seg = next((tmp_path / "raw").glob("seg-*.bin"))
    # 1. swap: make evt-a's index entry point at evt-b's ciphertext -> AAD (event id) mismatch
    ia, ib = a.lookup("evt-a"), a.lookup("evt-b")
    with a._dblock:
        a._db.execute("UPDATE raw SET off=?, len=? WHERE event_id='evt-a'", (ib["off"], ib["len"]))
        a._db.commit()
    with pytest.raises(ArchiveError):
        a.get("evt-a")
    with a._dblock:
        a._db.execute("UPDATE raw SET off=?, len=? WHERE event_id='evt-a'", (ia["off"], ia["len"]))
        a._db.commit()
    assert a.get("evt-a")["raw"] == b"first original log"
    # 2. flip one ciphertext byte
    data = bytearray(seg.read_bytes())
    data[ia["off"] + 20] ^= 0x01
    seg.write_bytes(bytes(data))
    with pytest.raises(ArchiveError):
        a.get("evt-a")
    assert a.get("evt-b")["intact"]
    # 3. wrong key
    a.close()
    b = RawArchive(str(tmp_path / "raw"), parse_key(base64.b64encode(os.urandom(32)).decode()))
    with pytest.raises(ArchiveError):
        b.get("evt-b")
    b.close()


def test_plaintext_requires_explicit_opt_in(tmp_path):
    with pytest.raises(ArchiveError):
        RawArchive(str(tmp_path / "r1"), None)
    p = RawArchive(str(tmp_path / "r2"), None, require_key=False)
    p.put("e", b"plain", None)
    p.flush()
    assert p.get("e")["raw"] == b"plain" and not p.encrypted
    p.close()
    s = Settings(alert_db_path=":memory:", raw_archive_enabled=True, raw_archive_dir=str(tmp_path / "r3"))
    with pytest.raises(ArchiveError):
        Pipeline(InMemoryBus(10), MetricsRegistry(), s)                   # PII redaction on + no key: refuses to start


def test_retention_deletes_whole_segments_and_their_index(tmp_path):
    a = arch(tmp_path, retention_days=30)
    a.put("old-1", b"old log", None)
    a.flush()
    old_seg = next((tmp_path / "raw").glob("seg-*.bin"))
    a._seg = None                                                        # roll to a new segment for the next write
    time.sleep(0.01)
    a.put("new-1", b"new log", None)
    a.flush()
    t = time.time() - 40 * 86400
    os.utime(old_seg, (t, t))
    assert a.purge_expired() == 1 and not old_seg.exists()
    assert a.get("old-1") is None and a.get("new-1")["raw"] == b"new log"
    a.close()


def test_full_queue_is_counted_not_silent(tmp_path):
    a = arch(tmp_path, queue_max=2)
    with a._dblock:                                                      # stall the writer thread after its first file write
        for i in range(50):
            a.put(f"e{i}", b"x", None)
            time.sleep(0.001)
        assert a.c["dropped"] > 0
    a.close()


def test_throughput_sanity(tmp_path):
    a = arch(tmp_path)
    t = time.perf_counter()
    for i in range(5000):
        a.put(f"e{i}", b"<38>Oct 11 22:14:15 web-01 sshd[41]: Failed password for bob from 185.220.101.4 port 22 ssh2", {"event": {"id": i}})
    enqueue = time.perf_counter() - t
    a.flush(30)
    assert a.stats()["records_indexed"] == 5000 and enqueue < 1.0       # the pipeline thread only enqueues
    a.close()


# ---- end to end: pipeline -> archive -> trace API -------------------------------------------------------------------
def make_app(tmp_path, **kw):
    base = dict(mock_enabled=False, alert_db_path=":memory:", dlq_path=str(tmp_path / "dlq.jsonl"), raw_archive_enabled=True,
                raw_archive_dir=str(tmp_path / "raw"), raw_archive_key=KEY, audit_db_path=str(tmp_path / "au.db"))
    base.update(kw)
    return create_app(Settings(**base))


def test_trace_proves_raw_to_normalized_link(tmp_path):
    raw = "<38>Oct 11 22:14:15 web-01 sshd[41]: Failed password for bob from 185.220.101.4 port 22 secret=hunter2 mail bob@example.com"
    with TestClient(make_app(tmp_path)) as c:
        c.post("/api/v1/ingest", json={"logs": [raw]})
        for _ in range(100):
            items = c.get("/api/v1/logs/recent").json()["items"]
            if items:
                break
            time.sleep(0.05)
        d = items[0]
        eid = d["event"]["id"]
        assert "bob@example.com" not in d["event"]["original"]                              # the document is redacted ...
        t = c.get(f"/api/v1/trace/{eid}").json()
        assert t["verdict"] == "verified" and all(v for v in t["checks"].values())
        assert t["raw"]["sha256"] == d["event"]["hash"] == hashlib.sha256(raw.encode()).hexdigest()
        assert "text" not in t["raw"]                                                        # ... and raw is not returned by default
        r = c.get(f"/api/v1/trace/{eid}?include_raw=true").json()
        assert "bob@example.com" in r["raw"]["text"] and r["raw"]["text"] == raw            # ... but is recoverable by an admin
        assert any(x["action"] == "trace.raw" and x["outcome"] == "allowed" for x in c.get("/api/v1/audit").json()["items"])
        assert c.get("/api/v1/trace/does-not-exist").status_code == 404
        assert c.get("/api/v1/archive").json()["encrypted"] is True
        # sealed batch reference once 100 records arrived
        c.post("/api/v1/ingest", json={"logs": [raw.replace("41", str(i)) for i in range(120)]})
        for _ in range(100):
            if c.get("/api/v1/integrity/batches").json()["items"]:
                break
            time.sleep(0.05)
        t2 = c.get(f"/api/v1/trace/{eid}").json()
        assert t2["integrity_reference"]["batch_id"] == "batch-000001" and t2["integrity_reference"]["anchor_tx_id"]


def test_raw_access_needs_admin_under_rbac(tmp_path):
    secret = "s" * 40
    with TestClient(make_app(tmp_path, auth_mode="jwt", jwt_secret=secret)) as c:
        def hdr(role):
            return {"Authorization": "Bearer " + tokens.encode({"sub": role, "exp": time.time() + 60, "roles": [role]}, secret)}
        assert c.post("/api/v1/parse", json={"log": "<38>Oct 11 22:14:15 h a[1]: hello"}, headers=hdr("analyst")).status_code == 200
        eid = c.get("/api/v1/logs/recent", headers=hdr("analyst")).json()["items"][0]["event"]["id"]
        time.sleep(0.5)
        assert c.get(f"/api/v1/trace/{eid}", headers=hdr("analyst")).status_code == 200
        assert c.get(f"/api/v1/trace/{eid}?include_raw=true", headers=hdr("analyst")).status_code == 403
        assert c.get(f"/api/v1/trace/{eid}?include_raw=true", headers=hdr("admin")).status_code == 200
        assert c.get(f"/api/v1/trace/{eid}", headers=hdr("viewer")).status_code == 403
