import time

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.security import tokens
from app.security.audit import AuditLog
from app.security.hardening import FailureLimiter, Hardening, RequestRateLimiter

SECRET = "s" * 40
LOG = "<38>Oct 11 22:14:15 web-01 sshd[41]: Failed password for bob from 185.220.101.4 port 22 ssh2"


def app_for(tmp_path, **kw):
    base = dict(mock_enabled=False, alert_db_path=":memory:", dlq_path=str(tmp_path / "dlq.jsonl"), audit_db_path=":memory:")
    base.update(kw)
    return create_app(Settings(**base))


def hdr(role="admin"):
    return {"Authorization": "Bearer " + tokens.encode({"sub": role, "exp": time.time() + 60, "roles": [role]}, SECRET)}


# ---- headers, docs, health ------------------------------------------------------------------------------------------
def test_security_headers_on_every_reply_including_errors(tmp_path):
    with TestClient(app_for(tmp_path, max_body_bytes=1000)) as c:
        for r in (c.get("/health"), c.get("/api/v1/metrics"), c.get("/nope"),
                  c.post("/api/v1/parse", content=b"x" * 5000, headers={"content-type": "application/json"})):
            assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
            assert r.headers["referrer-policy"] == "no-referrer"
        assert c.get("/api/v1/metrics").headers["cache-control"] == "no-store"
        assert "strict-transport-security" not in c.get("/health").headers
    with TestClient(app_for(tmp_path, hsts_enabled=True)) as c:
        assert "max-age" in c.get("/health").headers["strict-transport-security"]


def test_api_docs_are_off_by_default(tmp_path):
    with TestClient(app_for(tmp_path)) as c:
        assert [c.get(p).status_code for p in ("/docs", "/redoc", "/openapi.json")] == [404, 404, 404]
    with TestClient(app_for(tmp_path, docs_enabled=True)) as c:
        assert c.get("/docs").status_code == 200 and c.get("/openapi.json").status_code == 200


def test_public_probes_reveal_nothing_and_detail_needs_auth(tmp_path):
    with TestClient(app_for(tmp_path, auth_mode="jwt", jwt_secret=SECRET)) as c:
        assert c.get("/health").json() == {"status": "ok"} and c.get("/ready").json() == {"ready": True}
        assert c.get("/api/v1/system").status_code == 401
        info = c.get("/api/v1/system", headers=hdr("viewer")).json()
        assert info["version"] == "1.0.0" and info["auth_mode"] == "jwt" and info["docs_enabled"] is False


# ---- body size ------------------------------------------------------------------------------------------------------
def test_body_limit_by_content_length_and_while_streaming(tmp_path):
    with TestClient(app_for(tmp_path, max_body_bytes=2000)) as c:
        ok = c.post("/api/v1/parse", json={"log": LOG})
        assert ok.status_code == 200
        big = c.post("/api/v1/parse", content=b'{"log":"' + b"a" * 5000 + b'"}', headers={"content-type": "application/json"})
        assert big.status_code == 413
        def chunks():                                   # no Content-Length: chunked upload, the limit is enforced as it streams
            for _ in range(10):
                yield b"a" * 1000
        chunked = c.post("/api/v1/parse", content=chunks(), headers={"content-type": "application/json"})
        assert chunked.status_code == 413


def test_parse_endpoint_honours_the_per_log_limit(tmp_path):
    with TestClient(app_for(tmp_path, max_raw_bytes=500)) as c:
        r = c.post("/api/v1/parse", json={"log": "x" * 3000})
        assert r.status_code == 413
        assert c.get("/api/v1/metrics/dropped").json()["by_reason"] == {"oversize": 1}


# ---- brute-force lockout --------------------------------------------------------------------------------------------
def test_alert_api_key_guessing_is_locked_out_even_for_the_right_key(tmp_path):
    with TestClient(app_for(tmp_path, alert_api_key="right-key-123456", auth_fail_max=5)) as c:
        good = {"X-API-Key": "right-key-123456"}
        assert c.get("/api/v1/alerts", headers=good).status_code == 200
        codes = [c.get("/api/v1/alerts", headers={"X-API-Key": f"guess{i}"}).status_code for i in range(5)]
        assert codes == [401] * 5
        locked = c.get("/api/v1/alerts", headers=good)
        assert locked.status_code == 429 and int(locked.headers["retry-after"]) > 0       # guessing gets no oracle, no free attempts


def test_a_few_typos_do_not_lock_and_success_resets_the_counter(tmp_path):
    with TestClient(app_for(tmp_path, alert_api_key="right-key-123456", auth_fail_max=5)) as c:
        for _ in range(3):
            assert c.get("/api/v1/alerts", headers={"X-API-Key": "typo"}).status_code == 401
        assert c.get("/api/v1/alerts", headers={"X-API-Key": "right-key-123456"}).status_code == 200
        for _ in range(4):
            assert c.get("/api/v1/alerts", headers={"X-API-Key": "typo"}).status_code == 401      # counter restarted after the success


def test_source_token_lockout_is_per_source_and_client(tmp_path):
    with TestClient(app_for(tmp_path, auth_fail_max=4)) as c:
        a = c.post("/api/v1/sources", json={"name": "feed-a", "type": "http"}).json()
        b = c.post("/api/v1/sources", json={"name": "feed-b", "type": "http"}).json()
        for i in range(4):
            assert c.post(f"/api/v1/sources/{a['id']}/ingest", json={"logs": ["x"]}, headers={"X-Source-Token": f"bad{i}"}).status_code == 401
        assert c.post(f"/api/v1/sources/{a['id']}/ingest", json={"logs": ["x"]}, headers={"X-Source-Token": a["token"]}).status_code == 429
        assert c.post(f"/api/v1/sources/{b['id']}/ingest", json={"logs": ["x"]}, headers={"X-Source-Token": b["token"]}).status_code == 202
        for i in range(10):                                                                   # enumeration of unknown ids is throttled too
            c.post("/api/v1/sources/src-00000000/ingest", json={"logs": ["x"]}, headers={"X-Source-Token": "t"})
        assert c.post("/api/v1/sources/src-00000000/ingest", json={"logs": ["x"]}, headers={"X-Source-Token": "t"}).status_code == 429


def test_failure_limiter_unit():
    lim = FailureLimiter(max_failures=3, window_s=10, lock_s=60, max_keys=5)
    assert not lim.fail("k", now=0) and not lim.fail("k", now=1) and lim.fail("k", now=2)
    assert lim.locked("k", now=30) > 0 and lim.locked("k", now=63) == 0                         # expires
    lim.fail("w", now=0)
    lim.fail("w", now=1)
    assert not lim.fail("w", now=20)                                                          # old failures fell out of the window
    lim.success("w")
    for i in range(20):
        lim.fail(("other", i), now=0)
    assert len(lim._d) <= 5                                                                   # bounded memory


# ---- client identity ------------------------------------------------------------------------------------------------
def test_x_forwarded_for_is_only_believed_from_trusted_proxies():
    h = Hardening(Settings(trusted_proxies="10.0.0.0/8,127.0.0.1"))

    def scope(peer, xff=None):
        return {"client": (peer, 1234), "headers": [(b"x-forwarded-for", xff.encode())] if xff else []}
    assert h.client_ip(scope("203.0.113.9", "1.2.3.4")) == "203.0.113.9"                      # untrusted peer: spoofed header ignored
    assert h.client_ip(scope("10.0.0.5", "198.51.100.7")) == "198.51.100.7"                   # trusted proxy: believe it
    assert h.client_ip(scope("10.0.0.5", "6.6.6.6, 198.51.100.7, 10.0.0.9")) == "198.51.100.7"   # right-most untrusted hop, not the forgeable left
    assert h.client_ip(scope("10.0.0.5")) == "10.0.0.5"
    assert Hardening(Settings()).client_ip(scope("10.0.0.5", "1.1.1.1")) == "10.0.0.5"        # default: no trusted proxies


# ---- request-rate limit ---------------------------------------------------------------------------------------------
def test_request_rate_limit_with_exemptions(tmp_path):
    with TestClient(app_for(tmp_path, rate_limit_per_min=5)) as c:
        codes = [c.get("/api/v1/metrics").status_code for _ in range(8)]
        assert codes[:5] == [200] * 5 and codes[5:] == [429] * 3
        r = c.get("/api/v1/metrics")
        assert int(r.headers["retry-after"]) >= 1 and r.headers["x-content-type-options"] == "nosniff"
        assert c.get("/health").status_code == 200 and c.get("/ready").status_code == 200
    lim = RequestRateLimiter(2)
    assert [lim.allow("a", now=0)[0], lim.allow("a", now=1)[0], lim.allow("a", now=2)[0]] == [True, True, False]
    assert lim.allow("a", now=61)[0] and lim.allow("b", now=2)[0]


# ---- audit flood protection -----------------------------------------------------------------------------------------
def test_failed_login_flood_does_not_bloat_the_audit_log(tmp_path):
    with TestClient(app_for(tmp_path, auth_mode="jwt", jwt_secret=SECRET)) as c:
        for _ in range(100):
            assert c.get("/api/v1/metrics", headers={"Authorization": "Bearer junk"}).status_code == 401
        rows = [r for r in c.app.state.audit.list(limit=500) if r["outcome"] == "denied:401"]
        assert len(rows) == 1                                                                 # one row per client per 30 s window
        assert c.app.state.audit.verify()["valid"]


def test_audit_sampling_memory_is_bounded():
    a = AuditLog(":memory:")
    for i in range(25_000):
        a._last[("u", "act", str(i), "denied:401")] = [0.0, 0]
    a.append("x", "none", "none", "act", "/p", "denied:401", "1.1.1.1", {}, sample_s=30, sample_key="k")
    assert len(a._last) <= 20_000


def test_rotating_client_identities_cannot_bypass_sampling_forever(tmp_path):
    with TestClient(app_for(tmp_path, auth_mode="jwt", jwt_secret=SECRET)) as c:
        audit = c.app.state.audit
        for i in range(5):                                                                    # five distinct clients: five rows (bounded by clients)
            audit.append("unauthenticated", "none", "none", "metrics.view", "/x", "denied:401", f"198.51.100.{i}", {}, sample_s=30,
                         sample_key=f"198.51.100.{i}")
            audit.append("unauthenticated", "none", "none", "metrics.view", "/x", "denied:401", f"198.51.100.{i}", {}, sample_s=30,
                         sample_key=f"198.51.100.{i}")
        assert len([r for r in audit.list(limit=100) if r["outcome"] == "denied:401"]) == 5
