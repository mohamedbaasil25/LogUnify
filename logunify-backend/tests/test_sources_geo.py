import time

from fastapi.testclient import TestClient

from app.config import Settings
from app.enrich.geoip import lookup
from app.main import create_app


def test_geoip_mock():
    assert lookup("10.1.2.3")["source.geo.country_name"] == "Internal"
    assert lookup("185.220.101.4")["source.geo.country_iso_code"] == "DE"
    assert lookup("77.88.99.11") == lookup("77.88.99.11") and lookup("77.88.99.11")["logunify.geoip"] == "mock"
    assert lookup("not-an-ip") == {} and lookup(None) == {}


def test_geo_and_noise_in_pipeline():
    with TestClient(create_app(Settings(mock_enabled=False))) as c:
        r = c.post("/api/v1/parse", json={"log": "<38>Oct 11 22:14:15 web-01 sshd[1]: Failed password for bob from 185.220.101.4 port 22 ssh2"})
        assert r.json()["ecs"]["source"]["geo"]["country_iso_code"] == "DE"
        for _ in range(30):
            c.post("/api/v1/parse", json={"log": "Cache refresh completed on web-01 in 55 ms"})
        m = c.get("/api/v1/metrics").json()
        assert m["templates"] >= 1 and 0 < m["noise_reduced_pct"] < 100


def test_source_lifecycle_and_ingest():
    with TestClient(create_app(Settings(mock_enabled=False))) as c:
        r = c.post("/api/v1/sources", json={"name": "Edge FW", "type": "http", "format": "cef", "tags": ["fw"]})
        assert r.status_code == 201
        s = r.json()
        assert s["token"] and s["status"] == "active" and s["config"]["ingest_path"].endswith("/ingest")
        assert c.get("/api/v1/sources").json()["items"][0]["token"] is None       # token never listed again
        assert c.post("/api/v1/sources", json={"name": "edge fw", "type": "http"}).status_code == 409

        cef = "CEF:0|Acme|NGFW|1.0|100|Port scan|5|src=1.2.3.4 dst=10.0.0.5 dpt=22"
        path = s["config"]["ingest_path"]
        assert c.post(path, json={"logs": [cef]}).status_code == 401
        assert c.post(path, json={"logs": [cef]}, headers={"X-Source-Token": "wrong"}).status_code == 401
        ok = c.post(path, json={"logs": [cef]}, headers={"X-Source-Token": s["token"]})
        assert ok.status_code == 202 and ok.json()["accepted"] == 1
        for _ in range(60):
            if c.get("/api/v1/metrics").json()["processed"] >= 1:
                break
            time.sleep(0.05)
        assert c.get("/api/v1/logs/recent").json()["items"][0]["logunify"]["source_format"] == "cef"
        assert c.get("/api/v1/sources").json()["items"][0]["received"] == 1
        assert c.delete(f"/api/v1/sources/{s['id']}").status_code == 204
        assert c.delete(f"/api/v1/sources/{s['id']}").status_code == 404


def test_source_validation():
    with TestClient(create_app(Settings(mock_enabled=False))) as c:
        post = lambda **b: c.post("/api/v1/sources", json={"name": "x1", **b})   # noqa: E731
        assert post(type="syslog").status_code == 422                               # port required
        ok = post(type="syslog", port=5514, protocol="tcp")
        assert ok.status_code == 201 and ok.json()["status"] in ("active", "registered") and ok.json()["token"] is None   # active once the listener binds
        assert c.post("/api/v1/sources", json={"name": "a2", "type": "api", "url": "http://x.com"}).status_code == 422
        for bad in ("https://127.0.0.1/x", "https://10.0.0.5/x", "https://localhost/x", "https://db.internal/x"):
            assert c.post("/api/v1/sources", json={"name": "a3", "type": "api", "url": bad}).status_code == 422
        good = c.post("/api/v1/sources", json={"name": "a4", "type": "api", "url": "https://api.vendor.com/logs"})
        assert good.status_code == 201
        assert c.post("/api/v1/sources", json={"name": "<script>", "type": "http"}).status_code == 422
