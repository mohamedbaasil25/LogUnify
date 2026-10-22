import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.mock.generators import gen_cef, gen_json, gen_syslog, gen_text
from app.parsers.base import ParseError
from app.parsers.detect import parse_auto
from app.ecs.normalizer import to_ecs

SYSLOG_3164 = "<38>Oct 11 22:14:15 web-01 sshd[123]: Failed password for invalid user bob from 185.220.101.4 port 22 ssh2"
SYSLOG_5424 = "<165>1 2024-10-11T22:14:15.003Z fw-01 app 42 ID47 - hello world"
CEF = "CEF:0|Acme|NGFW|1.0|100|Port scan|5|src=1.2.3.4 dst=10.0.0.5 dpt=22 act=blocked msg=scan detected"
JSON = '{"timestamp":"2024-10-11T22:14:15Z","host":"web-01","src_ip":"8.8.8.8","level":"warn","message":"hi","extra":{"a":1}}'


def test_syslog_3164_to_ecs():
    d = to_ecs(parse_auto(SYSLOG_3164))
    assert d["host"]["name"] == "web-01" and d["source"]["ip"] == "185.220.101.4"
    assert d["user"]["name"] == "bob" and d["event"]["outcome"] == "failure"
    assert d["log"]["level"] == "info" and d["event"]["severity"] == 6   # PRI 38 = auth.info
    assert d["ecs"]["version"] and d["logunify"]["source_format"] == "syslog"


def test_syslog_5424():
    d = to_ecs(parse_auto(SYSLOG_5424))
    assert d["@timestamp"].startswith("2024-10-11T22:14:15") and d["process"]["pid"] == 42


def test_cef():
    d = to_ecs(parse_auto(CEF))
    assert d["destination"]["port"] == 22 and d["observer"]["vendor"] == "Acme"
    assert d["event"]["severity"] == 5 and d["message"] == "scan detected"


def test_json_flatten_and_labels():
    d = to_ecs(parse_auto(JSON))
    assert d["source"]["ip"] == "8.8.8.8" and d["labels"]["extra"]["a"] == 1


@pytest.mark.parametrize("bad", ["", "   ", "{nope", "CEF:0|a|b", "<999>Jan  1 00:00:00 h a: x"])
def test_bad_inputs_raise(bad):
    with pytest.raises(ParseError):
        parse_auto(bad)


def test_generators_parse():
    for _ in range(50):
        for g in (gen_syslog, gen_json, gen_cef, gen_text):
            parse_auto(g())


@pytest.fixture
def client():
    app = create_app(Settings(mock_enabled=False))
    with TestClient(app) as c:
        yield c


def test_ingest_roundtrip_and_metrics(client):
    r = client.post("/api/v1/ingest", json={"logs": [SYSLOG_3164, SYSLOG_5424, CEF, JSON, "{garbage"]})
    assert r.status_code == 202 and r.json()["accepted"] == 5
    for _ in range(50):
        if client.get("/api/v1/metrics").json()["received"] >= 5 and \
           client.get("/api/v1/metrics").json()["processed"] + client.get("/api/v1/metrics/dead-lettered").json()["total"] >= 5:
            break
        time.sleep(0.05)
    m = client.get("/api/v1/metrics").json()
    assert m["processed"] == 4 and m["dropped"] == 0 and m["dead_lettered"] == 1   # the garbage line is kept, not dropped
    assert m["reconciliation"]["unaccounted"] == 0
    assert m["by_format"] == {"syslog": 2, "cef": 1, "json": 1}
    assert m["compression_ratio"] > 0
    assert client.get("/api/v1/metrics/dead-lettered").json()["by_reason"]
    assert len(client.get("/api/v1/logs/recent?limit=10").json()["items"]) == 4
    assert client.get("/api/v1/logs/recent?format=cef").json()["count"] == 1
    assert len(client.get("/api/v1/metrics/throughput?window=10").json()["series"]) == 10


def test_parse_preview(client):
    r = client.post("/api/v1/parse", json={"log": CEF, "format": "cef"}).json()
    assert r["ok"] and r["ecs"]["source"]["ip"] == "1.2.3.4"
    assert client.post("/api/v1/parse", json={"log": "{nope"}).json()["ok"] is False
    assert client.post("/api/v1/parse", json={"log": "plain text works"}).json()["ecs"]["logunify"]["source_format"] == "text"
    assert client.get("/api/v1/system").json()["bus"] == "memory" and client.get("/health").json() == {"status": "ok"}


def test_oversize_dropped():
    app = create_app(Settings(mock_enabled=False, max_raw_bytes=50))
    with TestClient(app) as c:
        r = c.post("/api/v1/ingest", json={"logs": [CEF]}).json()
        assert r["rejected"] == 1
        assert c.get("/api/v1/metrics/dropped").json()["by_reason"] == {"oversize": 1}
