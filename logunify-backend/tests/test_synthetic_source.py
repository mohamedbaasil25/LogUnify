"""Sources tagged `synthetic` (test / drill feeds): labelled, never teach the model, left out of calibration, flagged on the alerts they raise."""
import json

import pytest
from fastapi.testclient import TestClient

from app.intel.anomaly import AnomalyScorer
from app.intel.engine import LogIntelligence
from app.main import create_app
from app.parsers.base import ParsedLog
from tests.alert_helpers import FakeNotifier
from tests.test_alert_api import KEY, settings, wait_for

WIN = {"EventTime": "2026-10-01 09:00:00", "Hostname": "WS-1.corp.example.com", "Channel": "Security", "EventID": 1102, "SourceName": "x",
       "SubjectUserName": "bob", "Message": "The audit log was cleared."}


def pl(msg: str) -> ParsedLog:
    return ParsedLog(format="text", original=msg, message=msg, fields={})


# ------------------------------------------------------------------------------------------------ the ML core
def test_no_learn_scores_but_does_not_change_the_model():
    li = LogIntelligence(warmup=50, settle=10)
    for i in range(300):
        li.analyze(pl(f"user{i % 7} logged in from 10.0.0.{i % 200} port {1000 + i}"))
    before = (li.miner.total, li.miner.cluster_count, li.scorer.samples)
    out = li.analyze_many([pl(f"completely new drill message number {i} about wibble {i * 3}") for i in range(40)], no_learn=[True] * 40)
    assert (li.miner.total, li.miner.cluster_count, li.scorer.samples) == before          # templates, counts and the training window untouched
    assert len(out) == 40 and all(isinstance(a.score, float) and a.is_new_template for a in out)    # still scored, and unknown templates are reported as new
    li.analyze_many([pl("user3 logged in from 10.0.0.9 port 4444")], no_learn=[False])
    assert li.miner.total == before[0] + 1                                                 # normal events still learn


def test_peek_returns_the_known_template_without_counting_it():
    li = LogIntelligence(warmup=50, settle=10)
    for i in range(30):
        li.analyze(pl(f"disk /dev/sda{i % 3} usage at {i} percent"))
    tid, size = li.miner.mine("disk /dev/sda1 usage at 77 percent").cluster_id, None
    sizes = {c["id"]: c["count"] for c in li.miner.top_templates(5)}
    m = li.miner.peek("disk /dev/sda2 usage at 91 percent")
    assert m.cluster_id == tid and not m.is_new
    assert {c["id"]: c["count"] for c in li.miner.top_templates(5)} == sizes and size is None


# ------------------------------------------------------------------------------------------------ end to end
@pytest.fixture
def env(tmp_path, monkeypatch):
    app = create_app(settings(tmp_path))
    fake = FakeNotifier()
    with TestClient(app) as c:
        app.state.pipeline.alerts.notifiers = [fake]
        c.headers.update({"X-API-Key": KEY})
        monkeypatch.setattr(app.state.pipeline.intel.scorer, "score_many", lambda rows, learn: [0.95] * len(rows))
        monkeypatch.setattr(AnomalyScorer, "ready", property(lambda self: True))
        yield c, app, fake


def make_source(c, name, tags):
    r = c.post("/api/v1/sources", json={"name": name, "type": "http", "format": "windows_security", "tags": tags}).json()
    return r["id"], r["token"]


def push(c, sid, token, host):
    line = json.dumps({**WIN, "Hostname": host})
    r = c.post(f"/api/v1/sources/{sid}/ingest", json={"logs": [line]}, headers={"X-Source-Token": token})
    assert r.status_code == 202, r.text


def test_synthetic_events_are_labelled_and_excluded_from_calibration_and_feedback(env):
    c, app, fake = env
    real, real_t = make_source(c, "real feed", ["windows"])
    syn, syn_t = make_source(c, "drill feed", ["Windows", "Synthetic"])                     # tag match is case-insensitive
    push(c, real, real_t, "REAL-1.corp")
    push(c, syn, syn_t, "DRILL-1.corp")
    assert wait_for(lambda: len(fake.sent) >= 2)
    docs = {d["host"]["name"]: d for d in app.state.pipeline.recent}
    assert "synthetic" not in (docs["REAL-1.corp"].get("labels") or {}) and docs["DRILL-1.corp"]["labels"]["synthetic"] == "true"

    items = c.get("/api/v1/alerts", params={"status": "active"}).json()["items"]
    by_host = {a["host"]: a for a in items}
    assert by_host["DRILL-1.corp"]["synthetic"] is True and by_host["REAL-1.corp"]["synthetic"] is False
    drill_msg = next(m for m in fake.sent if "DRILL-1" in m.text or m.subject.startswith("[TEST FEED"))
    assert drill_msg.subject.startswith("[TEST FEED")                                       # nobody mistakes a drill for an incident
    assert not next(m for m in fake.sent if m is not drill_msg).subject.startswith("[TEST FEED")

    rep = c.get("/api/v1/alerts-calibration").json()
    assert rep["replay"]["coverage"]["synthetic_excluded"] == 1 and rep["replay"]["coverage"]["events_in_scope"] == 1
    assert {a["asset"] for a in rep["replay"]["preview"]["items"]} == {"REAL-1.corp"}
    assert rep["feedback"]["synthetic_alerts_excluded"] == 1 and rep["feedback"]["alerts_total"] == 1
    inc = c.get("/api/v1/alerts-calibration", params={"include_synthetic": "true"}).json()
    assert inc["replay"]["coverage"]["events_in_scope"] == 2 and inc["feedback"]["alerts_total"] == 2
    assert inc["scope"]["include_synthetic"] is True


def test_synthetic_feed_does_not_teach_the_model(env):
    c, app, _ = env
    intel = app.state.pipeline.intel
    real, real_t = make_source(c, "real feed", [])
    syn, syn_t = make_source(c, "drill feed", ["synthetic"])
    push(c, real, real_t, "R1")
    assert wait_for(lambda: intel.miner.total >= 1)
    base = (intel.miner.total, intel.miner.cluster_count, intel.scorer.samples)
    for i in range(20):
        push(c, syn, syn_t, f"D{i}")
    assert wait_for(lambda: app.state.pipeline.metrics.processed >= 21)
    assert (intel.miner.total, intel.miner.cluster_count, intel.scorer.samples) == base
    push(c, real, real_t, "R2")
    assert wait_for(lambda: intel.miner.total == base[0] + 1)                               # real events still count
