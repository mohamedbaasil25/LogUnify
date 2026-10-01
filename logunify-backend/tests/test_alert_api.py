import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.integrity.merkle import hash_record
from app.intel.anomaly import AnomalyScorer
from app.main import create_app
from tests.alert_helpers import FakeNotifier

KEY = "k3y-for-tests"
LOG = "Audit log cleared by user root on db-01 from 203.0.113.9 password=hunter2"


def settings(tmp_path, **kw) -> Settings:
    base = dict(mock_enabled=False, alert_db_path=str(tmp_path / "alerts.db"), alert_api_key=KEY, alert_retry_attempts=1,
                alert_maintenance_seconds=3600, org_name="Acme Bank Ltd", poc_name="Asha Rao", poc_designation="CISO",
                poc_email="ciso@acme.example", poc_mobile="+91 90000 00001", org_address="1 MG Road, Mumbai",
                org_location="Mumbai, Maharashtra, India")
    base.update(kw)
    return Settings(**base)


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


def wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def raise_alert(c, fake, log=LOG) -> str:
    before = len(fake.sent)
    assert c.post("/api/v1/parse", json={"log": log}).json()["ok"]
    assert wait_for(lambda: len(fake.sent) > before), "notification never delivered"
    return c.get("/api/v1/alerts", params={"status": "active", "limit": 1}).json()["items"][0]["id"]


# ------------------------------------------------------------------------------------------------ access control
def test_alert_api_is_disabled_without_a_key_and_protected_with_one(tmp_path):
    with TestClient(create_app(Settings(mock_enabled=False, alert_db_path=str(tmp_path / "a.db")))) as c:
        r = c.get("/api/v1/alerts")
        assert r.status_code == 503 and "LOGUNIFY_ALERT_API_KEY" in r.json()["detail"]
    with TestClient(create_app(settings(tmp_path))) as c:
        assert c.get("/api/v1/alerts").status_code == 401
        assert c.get("/api/v1/alerts", headers={"X-API-Key": "wrong"}).status_code == 401
        assert c.get("/api/v1/alerts", headers={"X-API-Key": "k3y-for-testsé".encode("latin-1")}).status_code == 401   # non-ASCII must not crash
        assert c.get("/api/v1/alerts", headers={"X-API-Key": KEY}).status_code == 200
        for method, path in (("post", "/api/v1/alerts/test"), ("get", "/api/v1/alerts/config"),
                             ("post", "/api/v1/alerts/ALR-x/ack"), ("get", "/api/v1/alerts/ALR-x/evidence")):
            assert getattr(c, method)(path).status_code == 401, path              # every route is behind the key


def test_alerting_can_be_switched_off(tmp_path):
    with TestClient(create_app(settings(tmp_path, alerting_enabled=False))) as c:
        assert c.get("/api/v1/alerts", headers={"X-API-Key": KEY}).status_code == 503
        assert c.get("/api/v1/metrics").json()["alerting"] == {"enabled": False}
        assert c.post("/api/v1/parse", json={"log": LOG}).json()["ok"] is True


# ------------------------------------------------------------------------------------------------ pipeline -> alert
def test_high_scoring_critical_log_raises_a_cert_in_alert_end_to_end(env):
    c, app, fake = env
    aid = raise_alert(c, fake)
    msg = fake.sent[0]
    assert msg.kind == "incident.detected" and msg.alert_id == aid
    doc_basis = c.get(f"/api/v1/alerts/{aid}/evidence").json()["record"]["logunify"]["mitre"]["basis"]
    assert doc_basis == "rule:log_clearing"                          # the real tagger chose T1070 from the log text

    active = c.get("/api/v1/alerts", params={"status": "active"}).json()["items"]
    assert len(active) == 1 and active[0]["technique"] == "T1070" and active[0]["score"] == 0.95
    assert 21_500 < active[0]["seconds_remaining"] <= 21_600 and active[0]["overdue"] is False

    report = c.get(f"/api/v1/alerts/{aid}/cert-in-report").json()
    assert report["reference"] == aid and report["deadline"]["report_due_at"]["ist"] and report["reporter"]["organization_name"] == "Acme Bank Ltd"
    assert report["incident_type"]["annexure_i"][0]["id"] == "ii" and report["affected_system"]["location"] == "Mumbai, Maharashtra, India"
    text = c.get(f"/api/v1/alerts/{aid}/cert-in-report", params={"format": "text"})
    assert text.headers["content-type"].startswith("text/plain") and "REPORT DUE BY" in text.text and "incident@cert-in.org.in" in text.text

    assert c.get("/api/v1/metrics").json()["alerting"]["triggered"] == 1


def test_notifications_are_redacted_but_the_evidence_endpoint_keeps_the_unredacted_log(env):
    c, app, fake = env
    aid = raise_alert(c, fake)
    leaked = fake.sent[0].text + str(fake.sent[0].payload) + fake.sent[0].attachment[1].decode()
    assert "hunter2" not in leaked and "[REDACTED]" in leaked                # CERT-In FAQ Q32: confidentiality duties unchanged
    ev = c.get(f"/api/v1/alerts/{aid}/evidence").json()
    assert "hunter2" in ev["record"]["event"]["original"]                    # logs must accompany the report (para iv)
    assert ev["record_sha256"] == hash_record(ev["record"]).hex() and len(ev["record_sha256"]) == 64
    assert ev["integrity_reference"] is None                                 # not yet in a sealed Merkle batch


def test_nothing_fires_at_the_threshold_or_for_the_placeholder_tag(env, monkeypatch):
    c, app, fake = env
    monkeypatch.setattr(app.state.pipeline.intel.scorer, "score_many", lambda rows, learn: [0.9] * len(rows))
    c.post("/api/v1/parse", json={"log": LOG})
    monkeypatch.setattr(app.state.pipeline.intel.scorer, "score_many", lambda rows, learn: [0.99] * len(rows))
    c.post("/api/v1/parse", json={"log": "Quarterly frobnication of widget 7 started by operator ops-9"})   # no rule matches: T1078 fallback
    c.post("/api/v1/parse", json={"log": "Failed password for bob from 185.220.101.4 port 22 ssh2"})        # T1110: not critical
    time.sleep(0.3)
    assert fake.sent == [] and c.get("/api/v1/alerts").json()["items"] == []


def test_an_alerting_bug_never_drops_the_log(env, monkeypatch):
    c, app, fake = env

    def boom(doc):
        raise RuntimeError("alerting exploded")

    monkeypatch.setattr(app.state.pipeline.alerts, "on_event", boom)
    before = c.get("/api/v1/metrics").json()["processed"]
    assert c.post("/api/v1/parse", json={"log": LOG}).json()["ok"] is True
    assert c.get("/api/v1/metrics").json()["processed"] == before + 1


# ------------------------------------------------------------------------------------------------ workflow over HTTP
def test_full_human_workflow_and_audit_trail(env):
    c, app, fake = env
    aid = raise_alert(c, fake)

    r = c.post(f"/api/v1/alerts/{aid}/ack", json={"by": "ravi", "note": "triage started"})
    assert r.status_code == 200 and r.json()["summary"]["status"] == "acknowledged" and r.json()["ack"]["by"] == "ravi"
    assert c.post(f"/api/v1/alerts/{aid}/ack", json={"by": "ravi"}).status_code == 409

    before = len(c.get(f"/api/v1/alerts/{aid}/cert-in-report").json()["completeness"]["needs_analyst"])
    r = c.patch(f"/api/v1/alerts/{aid}/details", json={
        "by": "ravi", "operating_system": "Ubuntu 22.04", "critical": True, "critical_details": "core database",
        "incident_type_ids": ["ii", "iii"], "impact": "audit trail lost for 40 minutes", "actions_taken": "host isolated"})
    assert r.status_code == 200 and len(r.json()["needs_analyst"]) < before
    rep = c.get(f"/api/v1/alerts/{aid}/cert-in-report").json()
    assert rep["affected_system"]["operating_system"] == "Ubuntu 22.04" and rep["affected_system_critical"]["answer"] == "Yes"
    assert [t["id"] for t in rep["incident_type"]["annexure_i"]] == ["ii", "iii"]

    assert c.post(f"/api/v1/alerts/{aid}/close", json={"by": "asha", "resolution": "resolved"}).status_code == 409   # not reported yet
    r = c.post(f"/api/v1/alerts/{aid}/report", json={"by": "asha", "via": "email", "reference": "CERT-IN/2026/0042",
                                                     "note": "sent to incident@cert-in.org.in with log evidence"})
    assert r.status_code == 200 and r.json()["summary"]["status"] == "reported"
    assert r.json()["reported"]["on_time"] is True and r.json()["reported"]["reference"] == "CERT-IN/2026/0042"
    assert c.get("/api/v1/alerts", params={"status": "active"}).json()["items"] == []
    assert c.post(f"/api/v1/alerts/{aid}/report", json={"by": "asha"}).status_code == 409

    assert c.post(f"/api/v1/alerts/{aid}/close", json={"by": "asha", "resolution": "resolved"}).status_code == 200
    assert [a["id"] for a in c.get("/api/v1/alerts", params={"status": "closed"}).json()["items"]] == [aid]
    events = c.get(f"/api/v1/alerts/{aid}/events").json()["items"]
    assert [(e["kind"], e["actor"]) for e in events] == [
        ("created", "system"), ("notified", "system"), ("acknowledged", "ravi"), ("details_updated", "ravi"),
        ("reported_to_cert_in", "asha"), ("closed", "asha")]
    assert events[2]["data"]["client"]                                              # who/where is recorded for accountability


def test_validation_and_error_mapping(env):
    c, app, fake = env
    aid = raise_alert(c, fake)
    for path in ("", "/cert-in-report", "/evidence", "/events"):
        assert c.get(f"/api/v1/alerts/ALR-does-not-exist{path}").status_code == 404
    assert c.post("/api/v1/alerts/ALR-nope/ack", json={"by": "ravi"}).status_code == 404
    assert c.post(f"/api/v1/alerts/{aid}/ack", json={"note": "no actor"}).status_code == 422             # 'by' is mandatory
    assert c.post(f"/api/v1/alerts/{aid}/ack", json={"by": "x"}).status_code == 422                       # too short to attribute
    assert c.patch(f"/api/v1/alerts/{aid}/details", json={"by": "ravi"}).status_code == 422               # nothing to change
    assert c.patch(f"/api/v1/alerts/{aid}/details", json={"by": "ravi", "password": "x"}).status_code == 422
    assert c.patch(f"/api/v1/alerts/{aid}/details", json={"by": "ravi", "incident_type_ids": ["zz"]}).status_code == 422
    assert c.patch(f"/api/v1/alerts/{aid}/details", json={"by": "ravi", "i_am": "someone"}).status_code == 422
    assert c.post(f"/api/v1/alerts/{aid}/report", json={"by": "asha", "via": "telepathy"}).status_code == 422
    assert c.post(f"/api/v1/alerts/{aid}/report", json={"by": "asha", "reported_at": "2999-01-01T00:00:00Z"}).status_code == 422
    assert c.post(f"/api/v1/alerts/{aid}/close", json={"by": "asha", "resolution": "false_positive", "note": "no"}).status_code == 422
    assert c.get("/api/v1/alerts", params={"status": "bogus"}).status_code == 422
    assert c.get("/api/v1/alerts", params={"limit": 0}).status_code == 422
    r = c.post(f"/api/v1/alerts/{aid}/close", json={"by": "asha", "resolution": "false_positive",
                                                    "note": "Verified benign: scheduled log rotation by ops, ticket CHG-123"})
    assert r.status_code == 200 and r.json()["closed"]["resolution"] == "false_positive"


def test_reported_at_can_backdate_within_the_window_and_records_lateness(env):
    c, app, fake = env
    aid = raise_alert(c, fake)
    r = c.post(f"/api/v1/alerts/{aid}/report", json={"by": "asha", "via": "phone"})
    assert r.json()["reported"]["via"] == "phone" and r.json()["reported"]["late_by_seconds"] is None


# ------------------------------------------------------------------------------------------------ operations
def test_config_and_channel_test_endpoints(env):
    c, app, fake = env
    cfg = c.get("/api/v1/alerts/config").json()
    assert cfg["score_threshold"] == 0.9 and cfg["deadline_hours"] == 6 and "T1070" in cfg["critical_techniques"]
    assert "T1110" not in cfg["critical_techniques"] and cfg["organization_configured"] is True
    assert KEY not in str(cfg)
    r = c.post("/api/v1/alerts/test")
    assert r.status_code == 200 and r.json()["channels"]["fake"] == {"ok": True}
    assert fake.sent[-1].kind == "test" and c.get("/api/v1/alerts").json()["items"] == []        # a test is not an incident

    app.state.pipeline.alerts.notifiers = []
    assert c.post("/api/v1/alerts/test").status_code == 409


def test_persisted_alert_survives_an_application_restart(tmp_path, monkeypatch):
    s = settings(tmp_path)
    app1 = create_app(s)
    fake = FakeNotifier()
    with TestClient(app1) as c:
        app1.state.pipeline.alerts.notifiers = [fake]
        monkeypatch.setattr(app1.state.pipeline.intel.scorer, "score_many", lambda rows, learn: [0.95] * len(rows))
        monkeypatch.setattr(AnomalyScorer, "ready", property(lambda self: True))
        c.headers.update({"X-API-Key": KEY})
        aid = raise_alert(c, fake)
        due = c.get(f"/api/v1/alerts/{aid}/cert-in-report").json()["deadline"]["report_due_at"]["utc"]
    with TestClient(create_app(s)) as c2:
        c2.headers.update({"X-API-Key": KEY})
        items = c2.get("/api/v1/alerts", params={"status": "active"}).json()["items"]
        assert [i["id"] for i in items] == [aid]
        assert c2.get(f"/api/v1/alerts/{aid}/cert-in-report").json()["deadline"]["report_due_at"]["utc"] == due   # same clock
        ev = c2.get(f"/api/v1/alerts/{aid}/evidence").json()
        assert ev["record"]["source"]["ip"] == "203.0.113.9" and ev["record_sha256"] == hash_record(ev["record"]).hex()
