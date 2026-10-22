"""Alert calibration: replay, funnel, sweep, feedback, recommendation, suppression rules (module + API)."""
import copy
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.alerting import calibration as cal
from app.alerting.rules import AlertRules
from app.main import create_app
from app.security import tokens
from tests.alert_helpers import FakeNotifier, make_doc
from tests.test_alert_api import KEY, settings

T0 = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
CRIT = "T1070,T1059"


def doc(minutes: float, host="db-01", score=0.95, tech="T1070", basis="rule:log_clearing", ready=True, **extra):
    d = make_doc(host={"name": host}, **extra)
    d["@timestamp"] = (T0 + timedelta(minutes=minutes)).isoformat()
    d["logunify"]["anomaly"] = {"score": score, "model_ready": ready}
    d["logunify"]["mitre"] = {"basis": basis}
    d["threat"]["technique"] = {"id": tech, "name": "x"} if tech else None
    if not tech:
        d.pop("threat")
    d["event"] = {"id": f"e-{host}-{minutes}", "original": "line"}
    return d


def rules(thr=0.9, crit=CRIT, require=True):
    return AlertRules(thr, crit, require)


# ------------------------------------------------------------------------------------------------ pure functions
def test_grouping_matches_production_quiet_period():
    docs = [doc(0), doc(5), doc(10), doc(100), doc(0, host="db-02")]
    g = cal.group_alerts(docs, rules(), dedup_s=30 * 60)
    # db-01: 0,5,10 are one alert; 100 is >30 min after 10 -> a second one; db-02 separate
    assert len(g["alerts"]) == 3 and g["events"] == 5
    assert sorted(a["occurrences"] for a in g["alerts"]) == [1, 1, 3]


def test_threshold_is_strictly_greater_and_sweep_is_monotonic():
    docs = [doc(i, host=f"h{i}", score=s) for i, s in enumerate([0.71, 0.76, 0.81, 0.86, 0.91, 0.96])]
    rows = cal.sweep(docs, rules(0.9), 1800)
    by = {r["threshold"]: r["alerts"] for r in rows}
    assert by == {0.7: 6, 0.75: 5, 0.8: 4, 0.85: 3, 0.9: 2, 0.95: 1}
    assert all(a["alerts"] >= b["alerts"] for a, b in zip(rows, rows[1:]))
    assert cal.sweep(docs, rules(0.9), 1800, thresholds=(0.91,))[0]["alerts"] == 1               # 0.91 is NOT greater than 0.91


def test_funnel_explains_why_nothing_fires_and_agrees_with_the_rules():
    docs = [doc(0, ready=False),                                   # warming up
            doc(1, score=0.5),                                     # below threshold
            doc(2, tech=None),                                     # no technique
            doc(3, basis="default"),                               # placeholder tag
            doc(4, tech="T1110"),                                  # not critical
            doc(5, host="ok-1"), doc(6, host="ok-2")]
    f = {s["step"]: s["count"] for s in cal.funnel(docs, rules())}
    assert list(f.values()) == [7, 6, 5, 4, 3, 2, 2] and f["not suppressed"] == cal.group_alerts(docs, rules(), 1800)["events"]
    assert cal.funnel(docs, rules(require=False))[4]["count"] == 4                                # fallback allowed -> one more survives


def test_suppression_matching_and_expiry():
    now = T0.timestamp()
    sup = [{"id": "S1", "technique": "T1070", "asset": "backup-*", "expires_at": now + 100, "revoked_at": None},
           {"id": "S2", "technique": "*", "asset": "lab-1", "expires_at": now - 1, "revoked_at": None},
           {"id": "S3", "technique": "T1059", "asset": "*", "expires_at": now + 100, "revoked_at": now}]
    assert cal.is_suppressed(sup, "T1070.001", doc(0, host="Backup-02"), now)["id"] == "S1"       # parent covers sub-technique, case-insensitive
    assert cal.is_suppressed(sup, "T1059", doc(0, host="backup-02"), now) is None                  # other technique
    assert cal.is_suppressed(sup, "T1070", doc(0, host="db-01"), now) is None                      # other asset
    assert cal.is_suppressed(sup, "T1070", doc(0, host="lab-1"), now) is None                      # expired
    g = cal.group_alerts([doc(0, host="backup-01"), doc(0, host="db-01")], rules(), 1800, sup, now)
    assert len(g["alerts"]) == 1 and g["suppressed"] == 1


def test_confidence_and_recommendation_are_honest_about_short_windows():
    assert cal.confidence(300, 1800)["level"] == "low" and "too little" in cal.confidence(300, 1800)["why"]
    assert cal.confidence(9000, 4 * 86400)["level"] == "high"
    rows = [{"threshold": t, "alerts": a} for t, a in [(0.7, 100), (0.75, 40), (0.8, 10), (0.85, 4), (0.9, 0)]]
    r = cal.recommend(copy.deepcopy(rows), 86400, capacity_per_day=20, current=0.9)
    assert r["threshold"] == 0.8 and "LOGUNIFY_ALERT_SCORE_THRESHOLD=0.8" in r["text"] and "not changed from here" in r["text"]
    assert cal.recommend(copy.deepcopy(rows), 86400, 5, 0.85)["text"].startswith("Current threshold 0.85 already")
    assert cal.recommend(copy.deepcopy(rows), 86400, 0.5, 0.9)["threshold"] == 0.9
    assert cal.recommend(copy.deepcopy(rows), 600, 20, 0.9)["threshold"] is None                  # under an hour: no projection
    rows2 = [{"threshold": 0.9, "alerts": 5000}]
    assert "do not raise the threshold just to hide volume" in cal.recommend(rows2, 86400, 20, 0.9)["text"]


def test_histogram_and_percentiles():
    h = cal.histogram([0.0, 0.049, 0.05, 0.999, 1.0])
    assert sum(b["count"] for b in h) == 5 and h[0]["count"] == 2 and h[1]["count"] == 1 and h[-1]["count"] == 2
    assert cal.percentiles([]) == {} and cal.percentiles([0.1, 0.2, 0.3])["max"] == 0.3


# ------------------------------------------------------------------------------------------------ API
@pytest.fixture
def env(tmp_path, monkeypatch):
    app = create_app(settings(tmp_path, alert_score_threshold=0.9))
    fake = FakeNotifier()
    with TestClient(app) as c:
        app.state.pipeline.alerts.notifiers = [fake]
        c.headers.update({"X-API-Key": KEY})
        yield c, app, fake


def load(app, docs):
    app.state.pipeline.recent.extend(docs)


def test_calibration_endpoint_replay_preview_and_candidates(env):
    c, app, _ = env
    scores = [0.72, 0.78, 0.83, 0.88, 0.93, 0.97]
    load(app, [doc(i * 50, host=f"srv-{i}", score=s) for i, s in enumerate(scores)] + [doc(10, host="x", ready=False)])
    r = c.get("/api/v1/alerts-calibration").json()
    assert r["configured"]["threshold"] == 0.9 and r["candidate"]["threshold"] == 0.9
    rp = r["replay"]
    by = {row["threshold"]: row["alerts"] for row in rp["sweep"]}
    assert by[0.9] == 2 and by[0.7] == 6 and rp["preview"]["alerts"] == 2
    assert rp["model_ready_events"] == 6 and rp["confidence"]["level"] == "low" and rp["coverage"]["events_in_scope"] == 7
    assert [s["count"] for s in rp["funnel"]][:3] == [7, 6, 2]
    cand = c.get("/api/v1/alerts-calibration", params={"threshold": 0.8, "critical": "T1059"}).json()["replay"]
    assert cand["preview"]["alerts"] == 0                                                          # critical set narrowed to T1059
    assert c.get("/api/v1/alerts-calibration", params={"threshold": 0.8}).json()["replay"]["preview"]["alerts"] == 4
    assert c.get("/api/v1/alerts-calibration", params={"critical": "bogus"}).status_code == 422
    assert c.get("/api/v1/alerts-calibration", params={"from": "later"}).status_code == 422
    assert c.get("/api/v1/alerts-calibration", params={"threshold": 1.5}).status_code == 422
    assert c.get("/api/v1/alerts-calibration", params={"format": "text"}).json()["replay"]["coverage"]["events_in_scope"] == 7


def test_calibration_scopes_by_parser(env):
    c, app, _ = env
    a, b = doc(0, host="w1"), doc(1, host="f1")
    a["logunify"]["source_format"], b["logunify"]["source_format"] = "windows_security", "fortinet_fortigate"
    load(app, [a, b])
    r = c.get("/api/v1/alerts-calibration", params={"format": "windows_security"}).json()["replay"]
    assert r["coverage"]["events_in_scope"] == 1 and r["preview"]["items"][0]["asset"] == "w1"


def test_feedback_comes_from_closed_alerts(env):
    c, app, fake = env
    m = app.state.pipeline.alerts
    for host, res, note in [("srv-a", "false_positive", "backup job clears logs nightly"), ("srv-a", "false_positive", "backup job clears logs nightly"),
                            ("srv-a", "false_positive", "backup job clears logs nightly"), ("srv-b", "not_reportable", "test environment, no impact")]:
        m.dedup_s = 0
        assert m.on_event(make_doc(host={"name": host}, event={"id": f"e-{host}-{time.time()}"}))
        aid = c.get("/api/v1/alerts", params={"status": "active", "limit": 1}).json()["items"][0]["id"]
        m.close(aid, "asha", res, note)
        time.sleep(0.01)
    fb = c.get("/api/v1/alerts-calibration").json()["feedback"]
    assert fb["closed"] == 4 and fb["resolutions"] == {"false_positive": 3, "not_reportable": 1} and fb["false_positive_rate"] == 0.75
    top = fb["noisiest_assets"][0]
    assert (top["asset"], top["false_positive"], top["candidate"]) == ("srv-a", 3, True)            # 3 FPs and never a real one -> suggest suppression
    assert fb["techniques"][0]["technique"] == "T1070" and fb["techniques"][0]["fp_rate"] == 0.75
    assert fb["per_day"][-1]["alerts"] == 4 and fb["cert_in"]["reported"] == 0 and fb["cert_in"]["on_time_rate"] is None


def test_suppression_lifecycle_stops_alerts_but_counts_them(env):
    c, app, fake = env
    m = app.state.pipeline.alerts
    body = {"technique": "t1070", "asset": "backup-*", "reason": "nightly backup rotates the audit log", "days": 14}
    r = c.post("/api/v1/suppressions", json=body)
    assert r.status_code == 201 and r.json()["technique"] == "T1070" and r.json()["expires_at"] > time.time() + 13 * 86400
    sid = r.json()["id"]
    assert m.on_event(make_doc(host={"name": "backup-02"}, event={"id": "s1"})) is None            # suppressed: no alert
    assert m.on_event(make_doc(host={"name": "db-01"}, event={"id": "s2"})) is not None             # others still alert
    item = next(s for s in c.get("/api/v1/suppressions").json()["items"] if s["id"] == sid)
    assert item["hits"] == 1 and item["active"] and item["last_event_id"] == "s1"
    cal_ = c.get("/api/v1/alerts-calibration").json()
    assert cal_["suppressions"][0]["id"] == sid
    assert c.delete(f"/api/v1/suppressions/{sid}").json()["revoked_by"] == "anonymous"
    assert c.delete(f"/api/v1/suppressions/{sid}").status_code == 409
    assert c.delete("/api/v1/suppressions/SUP-nope").status_code == 404
    assert m.on_event(make_doc(host={"name": "backup-03"}, event={"id": "s3"})) is not None         # revoked: alerts again
    assert len(c.get("/api/v1/suppressions").json()["items"]) == 1                                  # history kept
    assert m.stats()["open"] >= 2


def test_suppression_validation(env):
    c, *_ = env
    ok = {"technique": "T1070", "asset": "backup-*", "reason": "nightly backup rotates the audit log", "days": 14}
    bad = lambda **kw: c.post("/api/v1/suppressions", json={**ok, **kw}).status_code   # noqa: E731
    assert bad(technique="nope") == 422 and bad(technique="T10") == 422
    assert bad(asset="*") == 422 and bad(asset="??") == 422                                         # a blanket rule would switch alerting off
    assert bad(reason="too short") == 422 and bad(days=0) == 422 and bad(days=91) == 422
    assert bad(asset="x\ny") == 422 and bad(asset="") == 422
    assert bad(technique="*", asset="lab-1") == 201                                                  # any technique on ONE named asset is fine


def test_suppressions_survive_restart_and_only_admins_create_them(tmp_path):
    secret = "s" * 40
    tok = lambda role: {"Authorization": "Bearer " + tokens.encode({"sub": role, "exp": time.time() + 60, "roles": [role]}, secret)}   # noqa: E731
    kw = dict(auth_mode="jwt", jwt_secret=secret)
    body = {"technique": "T1070", "asset": "backup-*", "reason": "nightly backup rotates the audit log", "days": 7}
    with TestClient(create_app(settings(tmp_path, **kw))) as c:
        assert c.post("/api/v1/suppressions", json=body, headers=tok("analyst")).status_code == 403
        assert c.get("/api/v1/alerts-calibration", headers=tok("viewer")).status_code == 403
        assert c.get("/api/v1/alerts-calibration", headers=tok("analyst")).status_code == 200
        assert c.post("/api/v1/suppressions", json=body, headers=tok("admin")).status_code == 201
    with TestClient(create_app(settings(tmp_path, **kw))) as c2:                                    # restart: the rule is still in force
        items = c2.get("/api/v1/suppressions", headers=tok("analyst")).json()["items"]
        assert len(items) == 1 and items[0]["active"] and items[0]["created_by"] == "admin"
        m = c2.app.state.pipeline.alerts
        assert m.on_event(make_doc(host={"name": "backup-01"})) is None
