"""Assignment, case notes, Slack/Teams notifications, log search with a time range, saved searches."""
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from app.alerting.notifiers import DeliveryError, SlackNotifier, TeamsNotifier, build_notifiers
from app.alerting.messages import build_test_message
from app.alerting.cert_in import OrgProfile
from app.config import Settings
from app.intel.anomaly import AnomalyScorer
from app.main import create_app
from app.search import SearchError, parse_query, parse_time, search_logs
from tests.alert_helpers import FakeNotifier, run
from tests.test_alert_api import KEY, LOG, raise_alert, settings, wait_for
from tests.test_state import LOG as SSH

BY = {"by": "asha"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Same setup as test_alert_api.env: a running app whose alert channel is a FakeNotifier and whose scorer always says 0.95."""
    app = create_app(settings(tmp_path))
    fake = FakeNotifier()
    with TestClient(app) as c:
        app.state.pipeline.alerts.notifiers = [fake]
        c.headers.update({"X-API-Key": KEY})
        monkeypatch.setattr(app.state.pipeline.intel.scorer, "score_many", lambda rows, learn: [0.95] * len(rows))
        monkeypatch.setattr(AnomalyScorer, "ready", property(lambda self: True))
        yield c, app, fake


# ------------------------------------------------------------------------------------------------ assignment
def test_assign_reassign_unassign_is_audited_and_does_not_touch_the_clock(env):
    c, app, fake = env
    aid = raise_alert(c, fake)
    before = c.get(f"/api/v1/alerts/{aid}").json()["summary"]
    r = c.post(f"/api/v1/alerts/{aid}/assign", json={**BY, "to": "ravi", "note": "please check the db host"})
    assert r.status_code == 200 and r.json()["assignee"]["to"] == "ravi" and r.json()["summary"]["assignee"] == "ravi"
    after = r.json()["summary"]
    assert after["due_at"] == before["due_at"] and after["status"] == before["status"]
    c.post(f"/api/v1/alerts/{aid}/assign", json={**BY, "to": "meena"})
    assert c.post(f"/api/v1/alerts/{aid}/assign", json={**BY, "to": None}).json()["assignee"] is None
    kinds = [e["kind"] for e in c.get(f"/api/v1/alerts/{aid}/events").json()["items"]]
    assert kinds.count("assigned") == 2 and kinds.count("unassigned") == 1


def test_assignment_filters_and_notice(env):
    c, app, fake = env
    a1 = raise_alert(c, fake)
    a2 = raise_alert(c, fake, LOG.replace("db-01", "db-02"))
    c.post(f"/api/v1/alerts/{a1}/assign", json={**BY, "to": "Ravi"})
    ids = lambda q: {i["id"] for i in c.get("/api/v1/alerts", params=q).json()["items"]}   # noqa: E731
    assert ids({"assignee": "ravi"}) == {a1}                                  # case-insensitive
    assert ids({"assignee": "unassigned"}) == {a2}
    assert wait_for(lambda: any(m.kind == "incident.assigned" for m in fake.sent))
    msg = next(m for m in fake.sent if m.kind == "incident.assigned")
    assert "Ravi" in msg.subject and a1 in msg.text and "CERT-In time left" in msg.text
    assert wait_for(lambda: any(e["kind"] == "assignment_notified" for e in c.get(f"/api/v1/alerts/{a1}/events").json()["items"]))


def test_assigning_to_an_email_mails_that_person(env):
    c, app, fake = env
    aid = raise_alert(c, fake)
    fake.name = "email"
    c.post(f"/api/v1/alerts/{aid}/assign", json={**BY, "to": "ravi@acme.example"})
    assert wait_for(lambda: any(m.kind == "incident.assigned" for m in fake.sent))
    assert next(m for m in fake.sent if m.kind == "incident.assigned").recipients == ("ravi@acme.example",)


def test_assign_validation_and_closed_alerts(env):
    c, app, fake = env
    aid = raise_alert(c, fake)
    assert c.post(f"/api/v1/alerts/{aid}/assign", json={**BY, "to": "x" * 101}).status_code == 422
    assert c.post(f"/api/v1/alerts/{aid}/assign", json={**BY, "to": "bad\nname"}).status_code == 422
    assert c.post("/api/v1/alerts/NOPE/assign", json={**BY, "to": "a1"}).status_code == 404
    c.post(f"/api/v1/alerts/{aid}/close", json={**BY, "resolution": "false_positive", "note": "known maintenance window"})
    assert c.post(f"/api/v1/alerts/{aid}/assign", json={**BY, "to": "ravi"}).status_code == 409


# ------------------------------------------------------------------------------------------------ notes
def test_notes_are_append_only_and_survive_closing(env):
    c, app, fake = env
    aid = raise_alert(c, fake)
    assert c.post(f"/api/v1/alerts/{aid}/notes", json={**BY, "text": "  Checked auth.log: root login from 203.0.113.9  "}).status_code == 201
    c.post(f"/api/v1/alerts/{aid}/notes", json={"by": "ravi", "text": "Confirmed with DBA: not a maintenance task"})
    notes = c.get(f"/api/v1/alerts/{aid}/notes").json()["items"]
    assert [n["by"] for n in notes] == ["asha", "ravi"] and notes[0]["text"].startswith("Checked auth.log")
    assert c.post(f"/api/v1/alerts/{aid}/notes", json={**BY, "text": "   "}).status_code == 422
    assert c.post(f"/api/v1/alerts/{aid}/notes", json={**BY, "text": "x" * 4001}).status_code == 422
    c.post(f"/api/v1/alerts/{aid}/close", json={**BY, "resolution": "false_positive", "note": "confirmed false positive"})
    assert c.post(f"/api/v1/alerts/{aid}/notes", json={**BY, "text": "post-incident review"}).status_code == 201
    assert len(c.get(f"/api/v1/alerts/{aid}/notes").json()["items"]) == 3
    with pytest.raises(Exception, match="append-only"):                         # the DB itself refuses edits
        app.state.pipeline.alerts.store._db().execute("UPDATE events SET data='{}' WHERE kind='note'")


# ------------------------------------------------------------------------------------------------ Slack / Teams
def _transport(status=200, seen=None):
    def handler(req: httpx.Request):
        if seen is not None:
            seen.append(json.loads(req.content))
        return httpx.Response(status)
    return httpx.MockTransport(handler)


def test_slack_and_teams_payloads_and_error_handling():
    seen: list = []
    msg = build_test_message(OrgProfile(), 0)
    run(SlackNotifier("https://hooks.slack.example/services/T/B/secret", transport=_transport(seen=seen)).send(msg))
    run(TeamsNotifier("https://prod.workflows.example/abc?sig=secret", transport=_transport(seen=seen)).send(msg))
    assert "TEST message" in seen[0]["text"]
    card = seen[1]["attachments"][0]
    assert seen[1]["type"] == "message" and card["contentType"].endswith("adaptive") and card["content"]["type"] == "AdaptiveCard"
    s = SlackNotifier("https://hooks.slack.example/services/T/B/secret")
    assert s.label == "https://hooks.slack.example" and "secret" not in s.label                  # the path is the credential
    with pytest.raises(DeliveryError) as e:
        run(SlackNotifier("https://h.example/x", transport=_transport(500)).send(msg))
    assert e.value.retryable and "https://h.example" in str(e.value) and "/x" not in str(e.value)       # label only, never the path
    with pytest.raises(DeliveryError) as e:
        run(TeamsNotifier("https://h.example/x", transport=_transport(404)).send(msg))
    assert not e.value.retryable
    with pytest.raises(ValueError):
        SlackNotifier("http://hooks.slack.example/x")                                              # plain http to a remote host refused


def test_build_notifiers_adds_chat_channels_from_settings():
    s = Settings(alert_slack_webhook_url="https://hooks.slack.example/s", alert_teams_webhook_url="https://t.example/w")
    assert [n.name for n in build_notifiers(s)] == ["slack", "teams"]
    assert build_notifiers(Settings()) == []


# ------------------------------------------------------------------------------------------------ search
def ev(minutes_ago: float, msg="hello", **extra):
    t = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    d = {"@timestamp": t.isoformat(), "message": msg, "event": {"original": msg}, "logunify": {"source_format": "syslog", "anomaly": {"score": 0.1}}}
    d.update(extra)
    return d


def test_query_syntax_and_time_parsing():
    assert parse_query('failed -user.name:root "audit log"') == [(False, None, "failed"), (True, "user.name", "root"), (False, None, "audit log")]
    assert parse_query("") == []
    with pytest.raises(SearchError):
        parse_query('"unterminated')
    with pytest.raises(SearchError):
        parse_time("yesterday")
    now = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
    assert parse_time("-6h", now) == now - timedelta(hours=6) and parse_time("2026-10-01T09:00:00Z") == datetime(2026, 10, 1, 9, tzinfo=timezone.utc)


def test_search_filters_and_reports_coverage():
    events = [ev(300, "old failed login", source={"ip": "1.1.1.1"}), ev(50, "Failed password for root", source={"ip": "203.0.113.9"}, user={"name": "root"}),
              ev(10, "failed password for bob", source={"ip": "203.0.113.9"}, user={"name": "bob"}),
              ev(5, "all good", logunify={"source_format": "json", "anomaly": {"score": 0.9}})]
    r = search_logs(events, q="failed")
    assert r["total"] == 3 and r["coverage"]["events_held"] == 4 and "SIEM" in r["coverage"]["note"]
    assert [i["message"] for i in r["items"]][0] == "failed password for bob"                  # newest first
    assert search_logs(events, q="failed", t_from="-1h")["total"] == 2                           # time range
    assert search_logs(events, q="failed", t_from="-1h", t_to="-20m")["total"] == 1
    assert search_logs(events, q="source.ip:203.0.113.9 -user.name:root")["total"] == 1
    assert search_logs(events, q="user.name:r*")["total"] == 1                                    # wildcard
    assert search_logs(events, min_score=0.5)["total"] == 1 and search_logs(events, fmt="json")["total"] == 1
    assert search_logs(events, limit=1, offset=2)["items"][0]["message"] == "Failed password for root"
    assert search_logs([], q="x")["coverage"]["oldest"] is None
    with pytest.raises(SearchError):
        search_logs(events, t_from="-1h", t_to="-2h")


def test_search_endpoint_over_real_pipeline(env):
    c, app, fake = env
    for i in range(5):
        c.post("/api/v1/parse", json={"log": SSH.format(i=i, j=7)})
    r = c.get("/api/v1/logs/search", params={"q": "source.ip:185.220.101.7 user3", "from": "-1h"}).json()
    assert r["total"] == 1 and r["items"][0]["source"]["ip"] == "185.220.101.7"
    assert c.get("/api/v1/logs/search", params={"from": "garbage"}).status_code == 422
    assert c.get("/api/v1/logs/search", params={"q": '"x'}).status_code == 422


# ------------------------------------------------------------------------------------------------ saved searches
def test_saved_searches_lifecycle_and_sharing(env):
    c, app, fake = env
    c.post("/api/v1/parse", json={"log": SSH.format(i=1, j=9)})
    r = c.post("/api/v1/searches", json={"name": "ssh brute force", "kind": "logs", "query": {"q": "failed password", "from": "-6h", "min_score": 0}})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert [s["name"] for s in c.get("/api/v1/searches").json()["items"]] == ["ssh brute force"]
    run_ = c.post(f"/api/v1/searches/{sid}/run").json()
    assert run_["result"]["total"] >= 1 and run_["search"]["id"] == sid
    upd = c.put(f"/api/v1/searches/{sid}", json={"name": "ssh brute force v2", "kind": "logs", "query": {"q": "failed"}, "shared": True})
    assert upd.status_code == 200 and upd.json()["shared"] is True and upd.json()["created_at"] == r.json()["created_at"]
    assert c.put(f"/api/v1/searches/{sid}", json={"name": "x", "kind": "alerts", "query": {}}).status_code == 422
    assert c.delete(f"/api/v1/searches/{sid}").status_code == 204
    assert c.post(f"/api/v1/searches/{sid}/run").status_code == 404


def test_saved_search_validation(env):
    c, *_ = env
    bad = lambda body: c.post("/api/v1/searches", json=body).status_code   # noqa: E731
    assert bad({"name": "a", "kind": "logs", "query": {"bogus": 1}}) == 422
    assert bad({"name": "a", "kind": "logs", "query": {"q": '"x'}}) == 422
    assert bad({"name": "a", "kind": "logs", "query": {"from": "someday"}}) == 422
    assert bad({"name": "a", "kind": "logs", "query": {"min_score": 7}}) == 422
    assert bad({"name": "a", "kind": "alerts", "query": {"status": "nope"}}) == 422
    assert bad({"name": "", "kind": "logs", "query": {}}) == 422


def test_alert_saved_search_resolves_me_and_private_searches_are_hidden(env):
    c, app, fake = env
    aid = raise_alert(c, fake)
    c.post(f"/api/v1/alerts/{aid}/assign", json={**BY, "to": "anonymous"})            # auth_mode=off: every caller is "anonymous"
    sid = c.post("/api/v1/searches", json={"name": "mine", "kind": "alerts", "query": {"status": "active", "assignee": "me"}}).json()["id"]
    assert [i["id"] for i in c.post(f"/api/v1/searches/{sid}/run").json()["result"]["items"]] == [aid]
    st = app.state.pipeline.alerts.store                                              # another user's private search is a 404, a shared one is visible
    st.put_search({"id": "SRC-other", "owner": "someone", "name": "theirs", "kind": "logs", "shared": False, "query": {}, "created_at": 1, "updated_at": 1})
    st.put_search({"id": "SRC-shared", "owner": "someone", "name": "team", "kind": "logs", "shared": True, "query": {}, "created_at": 1, "updated_at": 1})
    assert c.post("/api/v1/searches/SRC-other/run").status_code == 404
    assert c.post("/api/v1/searches/SRC-shared/run").status_code == 200
    assert {s["id"] for s in c.get("/api/v1/searches").json()["items"]} == {sid, "SRC-shared"}
    assert c.delete("/api/v1/searches/SRC-shared").status_code == 204                 # anonymous is admin in auth_mode=off
