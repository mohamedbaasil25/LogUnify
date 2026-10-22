"""Windows Security logs end to end: parse -> event-ID MITRE rules -> alert, and the SDK `copy` rule feature."""
import json
import textwrap
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.intel import mitre
from app.intel.anomaly import AnomalyScorer
from app.main import create_app
from app.parsers.sdk import DeclarativeParser, build_registry
from app.ecs.normalizer import to_ecs
from tests.alert_helpers import FakeNotifier
from tests.test_alert_api import KEY, settings, wait_for

FIX = Path(__file__).resolve().parents[1] / "parser_fixtures" / "windows_security"


def fixture(name: str) -> str:
    return (FIX / f"{name}.log").read_text().strip()


def tag_of(name: str) -> dict:
    parsed = build_registry().parse(fixture(name), "windows_security")
    return mitre.tag({**parsed.fields}, parsed.message or "")


def test_event_id_rules_tag_structured_windows_events():
    cleared = tag_of("audit_log_cleared")
    assert (cleared["threat.technique.id"], cleared["logunify.mitre.basis"]) == ("T1070.001", "rule:win_log_cleared")
    group = tag_of("group_add_domain_admins")
    assert (group["threat.technique.id"], group["logunify.mitre.basis"]) == ("T1098", "rule:win_privileged_group_add")
    assert tag_of("audit_policy_changed")["logunify.mitre.basis"] == "rule:win_audit_policy_changed"
    assert tag_of("logon_failed")["logunify.mitre.basis"] == "rule:auth_failure"                      # unchanged generic behaviour


def _fields(code, **kw):
    return {"event.module": "windows", "event.code": code, **kw}


def test_privileged_group_rule_uses_name_or_language_independent_sid():
    rule = next(r for r in mitre.RULES if r.name == "win_privileged_group_add")
    assert rule.matches(_fields(4732, **{"labels.target_name": "Administrators"}), "")
    assert rule.matches(_fields(4756, **{"labels.target_name": "Enterprise Admins"}), "")
    assert rule.matches(_fields(4728, **{"labels.target_name": "Administratoren", "labels.target_sid": "S-1-5-32-544"}), "")      # German OS: SID still matches
    assert rule.matches(_fields(4728, **{"labels.target_sid": "S-1-5-21-111-222-333-512"}), "")
    assert not rule.matches(_fields(4728, **{"labels.target_name": "Sales Team", "labels.target_sid": "S-1-5-21-111-222-333-1105"}), "")
    assert not rule.matches(_fields(4728, **{"labels.target_sid": "S-1-5-21-111-222-333-5120"}), "")                                # RID 5120 is not 512
    assert not rule.matches(_fields(4624, **{"labels.target_name": "Administrators"}), "")                                          # wrong event
    assert not rule.matches({"event.code": 4728, "labels.target_name": "Administrators"}, "")                                       # not a windows event


def test_log_cleared_rule_does_not_depend_on_the_message_language():
    rule = next(r for r in mitre.RULES if r.name == "win_log_cleared")
    assert rule.matches(_fields(1102), "Das Überwachungsprotokoll wurde gelöscht.")
    assert rule.matches(_fields(104), "")
    assert not rule.matches({"event.module": "linux", "event.code": 1102}, "")


def test_sdk_copy_repoints_fields_from_the_raw_log():
    spec = textwrap.dedent('''
        name: copy_demo
        version: "1.0.0"
        kind: json
        sniff: {keys: [who, target]}
        fields:
          user.name: {path: target}
        rules:
          - when: {field: who, equals: admin}
            copy: {user.name: who, user.target.name: target}
    ''')
    p = DeclarativeParser(yaml_load(spec))
    f = p.parse(json.dumps({"who": "admin", "target": "bob"})).fields
    assert f["user.name"] == "admin" and f["user.target.name"] == "bob"
    assert p.parse(json.dumps({"who": "root", "target": "bob"})).fields["user.name"] == "bob"        # rule did not match: unchanged
    assert "user.target.name" not in p.parse(json.dumps({"who": "admin", "target": ""})).fields      # empty source copies nothing


def yaml_load(text):
    import yaml
    return yaml.safe_load(text)


def test_actor_not_target_is_user_name_for_account_management():
    parsed = build_registry().parse(fixture("group_add_domain_admins"), "windows_security")
    assert parsed.fields["user.name"] == "helpdesk1" and parsed.fields["group.name"] == "Domain Admins"
    doc = to_ecs(parsed)
    assert doc["user"]["name"] == "helpdesk1" and doc["group"]["name"] == "Domain Admins"


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


@pytest.mark.parametrize("name,technique", [("audit_log_cleared", "T1070.001"), ("group_add_domain_admins", "T1098")])
def test_critical_windows_events_raise_an_alert_end_to_end(env, name, technique):
    c, app, fake = env
    r = c.post("/api/v1/parse", json={"log": fixture(name)}).json()
    assert r["ok"] and r["ecs"]["logunify"]["parser"]["name"] == "windows_security"
    assert wait_for(lambda: len(fake.sent) >= 1)
    a = c.get("/api/v1/alerts", params={"status": "active"}).json()["items"][0]
    assert a["technique"] == technique and a["host"].startswith(("DC01", "SRV-DB1"))


def test_noncritical_windows_events_do_not_alert_even_at_high_score(env):
    c, app, fake = env
    for name in ("logon_success", "logon_failed", "audit_policy_changed"):       # T1078 internal / T1110 excluded / T1562 IS critical (see below)
        c.post("/api/v1/parse", json={"log": fixture(name)})
    kinds = {a["technique"] for a in c.get("/api/v1/alerts", params={"status": "active"}).json()["items"]}
    assert "T1110" not in kinds and "T1562.002" in kinds                          # audit-policy change alerts: noisy candidate, flagged in the runbook


def test_nxlog_hostname_field_is_the_host_and_computer_still_works():
    reg = build_registry()
    nx = reg.parse(fixture("nxlog_hostname_only"), None)                    # auto-detection must pick the Windows parser for real NXLog output
    assert nx.parser == "windows_security" and nx.fields["host.name"] == "WS-0007.corp.example.com"
    assert reg.parse(fixture("logon_failed"), None).fields["host.name"] == "DC01.corp.example.com"          # `Computer` variant


def test_first_of_prefers_the_first_non_empty_path():
    spec = yaml_load('name: fo\nversion: "1"\nkind: json\nsniff: {keys: [a]}\nfields:\n  host.name: {first_of: [x, y, z]}\n')
    p = DeclarativeParser(spec)
    assert p.parse('{"a":1,"y":"why","z":"zed"}').fields["host.name"] == "why"
    assert p.parse('{"a":1,"x":"","z":"zed"}').fields["host.name"] == "zed"
    assert "host.name" not in p.parse('{"a":1}').fields
