"""The onboarding checker (scripts/verify_windows_onboarding.py) against canned API answers: it must tell a time-zone mistake from a backlog,
catch missing fields, a source nobody connected to, and unwanted high-volume event IDs."""
import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_windows_onboarding.py"
spec = importlib.util.spec_from_file_location("verify_onboarding", SCRIPT)
v = importlib.util.module_from_spec(spec)
sys.modules["verify_onboarding"] = v
spec.loader.exec_module(v)

NOW = datetime.now(timezone.utc)


def ev(i, skew_s=2.0, code=4624, **over):
    ts = NOW - timedelta(seconds=i) - timedelta(seconds=skew_s)
    d = {"@timestamp": ts.isoformat(), "host": {"name": "WS-1"}, "event": {"code": code, "ingested": (ts + timedelta(seconds=skew_s)).isoformat(),
         "outcome": "success"}, "user": {"name": "bob"}, "source": {"ip": "10.0.0.5"}, "labels": {"logon_type": 3}, "logunify": {}}
    for k, val in over.items():
        d[k] = val
    return d


def run(monkeypatch, capsys, docs, *, connections=1, received=500, dropped=0, tz="Asia/Kolkata", extra_args=()):
    src = {"id": "s1", "name": "win", "type": "syslog", "format": "windows_security", "status": "active", "error": None,
           "config": {"protocol": "tcp", "port": 5514, **({"timezone": tz} if tz else {})}}
    oldest, newest = (NOW - timedelta(hours=2)).isoformat(), NOW.isoformat()
    answers = {
        "/api/v1/sources": {"items": [src]},
        "/api/v1/sources/listeners": {"items": [{"source_id": "s1", "ports": {"tcp": 5514}, "queue_depth": 0, "queue_max": 10000,
                                                 **({"connections_total": connections, "tcp_connections": 1, "tcp_received": received} if connections else {})}]},
        "/api/v1/metrics": {"received": received, "processed": received, "dropped": dropped, "dead_lettered": 0},
    }

    def fake_get(self, path):
        if path.startswith("/api/v1/logs/search"):
            return {"total": len(docs), "items": docs, "coverage": {"events_held": len(docs) * 20, "oldest": oldest, "newest": newest}}
        if path.startswith("/api/v1/alerts-calibration"):
            return {"replay": {"coverage": {"buffer": 50000}}}
        return answers[path]
    monkeypatch.setattr(v.Api, "get", fake_get)
    monkeypatch.setattr(v.urllib.request, "urlopen", lambda *a, **k: type("R", (), {"read": lambda self: b"ok"})())
    monkeypatch.setattr(sys, "argv", ["x", "--url", "http://x", "--api-key", "k", *extra_args])
    v.RESULTS.clear()
    code = v.main()
    return code, {name: level for level, name, _ in v.RESULTS}, capsys.readouterr().out


def test_healthy_feed_passes(monkeypatch, capsys):
    code, r, _ = run(monkeypatch, capsys, [ev(i) for i in range(200)])
    assert code == 0 and "FAIL" not in r.values()
    assert r["time zone"] == "PASS" and r["parsed fields"] == "PASS" and r["events received"] == "PASS"


@pytest.mark.parametrize("skew,verdict", [(19800, "FAIL"), (-19800, "FAIL"), (3600, "FAIL"), (2141, "WARN"), (900, "WARN"), (60, "PASS")])
def test_time_zone_pattern_versus_backlog(monkeypatch, capsys, skew, verdict):
    # a constant skew of a whole UTC offset is a time-zone error; an arbitrary delay is clock drift / backlog
    code, r, out = run(monkeypatch, capsys, [ev(i, skew_s=skew) for i in range(200)])
    assert r["time zone"] == verdict, out
    if verdict == "FAIL":
        assert code == 1 and ("FUTURE" in out) == (skew < 0)


def test_a_varying_delay_is_a_backlog_not_a_zone_error(monkeypatch, capsys):
    docs = [ev(i, skew_s=19800 + i * 20) for i in range(200)]               # delay grows 20 s per event: spread > 15 min
    code, r, out = run(monkeypatch, capsys, docs)
    assert r["time zone"] == "WARN" and "backlog" in out and code == 0


def test_missing_fields_are_reported(monkeypatch, capsys):
    docs = [ev(i, user={}) for i in range(100)] + [ev(i + 100, code=4625, source={}) for i in range(50)]
    code, r, out = run(monkeypatch, capsys, docs)
    assert r["parsed fields"] == "FAIL" and "user.name" in out and "source.ip (network logon)" in out and code == 1


def test_no_connection_and_no_events_fail_clearly(monkeypatch, capsys):
    code, r, out = run(monkeypatch, capsys, [], connections=0)
    assert code == 1 and r["host connected"] == "FAIL" and r["windows events"] == "FAIL"


def test_dropped_events_fail(monkeypatch, capsys):
    code, r, out = run(monkeypatch, capsys, [ev(i) for i in range(50)], dropped=12)
    assert r["no loss"] == "FAIL" and "dropped" in out and code == 1


def test_noisy_event_ids_warn_and_missing_timezone_warns(monkeypatch, capsys):
    docs = [ev(i, code=5156) for i in range(80)] + [ev(i + 80) for i in range(120)]
    code, r, out = run(monkeypatch, capsys, docs, tz=None)
    assert r["event mix"] == "WARN" and "5156" in out and any("timezone" in k and lvl == "WARN" for k, lvl in r.items())


def test_buffer_horizon_warns_when_the_rate_is_too_high(monkeypatch, capsys):
    code, r, out = run(monkeypatch, capsys, [ev(i) for i in range(500)])
    # 500*20 held events over 2 h = 5,000/h -> 50,000-event buffer lasts 10 h
    assert r["buffer horizon"] == "WARN" and "10.0 h" in out


def test_expected_host_check(monkeypatch, capsys):
    code, r, out = run(monkeypatch, capsys, [ev(i) for i in range(50)], extra_args=("--host", "ws-1"))
    assert r["host ws-1"] == "PASS"
    code, r, out = run(monkeypatch, capsys, [ev(i) for i in range(50)], extra_args=("--host", "dc09"))
    assert r["host dc09"] == "FAIL" and code == 1
