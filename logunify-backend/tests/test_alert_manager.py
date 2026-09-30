import asyncio
import sqlite3

import pytest

from app.alerting.manager import AlertManager
from app.alerting.models import AlertNotFound, InvalidTransition
from app.alerting.store import AlertStore
from app.config import Settings
from tests.alert_helpers import FakeClock, FakeNotifier, doc_for, make_doc, run

H = 3600


def manager(notifiers, clock=None, **kw) -> AlertManager:
    base = dict(alert_db_path=":memory:", alert_retry_attempts=3, alert_retry_base_s=2.0, alert_reminder_minutes="120,60,30",
                alert_dedup_minutes=30, alert_max_notifications_per_hour=20, org_name="Acme Bank Ltd", poc_name="Asha Rao",
                poc_designation="CISO", poc_email="ciso@acme.example", poc_mobile="+91 90000 00001", org_address="Mumbai")
    base.update(kw)
    s = Settings(**base)
    sleeps: list[float] = []

    async def fake_sleep(d):
        sleeps.append(d)

    m = AlertManager(s, notifiers=notifiers, store=AlertStore(s.alert_db_path), clock=clock or FakeClock(), sleep=fake_sleep)
    m.sleeps = sleeps
    return m


# ------------------------------------------------------------------------------------------------ happy path
def test_new_alert_is_recorded_notified_and_the_clock_starts():
    fake, clock = FakeNotifier(), FakeClock()
    m = manager([fake], clock)

    async def go():
        await m.start()
        aid = m.on_event(make_doc())
        await m.drain()
        out = (aid, m.view(aid), m.events_for(aid), m.stats())
        await m.stop()
        return out

    aid, view, events, stats = run(go())
    assert aid.startswith("ALR-") and fake.kinds() == ["incident.detected"]
    msg = fake.sent[0]
    assert msg.subject.startswith("[CRITICAL][CERT-In 6h] T1070 Indicator Removal on db-01: report due ")
    assert msg.payload["schema"] == "logunify.alert/v1" and msg.payload["event"] == "incident.detected"
    assert msg.payload["alert"]["id"] == aid and msg.payload["alert"]["seconds_remaining"] == 6 * H
    assert msg.payload["cert_in_report"]["deadline"]["report_due_at"]["utc"].startswith("2026-")
    assert msg.attachment[0] == f"cert-in-report-{aid}.json"
    assert view["summary"]["status"] == "open" and view["notification"]["status"] == "sent"
    assert view["notification"]["channels"]["fake"]["ok"] is True and view["evidence"]["record_sha256"]
    assert [e["kind"] for e in events] == ["created", "notified"]
    assert stats["triggered"] == 1 and stats["open"] == 1 and stats["overdue"] == 0 and stats["channels"] == ["fake"]


def test_docs_that_do_not_qualify_raise_no_alert():
    fake = FakeNotifier()
    m = manager([fake])

    async def go():
        await m.start()
        ids = [m.on_event(d) for d in (
            make_doc(logunify={"anomaly": {"score": 0.9}}),                                   # not above the threshold
            make_doc(threat={"technique": {"id": "T1110"}}),                                   # not a critical technique
            make_doc(logunify={"mitre": {"basis": "default"}}),                                # placeholder tag
            {"message": "plain log"})]
        await m.drain()
        await m.stop()
        return ids

    assert run(go()) == [None] * 4 and fake.sent == []


# ------------------------------------------------------------------------------------------------ dedup
def test_repeats_are_absorbed_until_a_quiet_period_then_a_new_alert_opens():
    fake, clock = FakeNotifier(), FakeClock()
    m = manager([fake], clock, alert_dedup_minutes=30)

    async def go():
        await m.start()
        first = m.on_event(make_doc())
        clock.advance(20 * 60)
        second = m.on_event(make_doc())                      # 20 min later: same technique + asset -> absorbed
        clock.advance(25 * 60)
        third = m.on_event(make_doc())                       # 25 min after the last sighting (< 30): still the same incident
        other_asset = m.on_event(doc_for("web-09"))          # different asset -> separate alert
        clock.advance(31 * 60)
        later = m.on_event(make_doc())                       # quiet for 31 min -> new alert, new clock
        await m.drain()
        out = (first, second, third, other_asset, later, m.view(first)["summary"]["occurrences"], m.stats())
        await m.stop()
        return out

    first, second, third, other, later, occurrences, stats = run(go())
    assert second is None and third is None and occurrences == 3
    assert other and other != first and later and later != first
    assert stats["triggered"] == 3 and stats["suppressed"] == 2 and len(fake.sent) == 3


def test_sub_techniques_of_the_same_parent_share_an_alert():
    m = manager([FakeNotifier()])
    a = make_doc(threat={"technique": {"id": "T1070.001"}})
    b = make_doc(threat={"technique": {"id": "T1070.002"}})

    async def go():
        await m.start()
        out = (m.on_event(a), m.on_event(b))
        await m.drain()
        await m.stop()
        return out

    first, second = run(go())
    assert first and second is None


# ------------------------------------------------------------------------------------------------ delivery reliability
def test_transient_failures_are_retried_with_exponential_backoff():
    fake = FakeNotifier(fail_first=2)
    m = manager([fake], alert_retry_attempts=4, alert_retry_base_s=2.0)

    async def go():
        await m.start()
        aid = m.on_event(make_doc())
        await m.drain()
        out = m.view(aid)["notification"]
        await m.stop()
        return out

    n = run(go())
    assert fake.calls == 3 and len(fake.sent) == 1 and m.sleeps == [2.0, 4.0]
    assert n["status"] == "sent" and n["channels"]["fake"]["attempts"] == 3


def test_a_permanent_error_is_not_retried_but_the_alert_is_kept_and_retried_later():
    fake, clock = FakeNotifier(permanent=True), FakeClock()
    m = manager([fake], clock)

    async def go():
        await m.start()
        aid = m.on_event(make_doc())
        await m.drain()
        first = m.view(aid)["notification"]
        assert m.list_alerts("active")                      # the alert exists even though nothing was delivered
        clock.advance(100)
        await m.run_maintenance_once()
        await m.drain()
        too_soon = fake.calls
        fake.permanent = False                               # e.g. the webhook URL was fixed
        clock.advance(30)                                    # 130 s since the failure (backoff after 1 failed cycle = 120 s)
        await m.run_maintenance_once()
        await m.drain()
        out = (first, too_soon, m.view(aid)["notification"], [e["kind"] for e in m.events_for(aid)])
        await m.stop()
        return out

    first, too_soon, final, kinds = run(go())
    assert first["status"] == "failed" and first["channels"]["fake"]["attempts"] == 1 and "permanent" in first["channels"]["fake"]["last_error"]
    assert too_soon == 1                                     # not retried before the backoff elapsed
    assert final["status"] == "sent" and len(fake.sent) == 1
    assert kinds == ["created", "notify_failed", "notified"]


def test_only_the_failed_channel_is_retried():
    good, bad, clock = FakeNotifier("webhook"), FakeNotifier("email", fail_first=99), FakeClock()
    m = manager([good, bad], clock, alert_retry_attempts=2)

    async def go():
        await m.start()
        aid = m.on_event(make_doc())
        await m.drain()
        partial = m.view(aid)["notification"]["status"]
        bad.fail_first = 0
        clock.advance(130)
        await m.run_maintenance_once()
        await m.drain()
        out = (partial, m.view(aid)["notification"])
        await m.stop()
        return out

    partial, final = run(go())
    assert partial == "partial" and final["status"] == "sent"
    assert good.calls == 1 and len(good.sent) == 1           # the healthy channel was NOT spammed again
    assert len(bad.sent) == 1 and final["sent_at"] is not None


def test_no_channels_still_records_the_alert():
    m = manager([])

    async def go():
        await m.start()
        aid = m.on_event(make_doc())
        await m.drain()
        out = (m.view(aid)["notification"]["status"], m.list_alerts("active"), m.stats()["channels"])
        await m.stop()
        return out

    status, active, channels = run(go())
    assert status == "no_channels" and len(active) == 1 and channels == []


def test_alert_raised_before_start_is_delivered_once_the_manager_starts():
    fake = FakeNotifier()
    m = manager([fake])
    aid = m.on_event(make_doc())                              # no event loop yet: recorded as pending
    assert aid and fake.sent == []

    async def go():
        await m.start()
        await m.drain()
        out = m.view(aid)["notification"]["status"]
        await m.stop()
        return out

    assert run(go()) == "sent" and fake.kinds() == ["incident.detected"]


def test_on_event_is_safe_to_call_from_another_thread():
    fake = FakeNotifier()
    m = manager([fake])

    async def go():
        await m.start()
        ids = await asyncio.gather(*(asyncio.to_thread(m.on_event, doc_for(f"host-{i}")) for i in range(8)))
        await m.drain()
        await m.stop()
        return ids

    ids = run(go())
    assert all(ids) and len(set(ids)) == 8 and len(fake.sent) == 8


# ------------------------------------------------------------------------------------------------ the 6-hour clock
def test_reminders_fire_once_per_threshold_then_overdue_repeats_hourly():
    fake, clock = FakeNotifier(), FakeClock()
    m = manager([fake], clock, alert_overdue_repeat_minutes=60)

    async def tick(seconds):
        clock.advance(seconds)
        await m.run_maintenance_once()
        await m.drain()

    async def go():
        await m.start()
        m.on_event(make_doc())
        await m.drain()
        await tick(3 * H)                                   # 3h left: nothing yet
        assert fake.kinds() == ["incident.detected"]
        await tick(1 * H)                                   # 2h left -> threshold 120
        await tick(60)                                      # same threshold must not repeat
        await tick(1 * H)                                   # ~59 min left -> threshold 60
        await tick(31 * 60)                                 # ~28 min left -> threshold 30
        await tick(40 * 60)                                 # past the deadline -> overdue notice
        await tick(30 * 60)                                 # 30 min later: not repeated yet
        await tick(31 * 60)                                 # > 60 min since the first overdue -> repeated
        await m.stop()

    run(go())
    assert fake.kinds() == ["incident.detected", "incident.reminder", "incident.reminder", "incident.reminder",
                            "incident.overdue", "incident.overdue"]
    assert [s.subject.split("]")[0] for s in fake.sent[1:4]] == ["[REMINDER 2h left", "[REMINDER 1h left", "[REMINDER 30 min left"]
    assert fake.sent[4].subject.startswith("[OVERDUE][CERT-In 6h]") and "OVERDUE" in fake.sent[4].text


def test_a_long_outage_sends_one_reminder_not_a_burst():
    fake, clock = FakeNotifier(), FakeClock()
    m = manager([fake], clock)

    async def go():
        await m.start()
        aid = m.on_event(make_doc())
        await m.drain()
        clock.advance(5 * H + 40 * 60)                       # the service was down; 20 minutes left when it comes back
        await m.run_maintenance_once()
        await m.drain()
        await m.run_maintenance_once()
        await m.drain()
        out = m.get_reminders(aid) if hasattr(m, "get_reminders") else m._alerts[aid].reminders_sent
        await m.stop()
        return out

    sent = run(go())
    assert fake.kinds() == ["incident.detected", "incident.reminder"] and sorted(sent) == [30, 60, 120]
    assert fake.sent[1].subject.startswith("[REMINDER 30 min left]")


def test_reported_and_closed_alerts_get_no_more_reminders():
    fake, clock = FakeNotifier(), FakeClock()
    m = manager([fake], clock)

    async def go():
        await m.start()
        a = m.on_event(make_doc())
        b = m.on_event(doc_for("web-02"))
        await m.drain()
        m.mark_reported(a, "asha", via="email", reference="CERT-IN/2026/123")
        m.close(b, "asha", "false_positive", "Scheduled log rotation by ops, verified with change ticket")
        clock.advance(7 * H)
        await m.run_maintenance_once()
        await m.drain()
        await m.stop()

    run(go())
    assert fake.kinds() == ["incident.detected", "incident.detected"]     # no reminder, no overdue notice


def test_acknowledging_does_not_stop_the_clock():
    fake, clock = FakeNotifier(), FakeClock()
    m = manager([fake], clock)

    async def go():
        await m.start()
        a = m.on_event(make_doc())
        await m.drain()
        m.acknowledge(a, "ravi", "looking at it")
        clock.advance(4 * H)
        await m.run_maintenance_once()
        await m.drain()
        await m.stop()

    run(go())
    assert fake.kinds() == ["incident.detected", "incident.reminder"]


# ------------------------------------------------------------------------------------------------ human workflow
def test_workflow_transitions_and_audit_trail():
    fake, clock = FakeNotifier(), FakeClock()
    m = manager([fake], clock)

    async def go():
        await m.start()
        a = m.on_event(make_doc())
        await m.drain()
        m.acknowledge(a, "ravi", "triage started", "10.0.0.5")
        with pytest.raises(InvalidTransition):
            m.acknowledge(a, "ravi")                        # already acknowledged
        m.update_details(a, "ravi", {"operating_system": "Ubuntu 22.04", "critical": True, "incident_type_ids": ["iii", "iii", "ii"]})
        assert m.report_for(a)["affected_system"]["operating_system"] == "Ubuntu 22.04"
        assert m._alerts[a].analyst["incident_type_ids"] == ["iii", "ii"]
        clock.advance(2 * H)
        rep = m.mark_reported(a, "asha", via="email", reference="CERT-IN/2026/77", note="sent with log evidence")
        assert rep.status == "reported" and rep.reported["on_time"] is True and rep.reported["late_by_seconds"] is None
        with pytest.raises(InvalidTransition):
            m.mark_reported(a, "asha")                      # cannot report twice
        with pytest.raises(InvalidTransition):
            m.close(a, "asha", "false_positive", "trying to undo a submitted report")
        closed = m.close(a, "asha", "resolved", "contained and remediated")
        assert closed.status == "closed" and a not in m._alerts
        with pytest.raises(InvalidTransition):
            m.update_details(a, "asha", {"impact": "late edit"})
        out = [(e["kind"], e["actor"]) for e in m.events_for(a)]
        await m.stop()
        return out

    assert run(go()) == [("created", "system"), ("notified", "system"), ("acknowledged", "ravi"), ("details_updated", "ravi"),
                         ("reported_to_cert_in", "asha"), ("closed", "asha")]


def test_late_report_is_recorded_as_late():
    clock = FakeClock()
    m = manager([FakeNotifier()], clock)

    async def go():
        await m.start()
        a = m.on_event(make_doc())
        clock.advance(6 * H + 15 * 60)
        alert = m.mark_reported(a, "asha", via="phone")
        await m.stop()
        return alert

    alert = run(go())
    assert alert.reported["on_time"] is False and alert.reported["late_by_seconds"] == 15 * 60


@pytest.mark.parametrize("resolution,note,status", [
    ("false_positive", "short", None),                      # compliance decisions need a reason
    ("not_reportable", "", None),
    ("resolved", "anything", "open"),                       # cannot 'resolve' an incident that was never reported
])
def test_closing_rules(resolution, note, status):
    m = manager([FakeNotifier()])

    async def go():
        await m.start()
        a = m.on_event(make_doc())
        try:
            with pytest.raises(ValueError if status is None else InvalidTransition):
                m.close(a, "asha", resolution, note)
        finally:
            await m.stop()

    run(go())


def test_not_reportable_closure_with_a_reason_is_allowed_before_any_report():
    m = manager([FakeNotifier()])

    async def go():
        await m.start()
        a = m.on_event(make_doc())
        closed = m.close(a, "asha", "not_reportable", "Internal test by red team (ticket RT-44); none of the FAQ Q30 criteria apply")
        await m.stop()
        return closed

    assert run(go()).closed["resolution"] == "not_reportable"


def test_input_validation():
    m = manager([FakeNotifier()])

    async def go():
        await m.start()
        a = m.on_event(make_doc())
        for bad in ({"password": "x"}, {"critical": "yes"}, {"incident_type_ids": ["zz"]}, {"incident_type_ids": "ii"},
                    {"i_am": "nobody"}, {"impact": "x" * 2001}, {"impact": 5}):
            with pytest.raises(ValueError):
                m.update_details(a, "ravi", bad)
        with pytest.raises(ValueError):
            m.mark_reported(a, "asha", via="carrier-pigeon")
        with pytest.raises(ValueError):
            m.mark_reported(a, "asha", reported_at=m._clock() + 3600)        # future
        with pytest.raises(ValueError):
            m.mark_reported(a, "asha", reported_at=m._clock() - 3600)        # before it was noticed
        with pytest.raises(AlertNotFound):
            m.acknowledge("ALR-nope", "ravi")
        m.update_details(a, "ravi", {"impact": "  text  "})
        m.update_details(a, "ravi", {"impact": None})                          # null clears
        assert "impact" not in m._alerts[a].analyst
        await m.stop()

    run(go())


# ------------------------------------------------------------------------------------------------ alert storms
def test_rate_cap_defers_notification_but_never_drops_the_alert():
    fake, clock = FakeNotifier(), FakeClock()
    m = manager([fake], clock, alert_max_notifications_per_hour=2)

    async def go():
        await m.start()
        ids = [m.on_event(doc_for(f"host-{i}")) for i in range(3)]
        await m.drain()
        limited = m.view(ids[2])["notification"]["status"]
        await m.run_maintenance_once()                       # one summary message for the overflow
        await m.drain()
        await m.run_maintenance_once()
        await m.drain()
        summary_kinds = list(fake.kinds())
        clock.advance(3601)                                  # the hour passes: the deferred alert is delivered
        await m.run_maintenance_once()
        await m.drain()
        out = (limited, summary_kinds, m.view(ids[2])["notification"]["status"], m.stats())
        await m.stop()
        return out

    limited, summary_kinds, final, stats = run(go())
    assert limited == "rate_limited" and stats["triggered"] == 3 and stats["rate_limited"] == 1
    assert summary_kinds == ["incident.detected", "incident.detected", "incident.storm"]
    assert fake.kinds().count("incident.detected") == 3 and fake.kinds().count("incident.storm") == 1 and final == "sent"
    storm = next(s for s in fake.sent if s.kind == "incident.storm")
    assert "1 critical alert" in storm.subject or "1 critical alert(s)" in storm.subject


# ------------------------------------------------------------------------------------------------ durability
def test_open_alerts_clocks_counters_and_dedup_survive_a_restart(tmp_path):
    db, clock = str(tmp_path / "alerts.db"), FakeClock()
    fake1 = FakeNotifier()
    m1 = manager([fake1], clock, alert_db_path=db)

    async def first():
        await m1.start()
        aid = m1.on_event(make_doc())
        await m1.drain()
        clock.advance(10 * 60)
        m1.on_event(make_doc())                              # absorbed: occurrences=2, flushed on stop
        await m1.stop()
        return aid

    aid = run(first())
    fake2 = FakeNotifier()
    m2 = manager([fake2], clock, alert_db_path=db)

    async def second():
        await m2.start()
        restored = m2.list_alerts("active")
        clock.advance(10 * 60)
        absorbed = m2.on_event(make_doc())                   # the restored alert still deduplicates
        clock.advance(3 * H + 40 * 60)                       # ~4h after the original detection: reminder due
        await m2.run_maintenance_once()
        await m2.drain()
        out = (restored, absorbed, m2.view(aid)["summary"])
        await m2.stop()
        return out

    restored, absorbed, summary = run(second())
    assert [r["id"] for r in restored] == [aid] and absorbed is None and summary["occurrences"] == 3
    assert fake2.kinds() == ["incident.reminder"]            # the original 6-hour clock kept running across the restart
    assert fake2.sent[0].payload["alert"]["id"] == aid and fake1.kinds() == ["incident.detected"]


def test_closed_alerts_remain_queryable_from_the_store(tmp_path):
    clock = FakeClock()
    m = manager([FakeNotifier()], clock, alert_db_path=str(tmp_path / "a.db"))

    async def go():
        await m.start()
        a = m.on_event(make_doc())
        m.close(a, "asha", "false_positive", "Verified benign: scheduled rotation by ops")
        out = (m.list_alerts("closed"), m.list_alerts(), m.view(a)["closed"]["resolution"], m.list_alerts("active"))
        await m.stop()
        return out

    closed, everything, resolution, active = run(go())
    assert len(closed) == 1 and len(everything) == 1 and resolution == "false_positive" and active == []


def test_default_configuration_creates_no_files_until_an_alert_happens(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    m = AlertManager(Settings(), notifiers=[])

    async def go():
        await m.start()
        m.on_event({"message": "nothing interesting"})
        await m.stop()

    run(go())
    assert list(tmp_path.iterdir()) == []


# ------------------------------------------------------------------------------------------------ store
def test_audit_log_is_append_only():
    s = AlertStore(":memory:")
    s.add_event("ALR-1", "created", "system", {"x": 1}, 1.0)
    with pytest.raises(sqlite3.DatabaseError):
        s._db().execute("UPDATE events SET actor='mallory'")
    with pytest.raises(sqlite3.DatabaseError):
        s._db().execute("DELETE FROM events")
    assert s.events("ALR-1")[0]["actor"] == "system"


# ------------------------------------------------------------------------------------------------ evidence + misc
def test_evidence_reference_is_looked_up_and_cached():
    calls = []

    def locator(sha):
        calls.append(sha)
        return None if len(calls) == 1 else {"batch_id": "batch-000003", "index": 4}

    m = AlertManager(Settings(alert_db_path=":memory:"), notifiers=[], store=AlertStore(":memory:"), evidence_locator=locator)

    async def go():
        await m.start()
        a = m.on_event(make_doc())
        first = m.evidence_for(a)["integrity_reference"]      # record not sealed yet
        second = m.evidence_for(a)["integrity_reference"]
        third = m.evidence_for(a)["integrity_reference"]      # cached: no further lookup
        ev = m.evidence_for(a)
        await m.stop()
        return first, second, third, ev

    first, second, third, ev = run(go())
    assert first is None and second == third == {"batch_id": "batch-000003", "index": 4} and len(calls) == 2
    assert ev["record"]["host"]["name"] == "db-01" and len(ev["record_sha256"]) == 64    # unredacted record is available


def test_send_test_reports_per_channel_results_without_creating_an_alert():
    ok, bad = FakeNotifier("webhook"), FakeNotifier("email", permanent=True)
    m = manager([ok, bad])

    async def go():
        await m.start()
        res = await m.send_test()
        out = (res, m.list_alerts())
        await m.stop()
        return out

    res, alerts = run(go())
    assert res["webhook"] == {"ok": True} and res["email"]["ok"] is False and alerts == []
    assert ok.sent[0].kind == "test" and "not an incident" in ok.sent[0].text and ok.sent[0].payload["test"] is True


def test_config_view_has_no_secrets_and_reflects_settings():
    m = manager([FakeNotifier()], alert_score_threshold=0.92)
    v = m.config_view()
    assert v["score_threshold"] == 0.92 and v["deadline_hours"] == 6 and "T1070" in v["critical_techniques"]
    assert "T1110" not in v["critical_techniques"] and v["organization_configured"] is True
    assert v["reminder_minutes_before_due"] == [120, 60, 30] and v["require_rule_basis"] is True


def test_misconfiguration_fails_fast():
    from app.alerting.validation import AlertConfigError
    for kw in ({"alert_critical_techniques": "T1070,banana"}, {"alert_reminder_minutes": "500"},
               {"alert_webhook_url": "http://remote.example.org/hook"}, {"alert_smtp_host": "smtp.example.org"},
               {"alert_smtp_host": "smtp.example.org", "alert_email_from": "a@b.in", "alert_email_to": "not-an-email"}):
        with pytest.raises(AlertConfigError):
            AlertManager(Settings(alert_db_path=":memory:", **kw))
    with pytest.raises(ValueError):
        AlertManager(Settings(alert_db_path=":memory:", alert_score_threshold=1.0))
