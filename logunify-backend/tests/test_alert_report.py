import re
from datetime import datetime, timedelta, timezone

import pytest

from app.alerting.cert_in import (ANNEXURE_I, OrgProfile, affected_asset, build_report, fmt_remaining, parse_ts,
                                  render_text, subject_line, suggest_types, ts_pair)
from app.alerting.models import Alert
from app.alerting.rules import AlertRules
from tests.alert_helpers import make_doc

NOW = 1_790_000_000.0
ORG = OrgProfile(name="Acme Bank Ltd", address="1 MG Road, Mumbai 400001", location="Mumbai, Maharashtra, India",
                 isp="Tata Communications", poc_name="Asha Rao", poc_designation="CISO", poc_email="ciso@acme.example",
                 poc_mobile="+91 90000 00001", poc_phone="022-5550100", critical_assets=("db-*", "10.9.*"))


def alert_for(doc=None, status="open", **kw) -> Alert:
    doc = doc or make_doc()
    trig = AlertRules(0.9, "T1070,T1048,T1190,T1078,T9999", require_rule_basis=False).evaluate(doc)
    return Alert(id="ALR-20260930-deadbeef", dedup_key="k", status=status, created_at=NOW, due_at=NOW + 6 * 3600,
                 last_seen_at=NOW, occurrences=1, trigger=trig.as_dict(), doc=doc,
                 evidence={"record_sha256": "ab" * 32, "event_id": doc["event"]["id"]}, **kw)


def report(alert=None, org=ORG, now=NOW, ref=None) -> dict:
    return build_report(alert or alert_for(), org, now=now, evidence_ref=ref)


# ------------------------------------------------------------------------------------------------ vocabulary
def test_annexure_i_is_the_twenty_item_controlled_vocabulary():
    assert list(ANNEXURE_I) == "i ii iii iv v vi vii viii ix x xi xii xiii xiv xv xvi xvii xviii xix xx".split()
    assert ANNEXURE_I["iii"] == "Unauthorised access of IT systems/data" and ANNEXURE_I["xi"] == "Data Breach"
    assert "Ransomware" in ANNEXURE_I["v"] and ANNEXURE_I["ii"] == "Compromise of critical systems/information"


@pytest.mark.parametrize("technique,expected", [("T1070", ("ii",)), ("T1070.001", ("ii",)), ("T1048", ("xi", "xii")),
                                                ("T1190", ("x", "vi", "ii")), ("T1486", ("v", "ii")), ("T9999", ())])
def test_incident_type_suggestions(technique, expected):
    assert suggest_types(technique) == expected
    assert all(i in ANNEXURE_I for i in expected)


# ------------------------------------------------------------------------------------------------ deadline
def test_six_hour_clock_runs_from_noticing():
    d = report()["deadline"]
    started, due = datetime.fromisoformat(d["clock_started_at"]["utc"]), datetime.fromisoformat(d["report_due_at"]["utc"])
    assert due - started == timedelta(hours=6)
    assert started.timestamp() == NOW
    ist = datetime.fromisoformat(d["report_due_at"]["utc"]).astimezone(timezone(timedelta(hours=5, minutes=30)))
    assert d["report_due_at"]["ist"] == ist.strftime("%d/%m/%Y %H:%M")
    assert re.fullmatch(r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}", d["clock_started_at"]["ist"])
    assert d["submit_via"] == {"email": "incident@cert-in.org.in", "phone": "1800-11-4949", "fax": "1800-11-6969"}
    assert "FAQ Q30" in d["incomplete_information"] and "6 hours" in d["rule"]


def test_seconds_remaining_and_overdue():
    assert report(now=NOW + 3600)["deadline"]["seconds_remaining"] == 5 * 3600
    late = report(now=NOW + 7 * 3600)["deadline"]
    assert late["overdue"] is True and late["seconds_remaining"] == -3600
    done = report(alert_for(status="reported"), now=NOW + 7 * 3600)["deadline"]
    assert done["seconds_remaining"] is None and done["overdue"] is False      # the clock stops once it was reported


def test_time_helpers():
    assert ts_pair(None) is None and ts_pair(0)["utc"].startswith("1970-01-01T00:00:00")
    assert ts_pair(0)["ist"] == "01/01/1970 05:30"
    assert parse_ts("2026-09-30T09:15:00Z") == parse_ts("2026-09-30T09:15:00+00:00") == parse_ts("2026-09-30T09:15:00")
    assert parse_ts("2026-09-30T14:45:00+05:30") == parse_ts("2026-09-30T09:15:00Z")
    assert parse_ts("yesterday") is None and parse_ts(None) is None and parse_ts(5) is None
    assert fmt_remaining(3 * 3600 + 5 * 60) == "3h05m" and fmt_remaining(-90) == "-0h01m"


# ------------------------------------------------------------------------------------------------ form fields
def test_every_field_of_the_official_form_is_present():
    r = report()
    assert r["form"]["url"] == "https://www.cert-in.org.in/PDF/certinirform.pdf" and "not mandatory" in r["form"]["note"]
    assert r["i_am"] == "the affected entity" and r["affected_entity"] == "Acme Bank Ltd"
    assert set(r["reporter"]) >= {"name_role", "type", "organization_name", "contact_no", "email", "address"}
    assert r["reporter"]["name_role"] == "Asha Rao, CISO" and r["reporter"]["contact_no"] == "+91 90000 00001"
    assert set(r["affected_system"]) >= {"domain_url", "ip_address", "operating_system", "make_model_cloud", "application",
                                         "location", "network_isp"}
    assert r["affected_system"]["location"] == "Mumbai, Maharashtra, India" and r["affected_system"]["network_isp"] == "Tata Communications"
    assert set(r["affected_system_critical"]) >= {"answer", "details"}
    assert r["incident_type"]["annexure_i"][0] == {"id": "ii", "label": ANNEXURE_I["ii"]}
    assert r["occurrence"]["ist"] == "30/09/2026 14:45"                    # 09:15 UTC = 14:45 IST
    assert r["detection"]["utc"] and "T1070" in r["description"] and "0.95" in r["description"]


def test_reporter_block_is_blank_not_invented_when_unconfigured():
    r = report(org=OrgProfile())
    assert r["reporter"]["name_role"] is None and r["reporter"]["organization_name"] is None and r["reporter"]["email"] is None
    cfg = {x["field"] for x in r["completeness"]["needs_configuration"]}
    assert cfg == {"reporter.name_role", "reporter.organization_name", "reporter.contact_no", "reporter.email", "reporter.address"}


def test_affected_system_versus_remote_party():
    inbound = affected_asset(make_doc(destination={"ip": "10.9.1.5"}))            # external attacker -> internal server
    assert inbound == {"ip": "10.9.1.5", "host": "db-01", "remote_ip": "203.0.113.9"}
    outbound = affected_asset(make_doc(source={"ip": "10.2.3.4"}, destination={"ip": "198.51.100.23"}))   # exfiltration
    assert outbound["ip"] == "10.2.3.4" and outbound["remote_ip"] == "198.51.100.23"
    public = affected_asset(make_doc(source={"ip": "203.0.113.9"}, destination={"ip": "198.51.100.7"}))  # public server
    assert public["ip"] == "198.51.100.7" and public["remote_ip"] == "203.0.113.9"
    syslog_only = affected_asset(make_doc())                                      # no destination: host is the asset
    assert syslog_only["ip"] is None and syslog_only["host"] == "db-01" and syslog_only["remote_ip"] == "203.0.113.9"
    assert affected_asset({}) == {"ip": None, "host": None, "remote_ip": None}


def test_a_lone_external_address_is_the_remote_party_never_the_victim():
    """Found in the live run: 'outbound transfer ... to 91.240.118.172' was reported as an incident ON 91.240.118.172."""
    exfil = {"destination": {"ip": "91.240.118.172"}, "message": "Unexpected outbound transfer of 597 MB to 91.240.118.172"}
    assert affected_asset(exfil) == {"ip": None, "host": None, "remote_ip": "91.240.118.172"}
    attacker_only = affected_asset({"source": {"ip": "185.220.101.4"}})
    assert attacker_only["ip"] is None and attacker_only["remote_ip"] == "185.220.101.4"
    doc = make_doc(threat={"technique": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}})
    doc["destination"] = {"ip": "91.240.118.172"}
    del doc["source"], doc["host"]
    r = report(alert_for(doc))
    assert r["affected_system"]["ip_address"] is None and r["additional_information"]["remote_party"]["ip"] == "91.240.118.172"
    assert "ip_address" in " ".join(x["field"] for x in r["completeness"]["needs_analyst"])
    s = subject_line("incident.detected", r)
    assert "on unidentified asset (remote 91.240.118.172)" in s and "on 91.240.118.172:" not in s
    assert "an unidentified asset" in r["description"] and "Remote party 91.240.118.172" in r["description"]


def test_incident_grouping_key_prefers_asset_then_remote_party():
    from app.alerting.cert_in import asset_key
    assert asset_key(make_doc()) == "db-01"
    assert asset_key(make_doc(destination={"ip": "10.9.1.5"}, host={"name": None})) == "10.9.1.5"
    only_src = {"source": {"ip": "185.220.101.4"}}
    only_dst = {"destination": {"ip": "91.240.118.172"}}
    assert asset_key(only_src) == "185.220.101.4" and asset_key(only_dst) == "91.240.118.172"     # different remotes stay separate
    assert asset_key({}) == "unknown"


def test_mission_critical_answer_comes_from_the_configured_asset_list():
    yes = report(alert_for(make_doc(host={"name": "db-01"})))["affected_system_critical"]
    assert yes["answer"] == "Yes" and yes["origin"] == "configuration"
    by_ip = report(alert_for(make_doc(host={"name": "app-7"}, destination={"ip": "10.9.3.3"})))["affected_system_critical"]
    assert by_ip["answer"] == "Yes"
    unknown = report(alert_for(make_doc(host={"name": "web-01"})))
    assert unknown["affected_system_critical"]["answer"] is None
    assert "affected_system_critical.answer" in [x["field"] for x in unknown["completeness"]["needs_analyst"]]


def test_analyst_supplied_values_fill_the_gaps_and_win_over_inference():
    a = alert_for(make_doc(host={"name": "web-01"}), analyst={
        "critical": False, "critical_details": "public marketing site", "operating_system": "Ubuntu 22.04",
        "make_model_cloud": "AWS ap-south-1 t3.large", "network_isp": "AWS", "ip_address": "10.1.1.1",
        "incident_type_ids": ["iii", "ii"], "impact": "none observed", "actions_taken": "host isolated",
        "description_addendum": "Confirmed by SOC", "i_am": "reporting incident affecting other entity",
        "affected_entity": "Partner Co", "location": "Pune, Maharashtra, India"})
    r = report(a)
    assert r["affected_system_critical"] == {"answer": "No", "details": "public marketing site", "origin": "analyst"}
    assert r["affected_system"]["operating_system"] == "Ubuntu 22.04" and r["affected_system"]["ip_address"] == "10.1.1.1"
    assert r["affected_system"]["location"] == "Pune, Maharashtra, India"
    assert [x["id"] for x in r["incident_type"]["annexure_i"]] == ["iii", "ii"] and r["incident_type"]["origin"] == "analyst"
    assert r["i_am"] == "reporting incident affecting other entity" and r["affected_entity"] == "Partner Co"
    assert "Analyst addendum: Confirmed by SOC" in r["description"]
    assert r["completeness"]["needs_analyst"] == []
    assert [x["field"] for x in r["completeness"]["to_confirm"]] == ["affected_system"]


def test_invalid_analyst_choices_fall_back_safely():
    r = report(alert_for(analyst={"incident_type_ids": ["zz"], "i_am": "someone else"}))
    assert [x["id"] for x in r["incident_type"]["annexure_i"]] == ["ii"] and r["i_am"] == "the affected entity"


def test_unknown_technique_asks_the_analyst_for_the_incident_type():
    doc = make_doc(threat={"technique": {"id": "T9999", "name": "Novel"}})
    r = report(alert_for(doc))
    assert r["incident_type"]["annexure_i"] == []
    assert "incident_type.annexure_i" in [x["field"] for x in r["completeness"]["needs_analyst"]]


def test_missing_items_are_listed_but_the_report_is_still_produced():
    r = report(alert_for(make_doc(host={"name": "web-01"})))
    needs = {x["field"] for x in r["completeness"]["needs_analyst"]}
    assert {"affected_system.operating_system", "affected_system.make_model_cloud", "affected_system.ip_address"} <= needs
    assert "complete the rest afterwards" in r["completeness"]["note"]


# ------------------------------------------------------------------------------------------------ honesty about data
def test_demo_enrichment_is_never_shown_to_a_regulator():
    doc = make_doc(source={"geo": {"country_iso_code": "NL", "country_name": "Netherlands"}},
                   logunify={"geoip": "mock"}, threat={"indicator": {"provider": "mock-misp", "type": "ipv4-addr"}})
    r = report(alert_for(doc))
    rp = r["additional_information"]["remote_party"]
    assert "geo" not in rp and "threat_intel" not in rp
    warnings = " ".join(r["data_quality_warnings"])
    assert "GeoIP" in warnings and "demo feed" in warnings


def test_real_enrichment_is_included():
    doc = make_doc(source={"geo": {"country_iso_code": "DE", "country_name": "Germany"}},
                   threat={"indicator": {"provider": "misp", "type": "ipv4-addr", "confidence": "High", "description": "C2"}})
    rp = report(alert_for(doc))["additional_information"]["remote_party"]
    assert rp["geo"]["country_iso_code"] == "DE" and rp["threat_intel"]["provider"] == "misp"


def test_a_log_without_its_own_timestamp_is_flagged():
    """Found in the live run: free-text logs carry no time, so 'occurrence' silently equalled the ingest time."""
    doc = make_doc(event={"ingested": "2026-09-30T09:15:00+00:00"})                  # same instant as @timestamp
    assert "carried no timestamp" in " ".join(report(alert_for(doc))["data_quality_warnings"])
    later = make_doc(event={"ingested": "2026-09-30T09:15:07+00:00"})
    assert "carried no timestamp" not in " ".join(report(alert_for(later))["data_quality_warnings"])


def test_configured_defaults_are_flagged_for_confirmation_not_presented_as_facts():
    r = report(alert_for(make_doc(host={"name": "web-01"})), org=OrgProfile(location="Mumbai, Maharashtra, India", isp="Tata"))
    confirm = {x["field"] for x in r["completeness"]["to_confirm"]}
    assert {"affected_system.location", "affected_system.network_isp"} <= confirm
    analyst = alert_for(make_doc(host={"name": "web-01"}), analyst={"location": "Pune, Maharashtra, India"})
    confirm = {x["field"] for x in report(analyst, org=OrgProfile(location="Mumbai, Maharashtra, India"))["completeness"]["to_confirm"]}
    assert "affected_system.location" not in confirm                                  # the analyst supplied it


def test_timestamp_and_heuristic_warnings():
    doc = make_doc(event={"original": "<38>Oct 11 22:14:15 web-01 sshd[1]: something odd"})
    w = " ".join(report(alert_for(doc))["data_quality_warnings"])
    assert "no year or timezone" in w and "heuristic rule 'log_clearing'" in w
    assert "no year or timezone" not in " ".join(report()["data_quality_warnings"])


# ------------------------------------------------------------------------------------------------ evidence
def test_evidence_block_links_the_record_hash_and_the_integrity_batch():
    ref = {"batch_id": "batch-000007", "index": 12, "merkle_root": "cd" * 32, "anchor_tx_id": "ef" * 32}
    ev = report(ref=ref)["additional_information"]["evidence"]
    assert ev["record_sha256"] == "ab" * 32 and ev["event_id"] == "logunify.ecs:0:42"
    assert ev["integrity_reference"]["batch_id"] == "batch-000007" and "para (iv)" in ev["note"]
    assert "GET /api/v1/alerts/ALR-20260930-deadbeef/evidence" in ev["full_record"]
    assert report()["additional_information"]["evidence"]["integrity_reference"] is None


def test_drain3_template_text_is_redacted_too():
    """A first-seen message's Drain3 template still holds the literal values (found by the API test: it leaked)."""
    doc = make_doc(logunify={"template": {"id": 9, "text": "Audit log cleared by root password = hunter2 token=abc123456789"}})
    r = report(alert_for(doc))
    assert "hunter2" not in render_text(r) + str(r) and "abc123456789" not in str(r)
    assert "password = [REDACTED]" in r["additional_information"]["detection"]["log_template"]


def test_excerpt_in_the_report_is_redacted_and_bounded():
    secret = "Audit log cleared by root using password=hunter2 Authorization: Bearer abcdefghijklmnop12345 " + "x" * 900
    doc = make_doc(message=secret, event={"original": secret})
    r = report(alert_for(doc))
    text = render_text(r) + str(r)
    assert "hunter2" not in text and "abcdefghijklmnop12345" not in text
    assert len(r["additional_information"]["evidence"]["log_excerpt_redacted"]) < 480


# ------------------------------------------------------------------------------------------------ rendering
def test_text_report_has_the_deadline_contacts_form_fields_and_gaps():
    r = report(alert_for(make_doc(host={"name": "web-01"})))
    t = render_text(r)
    for needle in ("CERT-In 6-HOUR REPORTING CLOCK IS RUNNING", "REPORT DUE BY", "incident@cert-in.org.in", "1800-11-4949",
                   "Incident type (Annexure I)", "Occurrence date & time (IST)", "Detection date & time (IST)",
                   "Brief description of incident", "Record SHA-256", "Reportability check", "[ANALYST]", "Still missing",
                   "FAQ Q30", "never files with CERT-In by itself", "Domain/URL", "Network and name of ISP"):
        assert needle in t, needle
    assert "[CONFIG]" not in t                                              # org is configured in ORG
    assert "[CONFIG]" in render_text(report(org=OrgProfile()))


def test_banners_for_reminders_and_overdue():
    r = report(now=NOW + 5 * 3600)
    assert "REMINDER (1h left)" in render_text(r, "incident.reminder", "1h left")
    assert "OVERDUE" in render_text(report(now=NOW + 7 * 3600), "incident.overdue")


def test_subject_line_is_single_line_and_bounded():
    r = report(alert_for(make_doc(host={"name": "evil\r\nBcc: attacker@example.com"})))
    s = subject_line("incident.detected", r)
    assert "\n" not in s and "\r" not in s and len(s) <= 180
    assert s.startswith("[CRITICAL][CERT-In 6h] T1070 Indicator Removal on evil") and "ALR-20260930-deadbeef" in s
    assert subject_line("incident.reminder", report(), "30 min left").startswith("[REMINDER 30 min left]")
    assert subject_line("incident.overdue", report()).startswith("[OVERDUE]")
