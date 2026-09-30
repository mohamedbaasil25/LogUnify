import pytest

from app.alerting.redact import clean, redact
from app.alerting.rules import AlertRules
from app.alerting.validation import (AlertConfigError, parse_emails, parse_minutes, parse_techniques, safe_url_label,
                                     validate_webhook_url)
from tests.alert_helpers import make_doc

CRITICAL = "T1070,T1190,T1078"


def rules(**kw):
    return AlertRules(kw.pop("threshold", 0.9), kw.pop("critical", CRITICAL), **kw)


# ------------------------------------------------------------------------------------------------ the trigger
def test_fires_when_score_exceeds_threshold_and_technique_is_critical():
    t = rules().evaluate(make_doc())
    assert t is not None and t.technique_id == "T1070" and t.critical_match == "T1070"
    assert t.score == 0.95 and t.threshold == 0.9 and t.basis == "rule:log_clearing"


@pytest.mark.parametrize("score,fires", [(0.8999, False), (0.9, False), (0.9001, True), (0.95, True), (1.0, True)])
def test_threshold_is_strictly_exceeded(score, fires):
    doc = make_doc(logunify={"anomaly": {"score": score}})
    assert (rules().evaluate(doc) is not None) is fires


def test_non_critical_technique_does_not_fire_even_at_max_score():
    doc = make_doc(logunify={"anomaly": {"score": 1.0}}, threat={"technique": {"id": "T1110", "name": "Brute Force"}})
    assert rules().evaluate(doc) is None


def test_sub_technique_matches_critical_parent_but_not_the_reverse():
    sub = make_doc(threat={"technique": {"id": "T1070.001", "name": "Clear Windows Event Logs"}})
    assert rules().evaluate(sub).critical_match == "T1070"
    assert rules(critical="T1070.002").evaluate(sub) is None          # a specific sub-technique entry is exact
    assert rules(critical="T1070.001").evaluate(sub).critical_match == "T1070.001"


def test_placeholder_fallback_tag_is_not_a_finding():
    doc = make_doc(threat={"technique": {"id": "T1078", "name": "Valid Accounts"}}, logunify={"mitre": {"basis": "default"}})
    assert rules().evaluate(doc) is None
    assert rules(require_rule_basis=False).evaluate(doc) is not None     # opt-in only


def test_missing_basis_is_treated_as_not_rule_based():
    doc = make_doc()
    del doc["logunify"]["mitre"]
    assert rules().evaluate(doc) is None


def test_model_warmup_score_is_ignored():
    assert rules().evaluate(make_doc(logunify={"anomaly": {"model_ready": False}})) is None


@pytest.mark.parametrize("mutate", [
    lambda d: d["logunify"]["anomaly"].pop("score"),
    lambda d: d["logunify"]["anomaly"].update(score="0.99"),
    lambda d: d["logunify"]["anomaly"].update(score=True),
    lambda d: d.pop("threat"),
    lambda d: d["threat"]["technique"].update(id=None),
    lambda d: d.pop("logunify"),
])
def test_malformed_or_partial_docs_never_raise_and_never_fire(mutate):
    doc = make_doc()
    mutate(doc)
    assert rules().evaluate(doc) is None


def test_technique_id_is_normalised():
    doc = make_doc(threat={"technique": {"id": " t1070 "}})
    assert rules().evaluate(doc).technique_id == "T1070"


def test_bad_threshold_is_rejected():
    for bad in (-0.1, 1.0, 1.5):
        with pytest.raises(ValueError):
            rules(threshold=bad)


# ------------------------------------------------------------------------------------------------ config validation
def test_parse_techniques():
    assert parse_techniques("t1070, T1190 ;T1003.001") == frozenset({"T1070", "T1190", "T1003.001"})
    for bad in ("T107", "1070", "T1070.1", "T1070,banana"):
        with pytest.raises(AlertConfigError):
            parse_techniques(bad)
    with pytest.raises(AlertConfigError):
        parse_techniques("  ")


def test_parse_minutes():
    assert parse_minutes("30, 120,60,60") == (120, 60, 30)
    for bad in ("0", "-5", "360", "abc", "500"):
        with pytest.raises(AlertConfigError):
            parse_minutes(bad)


def test_parse_emails_rejects_injection_and_junk():
    assert parse_emails("a@b.in, soc@corp.example.org") == ("a@b.in", "soc@corp.example.org")
    for bad in ("nobody", "a@b", "a@b.in\r\nBcc: x@y.com", "a b@c.in"):
        with pytest.raises(AlertConfigError):
            parse_emails(bad)


def test_webhook_url_rules():
    assert validate_webhook_url("https://hooks.example.org/x/y") == "https://hooks.example.org/x/y"
    assert validate_webhook_url("http://127.0.0.1:9000/hook") and validate_webhook_url("http://localhost/hook")
    with pytest.raises(AlertConfigError):
        validate_webhook_url("http://hooks.example.org/x")                      # plaintext to a remote host
    assert validate_webhook_url("http://hooks.example.org/x", allow_http=True)
    for bad in ("ftp://x.org/a", "https://user:pw@hooks.example.org/x", "not a url", "https:///nohost"):
        with pytest.raises(AlertConfigError):
            validate_webhook_url(bad)


def test_url_label_never_includes_path_or_query():
    assert safe_url_label("https://hooks.example.org:8443/services/T000/B000/SECRETTOKEN?x=1") == "https://hooks.example.org:8443"


# ------------------------------------------------------------------------------------------------ redaction
@pytest.mark.parametrize("text,gone", [
    ("login ok password=hunter2 user=bob", "hunter2"),
    ('{"user":"bob","password": "s3cret value"}', "s3cret value"),
    ("curl -H 'Authorization: Bearer abcdefghijklmnop12345' https://x", "abcdefghijklmnop12345"),
    ("api_key=AKIAABCDEFGHIJKLMNOP leaked", "AKIAABCDEFGHIJKLMNOP"),
    ("token is ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY----- tail", "MIIabc"),
    ("session=abc123def; other=1", "abc123def"),
])
def test_secrets_are_redacted(text, gone):
    out = redact(text)
    assert gone not in out and "[REDACTED" in out


def test_redaction_keeps_investigative_content():
    text = "Failed password for invalid user bob from 185.220.101.4 port 22 ssh2"
    assert redact(text) == text                               # 'password' without a value delimiter is not a secret


def test_redact_truncates_and_strips_control_characters():
    out = redact("a" * 1000, max_len=50)
    assert out.startswith("a" * 50) and "truncated 950 chars" in out
    assert clean("x\x00y\r\nz\tw") == "x y z w" and redact(None) == "" and redact("") == ""
