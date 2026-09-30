import json

import pytest

from app.config import Settings
from app.pipeline.bus import InMemoryBus
from app.pipeline.metrics import MetricsRegistry
from app.pipeline.processor import Pipeline
from app.privacy.pii import PiiRedactor, luhn, verhoeff, verhoeff_check_digit

VISA = "4111111111111111"
AADHAAR_BODY = "23456789012"
AADHAAR = AADHAAR_BODY + verhoeff_check_digit(AADHAAR_BODY)


def test_checksums():
    assert luhn(VISA) and not luhn("4111111111111112")
    assert verhoeff(AADHAAR) and not verhoeff(AADHAAR[:-1] + str((int(AADHAAR[-1]) + 1) % 10))


@pytest.mark.parametrize("text,kind", [
    (f"card {VISA} used", "card"),
    ("card 4111-1111-1111-1111 used", "card"),
    ("mail bob.smith@example.co.in sent", "email"),
    ("ssn 123-45-6789 on file", "ssn"),
    (f"aadhaar {AADHAAR} kyc", "aadhaar"),
    ("pan ABCPE1234F filed", "pan"),
])
def test_detects(text, kind):
    out, found = PiiRedactor().redact(text)
    assert found[kind] == 1 and f"[PII:{kind}]" in out


@pytest.mark.parametrize("text", [
    "order 4111111111111112 failed",        # fails Luhn
    "ssn 000-12-3456 666-12-3456 900-12-3456",
    "user@10.0.0.5 login",                  # no alphabetic TLD
    "pid 1234567890123456 ok-ish",          # 16 digits, fails Luhn
    "ip 192.168.1.10 port 22",
])
def test_no_false_positive(text):
    out, found = PiiRedactor().redact(text)
    assert out == text and not found


def test_hash_mode_is_stable_and_keyed():
    a, b = PiiRedactor(mode="hash", key="k1"), PiiRedactor(mode="hash", key="k2")
    t1, _ = a.redact("x bob@example.com y")
    t2, _ = a.redact("z BOB@example.com w")
    assert t1.split()[1] == t2.split()[1]           # case-insensitive, same pseudonym
    assert "bob" not in t1
    assert b.redact("bob@example.com")[0] != a.redact("bob@example.com")[0]
    with pytest.raises(ValueError):
        PiiRedactor(mode="hash")


def test_bad_config():
    with pytest.raises(ValueError):
        PiiRedactor(types=["nope"])
    with pytest.raises(ValueError):
        PiiRedactor(mode="x")


def test_phone_is_opt_in():
    assert PiiRedactor().redact("call 9876543210")[1] == {}
    assert PiiRedactor(types=("phone",)).redact("call +91 9876543210")[1]["phone"] == 1


def _pipe(**kw):
    return Pipeline(InMemoryBus(100), MetricsRegistry(), Settings(alert_db_path=":memory:", mock_enabled=False, **kw))


def test_pipeline_redacts_everywhere():
    p = _pipe()
    raw = json.dumps({"message": f"payment by carol@example.com card {VISA}", "user": "carol@example.com",
                      "card": int(VISA)}).encode()
    doc = p.process(raw, "json")
    blob = json.dumps(doc)
    assert VISA not in blob and "carol@example.com" not in blob
    assert p.metrics.pii_redactions["card"] >= 1 and p.metrics.pii_redactions["email"] >= 1
    tmpl = doc.get("logunify", {}).get("template", {}).get("text", "")
    assert VISA not in tmpl and "carol@" not in tmpl


def test_pipeline_disabled():
    p = _pipe(pii_enabled=False)
    doc = p.process(json.dumps({"message": "mail dave@example.com"}).encode(), "json")
    assert "dave@example.com" in json.dumps(doc)


def test_failure_fails_closed_but_keeps_log():
    p = _pipe()

    def boom(_):
        raise RuntimeError("x")
    p.pii.redact_parsed = boom
    doc = p.process(json.dumps({"message": f"card {VISA}"}).encode(), "json")
    assert doc is not None and VISA not in json.dumps(doc)
    assert p.metrics.pii_failures == 1
