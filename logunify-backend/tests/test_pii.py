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


def _luhn_complete(prefix: str, length: int = 16) -> str:
    body = prefix + "0" * (length - 1 - len(prefix))
    for c in "0123456789":
        if luhn(body + c):
            return body + c
    raise AssertionError


@pytest.mark.parametrize("prefix", ["4", "51", "55", "2221", "2720", "34", "37", "36", "38", "35", "60", "65", "300", "305", "644", "649", "508"])
def test_issuer_ranges_are_redacted(prefix):
    n = _luhn_complete(prefix)
    out, found = PiiRedactor().redact(f"pan {n} end")
    assert found["card"] == 1 and n not in out


@pytest.mark.parametrize("prefix", ["50", "56", "2220", "2721", "33", "39", "306", "643", "66", "507", "10", "99"])
def test_luhn_valid_non_issuer_numbers_are_left_alone(prefix):
    n = _luhn_complete(prefix)
    assert luhn(n)
    out, found = PiiRedactor().redact(f"order {n} end")
    assert found["card"] == 0 and n in out


@pytest.mark.parametrize("length,expected", [(12, 0), (13, 1), (16, 1), (19, 1), (20, 0)])
def test_card_length_bounds(length, expected):
    n = _luhn_complete("4", length)
    _, found = PiiRedactor().redact(f"x {n} y")
    assert found["card"] == expected


def test_verhoeff_known_vectors_and_every_table_row_is_exercised():
    assert verhoeff("2363") and not verhoeff("2364")           # classic Verhoeff test vectors: check digit 3 for payload 236
    assert verhoeff_check_digit("236") == "3"
    for body in ("1", "12", "123", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890", "98765432109876543210"):
        assert verhoeff(body + verhoeff_check_digit(body))     # round-trip across all 8 permutation rows and both table axes
        wrong = body + str((int(verhoeff_check_digit(body)) + 1) % 10)
        assert not verhoeff(wrong)


def test_hash_mode_is_stable_per_value_and_distinct_across_values():
    r = PiiRedactor(mode="hash", key="k" * 32)
    a1, _ = r.redact("mail a@example.com")
    a2, _ = r.redact("MAIL A@example.com")
    b, _ = r.redact("mail b@example.com")
    assert a1.split()[-1] == a2.split()[-1] != b.split()[-1]
    assert a1.split()[-1].startswith("[PII:email:")
    masked, _ = PiiRedactor(mode="mask").redact("mail a@example.com")
    assert masked.endswith("[PII:email]")
