import email
import json
import socket
import time
from email import policy

import httpx
import pytest

from app.alerting.messages import Message, verify_signature
from app.alerting.notifiers import DeliveryError, EmailNotifier, WebhookNotifier, build_notifiers
from app.alerting.validation import AlertConfigError
from app.config import Settings
from tests.alert_helpers import FakeSMTP, make_message, run

URL = "https://hooks.example.org/services/T000/B000/SECRETPATH"


def webhook(handler, secret="s3cret", url=URL, **kw) -> WebhookNotifier:
    return WebhookNotifier(url, secret, 5.0, transport=httpx.MockTransport(handler), **kw)


def ok(_request):
    return httpx.Response(200, json={"ok": True})


# ------------------------------------------------------------------------------------------------ webhook
def test_webhook_posts_signed_json_a_receiver_can_verify():
    seen = []
    n = webhook(lambda r: (seen.append(r), httpx.Response(204))[1])
    msg = make_message()
    run(n.send(msg))
    run(n.send(msg))
    r = seen[0]
    assert r.method == "POST" and str(r.url) == URL and r.headers["content-type"] == "application/json"
    assert r.headers["x-logunify-event"] == "incident.detected" and r.headers["x-logunify-alert-id"] == "ALR-20260930-deadbeef"
    assert seen[0].headers["x-logunify-delivery"] != seen[1].headers["x-logunify-delivery"]
    ts, sig = r.headers["x-logunify-timestamp"], r.headers["x-logunify-signature"]
    assert sig.startswith("v1=") and verify_signature("s3cret", ts, r.content, sig)
    assert not verify_signature("wrong-secret", ts, r.content, sig)                      # wrong key
    assert not verify_signature("s3cret", ts, r.content + b" ", sig)                      # tampered body
    assert not verify_signature("s3cret", str(int(ts) - 10), r.content, sig)              # timestamp is part of the signature
    assert not verify_signature("s3cret", ts, r.content, sig, now=int(ts) + 3600)         # replay of a stale request
    assert not verify_signature("s3cret", "abc", r.content, sig) and not verify_signature("s3cret", ts, r.content, "")
    body = json.loads(r.content)
    assert body["schema"] == "logunify.alert/v1" and body["event"] == "incident.detected" and body["severity"] == "critical"
    assert body["text"].startswith("[CRITICAL][CERT-In 6h]") and body["cert_in_report"]["deadline"]["report_due_at"]["ist"]
    assert body["alert"]["id"] == "ALR-20260930-deadbeef" and body["test"] is False


def test_unsigned_webhook_sends_no_signature_header():
    seen = []
    run(webhook(lambda r: (seen.append(r), httpx.Response(200))[1], secret=None).send(make_message()))
    assert "x-logunify-signature" not in seen[0].headers and "x-logunify-timestamp" in seen[0].headers


@pytest.mark.parametrize("status,retryable", [(500, True), (502, True), (503, True), (429, True), (408, True),
                                              (400, False), (401, False), (403, False), (404, False), (410, False), (302, False)])
def test_webhook_error_classification(status, retryable):
    n = webhook(lambda r: httpx.Response(status, headers={"Location": "https://elsewhere.example.org/"} if status == 302 else {}))
    with pytest.raises(DeliveryError) as e:
        run(n.send(make_message()))
    assert e.value.retryable is retryable and f"HTTP {status}" in str(e.value)
    assert "SECRETPATH" not in str(e.value) and "hooks.example.org" in str(e.value)       # never leak the credential-bearing path


def test_webhook_network_failures_are_retryable_and_leak_nothing():
    def boom(request):
        raise httpx.ConnectError("could not connect to /services/T000/B000/SECRETPATH")

    def slow(request):
        raise httpx.ReadTimeout("timed out talking to SECRETPATH")

    for handler in (boom, slow):
        with pytest.raises(DeliveryError) as e:
            run(webhook(handler).send(make_message()))
        assert e.value.retryable is True and "SECRETPATH" not in str(e.value) and "Error" in str(e.value) or "Timeout" in str(e.value)


def test_webhook_never_follows_redirects():
    calls = []

    def redirect(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

    with pytest.raises(DeliveryError):
        run(webhook(redirect).send(make_message()))
    assert calls == [URL]                                                                   # the redirect target was never contacted


def test_webhook_constructor_validates_the_url():
    for bad in ("http://remote.example.org/x", "https://user:pw@hooks.example.org/x", "ftp://x.org/y", "hooks.example.org"):
        with pytest.raises(AlertConfigError):
            WebhookNotifier(bad, "s", 5.0)
    assert WebhookNotifier("http://127.0.0.1:9000/hook", None, 5.0).label == "http://127.0.0.1:9000"
    assert WebhookNotifier("https://hooks.example.org/x", None, 5.0).label == "https://hooks.example.org"


# ------------------------------------------------------------------------------------------------ email
def emailer(port, security="none", **kw) -> EmailNotifier:
    return EmailNotifier("127.0.0.1", port, security, "", None, "logunify@acme.example",
                         ("soc@acme.example", "ciso@acme.example"), 5.0, **kw)


def test_email_is_delivered_with_priority_headers_body_and_json_attachment():
    with FakeSMTP() as smtp:
        msg = make_message()
        run(emailer(smtp.port).send(msg))
    sender, rcpts, raw = smtp.messages[0]
    assert sender == "logunify@acme.example" and rcpts == ["soc@acme.example", "ciso@acme.example"]
    m = email.message_from_bytes(raw, policy=policy.default)
    assert m["Subject"] == msg.subject and m["Importance"] == "high" and m["X-Priority"].startswith("1")
    assert m["Auto-Submitted"] == "auto-generated" and m["X-LogUnify-Alert-Id"] == "ALR-20260930-deadbeef"
    body = m.get_body(preferencelist=("plain",)).get_content()
    assert "REPORT DUE BY" in body and "incident@cert-in.org.in" in body and "DRAFT" in body
    [att] = list(m.iter_attachments())
    assert att.get_filename() == "cert-in-report-ALR-20260930-deadbeef.json" and att.get_content_type() == "application/json"
    assert json.loads(att.get_content())["reference"] == "ALR-20260930-deadbeef"


def test_header_injection_through_log_derived_text_is_neutralised():
    evil = Message("incident.detected", "ALR-1", "host x\r\nBcc: attacker@example.com\r\nX-Evil: 1", "body", {}, None)
    with FakeSMTP() as smtp:
        run(emailer(smtp.port).send(evil))
    _, rcpts, raw = smtp.messages[0]
    m = email.message_from_bytes(raw, policy=policy.default)
    assert m["Bcc"] is None and m["X-Evil"] is None and "attacker@example.com" not in "".join(rcpts)
    assert rcpts == ["soc@acme.example", "ciso@acme.example"]                              # recipients come from config only
    assert "\n" not in m["Subject"]


def test_email_failure_classification():
    with pytest.raises(DeliveryError) as e:                                                  # nothing is listening
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        run(emailer(port).send(make_message()))
    assert e.value.retryable is True

    with FakeSMTP(reject_rcpt=True) as smtp, pytest.raises(DeliveryError) as e:
        run(emailer(smtp.port).send(make_message()))
    assert e.value.retryable is False and "recipients refused" in str(e.value) and smtp.messages == []

    with FakeSMTP(temp_fail=True) as smtp, pytest.raises(DeliveryError) as e:               # 451: try again later
        run(emailer(smtp.port).send(make_message()))
    assert e.value.retryable is True and "451" in str(e.value)


def test_starttls_is_required_never_silently_downgraded_to_plaintext():
    with FakeSMTP(advertise_starttls=False) as smtp, pytest.raises(DeliveryError) as e:
        run(emailer(smtp.port, security="starttls").send(make_message()))
    assert e.value.retryable is False and "capability" in str(e.value) and smtp.messages == []


def test_email_constructor_validation():
    with pytest.raises(AlertConfigError):
        EmailNotifier("smtp.example.org", 25, "none", "", None, "a@b.in", ("c@d.in",))      # plaintext to a remote host
    assert EmailNotifier("smtp.example.org", 25, "none", "", None, "a@b.in", ("c@d.in",), allow_plaintext=True)
    with pytest.raises(AlertConfigError):
        EmailNotifier("127.0.0.1", 25, "tls", "", None, "a@b.in", ("c@d.in",))              # unknown security mode
    with pytest.raises(AlertConfigError):
        EmailNotifier("127.0.0.1", 25, "none", "", None, "a@b.in", ())                      # no recipients
    with pytest.raises(AlertConfigError):
        EmailNotifier("127.0.0.1", 25, "none", "", None, "not-an-address", ("c@d.in",))


# ------------------------------------------------------------------------------------------------ settings -> channels
def test_build_notifiers_from_settings():
    assert build_notifiers(Settings(alert_db_path=":memory:")) == []
    both = build_notifiers(Settings(alert_webhook_url=URL, alert_webhook_secret="s", alert_smtp_host="127.0.0.1",
                                    alert_smtp_security="none", alert_email_from="a@b.in", alert_email_to="c@d.in, e@f.in"))
    assert [n.name for n in both] == ["webhook", "email"] and both[1].recipients == ("c@d.in", "e@f.in")
    for kw in ({"alert_smtp_host": "h"}, {"alert_email_to": "c@d.in"}, {"alert_smtp_host": "h", "alert_email_to": "c@d.in"}):
        with pytest.raises(AlertConfigError):
            build_notifiers(Settings(**kw))
