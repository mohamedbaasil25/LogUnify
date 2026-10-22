"""Delivery channels: signed webhook, SMTP email, Slack and Microsoft Teams incoming webhooks.

Both raise DeliveryError(retryable=...) so the manager can tell "try again" (network, 5xx, 429, SMTP 4xx) from "this
will never work without a config change" (401/403/404, SMTP auth/5xx, STARTTLS unsupported). Error text never
contains URLs with credentials, secrets or message bodies.
"""
import asyncio
import json
import logging
import smtplib
import ssl
import time
import uuid
from email.message import EmailMessage

import httpx

from .messages import Message, sign
from .redact import clean
from .validation import AlertConfigError, _is_loopback, parse_emails, safe_url_label, validate_webhook_url

log = logging.getLogger("logunify.alerting")


class DeliveryError(Exception):
    def __init__(self, message: str, retryable: bool = True):
        super().__init__(message)
        self.retryable = retryable


class WebhookNotifier:
    name = "webhook"

    def __init__(self, url: str, secret: str | None, timeout: float = 10.0, *, allow_http: bool = False,
                 ca_file: str | None = None, transport: httpx.AsyncBaseTransport | None = None):
        self.url = validate_webhook_url(url, allow_http)
        self.label = safe_url_label(url)                 # only scheme://host is ever logged or stored
        self._secret, self._timeout, self._verify, self._transport = secret, timeout, ca_file or True, transport

    async def send(self, msg: Message) -> None:
        body = json.dumps(msg.payload, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
        ts = int(time.time())
        headers = {"Content-Type": "application/json", "User-Agent": "LogUnify-Alerting/1",
                   "X-LogUnify-Event": msg.kind, "X-LogUnify-Delivery": uuid.uuid4().hex, "X-LogUnify-Timestamp": str(ts)}
        if msg.alert_id:
            headers["X-LogUnify-Alert-Id"] = msg.alert_id
        if self._secret:
            headers["X-LogUnify-Signature"] = "v1=" + sign(self._secret, ts, body)
        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify, follow_redirects=False,
                                         transport=self._transport) as client:
                r = await client.post(self.url, content=body, headers=headers)
        except httpx.HTTPError as e:
            raise DeliveryError(f"webhook {self.label}: {type(e).__name__}", retryable=True) from None
        if 200 <= r.status_code < 300:
            return
        raise DeliveryError(f"webhook {self.label}: HTTP {r.status_code}",
                            retryable=r.status_code in (408, 425, 429) or r.status_code >= 500)


class EmailNotifier:
    name = "email"

    def __init__(self, host: str, port: int, security: str, user: str, password: str | None, sender: str,
                 recipients: tuple[str, ...], timeout: float = 15.0, *, allow_plaintext: bool = False):
        if security not in ("starttls", "ssl", "none"):
            raise AlertConfigError("alert_smtp_security must be starttls, ssl or none")
        if security == "none" and not (allow_plaintext or _is_loopback(host)):
            raise AlertConfigError("plaintext SMTP is only allowed for loopback (or set alert_smtp_allow_plaintext)")
        if not recipients:
            raise AlertConfigError("alert_email_to must list at least one recipient")
        parse_emails(sender)
        self.host, self.port, self.security, self.user, self.password = host, port, security, user, password
        self.sender, self.recipients, self.timeout = sender, recipients, timeout
        self.label = f"{host}:{port}"

    async def send(self, msg: Message) -> None:
        await asyncio.to_thread(self._send_sync, msg)

    def _connect(self) -> smtplib.SMTP:
        ctx = ssl.create_default_context()
        if self.security == "ssl":
            smtp = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=ctx)
        else:
            smtp = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        try:
            smtp.ehlo()
            if self.security == "starttls":
                smtp.starttls(context=ctx)                # raises if unsupported: never silently downgrade to plaintext
                smtp.ehlo()
            if self.user:
                smtp.login(self.user, self.password or "")
        except Exception:
            smtp.close()
            raise
        return smtp

    def _send_sync(self, msg: Message) -> None:
        em = EmailMessage()
        em["From"], em["To"], em["Subject"] = self.sender, ", ".join(msg.recipients or self.recipients), clean(msg.subject)
        em["X-Priority"], em["Importance"], em["Auto-Submitted"] = "1 (Highest)", "high", "auto-generated"
        if msg.alert_id:
            em["X-LogUnify-Alert-Id"] = msg.alert_id
        em.set_content(msg.text)
        if msg.attachment:
            name, data = msg.attachment
            em.add_attachment(data, maintype="application", subtype="json", filename=name)
        try:
            smtp = self._connect()
            try:
                smtp.send_message(em)
            finally:
                try:
                    smtp.quit()
                except smtplib.SMTPException:
                    smtp.close()
        except smtplib.SMTPNotSupportedError:
            raise DeliveryError(f"smtp {self.label}: server lacks a required capability (STARTTLS/AUTH)", False) from None
        except smtplib.SMTPRecipientsRefused:
            raise DeliveryError(f"smtp {self.label}: all recipients refused", False) from None
        except smtplib.SMTPResponseException as e:
            raise DeliveryError(f"smtp {self.label}: {e.smtp_code}", retryable=400 <= e.smtp_code < 500) from None
        except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
            raise DeliveryError(f"smtp {self.label}: {type(e).__name__}", retryable=True) from None


class _ChatNotifier:
    """Chat incoming webhook (Slack / Teams). The URL path IS the credential: only scheme://host is ever logged, and it must be https."""
    name = ""

    def __init__(self, url: str, timeout: float = 10.0, *, ca_file: str | None = None, transport: httpx.AsyncBaseTransport | None = None):
        self.url = validate_webhook_url(url, allow_http=False)
        self.label = safe_url_label(url)
        self._timeout, self._verify, self._transport = timeout, ca_file or True, transport

    def body(self, msg: Message) -> dict:
        raise NotImplementedError

    async def send(self, msg: Message) -> None:
        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify, follow_redirects=False,
                                         transport=self._transport) as client:
                r = await client.post(self.url, json=self.body(msg), headers={"User-Agent": "LogUnify-Alerting/1"})
        except httpx.HTTPError as e:
            raise DeliveryError(f"{self.name} {self.label}: {type(e).__name__}", retryable=True) from None
        if 200 <= r.status_code < 300:
            return
        raise DeliveryError(f"{self.name} {self.label}: HTTP {r.status_code}",
                            retryable=r.status_code in (408, 425, 429) or r.status_code >= 500)


def _chat_text(msg: Message, limit: int = 2800) -> str:
    return clean(msg.text)[:limit]


class SlackNotifier(_ChatNotifier):
    name = "slack"

    def body(self, msg: Message) -> dict:
        icon = {"incident.overdue": ":rotating_light:", "incident.assigned": ":bust_in_silhouette:", "test": ":white_check_mark:"}.get(msg.kind, ":warning:")
        return {"text": f"{icon} *{clean(msg.subject)}*\n```{_chat_text(msg)}```"}


class TeamsNotifier(_ChatNotifier):
    """Adaptive Card in a `message` envelope (the Teams "Workflows" / Power Automate webhook shape). NOT verified against a live Teams tenant."""
    name = "teams"

    def body(self, msg: Message) -> dict:
        card = {"type": "AdaptiveCard", "version": "1.4", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "body": [{"type": "TextBlock", "text": clean(msg.subject), "weight": "Bolder", "wrap": True,
                          "color": "Attention" if msg.kind in ("incident.detected", "incident.overdue", "incident.storm") else "Default"},
                         {"type": "TextBlock", "text": _chat_text(msg), "wrap": True, "fontType": "Monospace"}]}
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}


def build_notifiers(s) -> list:
    """Channels from settings. Raises AlertConfigError on a half-configured channel (fail fast, not silently blind)."""
    out: list = []
    if s.alert_webhook_url:
        secret = s.alert_webhook_secret.get_secret_value() if s.alert_webhook_secret else None
        out.append(WebhookNotifier(s.alert_webhook_url, secret, s.alert_webhook_timeout_s,
                                   allow_http=s.alert_webhook_allow_http, ca_file=s.alert_webhook_ca_file or None))
        if not secret:
            log.warning("alert webhook is UNSIGNED: set LOGUNIFY_ALERT_WEBHOOK_SECRET so receivers can verify it")
    if getattr(s, "alert_slack_webhook_url", None) and s.alert_slack_webhook_url.get_secret_value():
        out.append(SlackNotifier(s.alert_slack_webhook_url.get_secret_value(), s.alert_webhook_timeout_s, ca_file=s.alert_webhook_ca_file or None))
    if getattr(s, "alert_teams_webhook_url", None) and s.alert_teams_webhook_url.get_secret_value():
        out.append(TeamsNotifier(s.alert_teams_webhook_url.get_secret_value(), s.alert_webhook_timeout_s, ca_file=s.alert_webhook_ca_file or None))
    if s.alert_smtp_host or s.alert_email_to:
        if not (s.alert_smtp_host and s.alert_email_to and s.alert_email_from):
            raise AlertConfigError("email alerts need alert_smtp_host, alert_email_from and alert_email_to together")
        out.append(EmailNotifier(s.alert_smtp_host, s.alert_smtp_port, s.alert_smtp_security, s.alert_smtp_user,
                                 s.alert_smtp_password.get_secret_value() if s.alert_smtp_password else None,
                                 s.alert_email_from, parse_emails(s.alert_email_to), s.alert_smtp_timeout_s,
                                 allow_plaintext=s.alert_smtp_allow_plaintext))
    return out
