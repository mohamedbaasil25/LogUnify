"""Notification messages (what is sent) and webhook signing (how a receiver verifies it came from us)."""
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from . import cert_in
from .redact import clean

SCHEMA = "logunify.alert/v1"


@dataclass
class Message:
    kind: str                              # incident.detected | incident.reminder | incident.overdue | incident.storm | test
    alert_id: str | None
    subject: str
    text: str                              # plain-text body (email, chat)
    payload: dict                          # JSON body for webhooks
    attachment: tuple[str, bytes] | None = None     # (filename, JSON bytes) for email
    recipients: tuple[str, ...] | None = None       # email only: overrides the configured recipients (e.g. the assignee)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")


def alert_summary(alert, now: float) -> dict:
    a = cert_in.affected_asset(alert.doc)
    active = alert.status in ("open", "acknowledged")
    return {
        "id": alert.id, "status": alert.status, "created_at": _iso(alert.created_at), "due_at": _iso(alert.due_at),
        "seconds_remaining": int(alert.due_at - now) if active else None,
        "overdue": bool(active and alert.due_at <= now),
        "technique": alert.trigger["technique_id"], "technique_name": alert.trigger["technique_name"],
        "score": round(alert.trigger["score"], 4), "host": a["host"], "affected_ip": a["ip"], "remote_ip": a["remote_ip"],
        "occurrences": alert.occurrences, "notification": alert.notification["status"],
        "on_time": (alert.reported or {}).get("on_time"),
        "assignee": (alert.assignee or {}).get("to"),
    }


def build_message(kind: str, alert, report: dict, *, label: str = "", now: float) -> Message:
    subject = cert_in.subject_line(kind, report, label)
    remaining = cert_in.fmt_remaining(alert.due_at - now)
    det = report["additional_information"]["detection"]
    line = f"{subject} | score {det['anomaly_score']:.2f} | time left {remaining}"
    payload = {"schema": SCHEMA, "event": kind, "severity": "critical", "test": False, "text": line,
               "sent_at": _iso(now), "alert": alert_summary(alert, now), "cert_in_report": report}
    body = json.dumps(report, indent=2, ensure_ascii=False, default=str).encode("utf-8")
    return Message(kind, alert.id, subject, cert_in.render_text(report, kind, label), payload,
                   (f"cert-in-report-{alert.id}.json", body))


def build_assignment_message(alert, by: str, to: str, note: str, now: float, recipients: tuple[str, ...] | None = None) -> Message:
    s = alert_summary(alert, now)
    left = cert_in.fmt_remaining(alert.due_at - now) if alert.status in ("open", "acknowledged") else alert.status
    subject = clean(f"[ASSIGNED] {alert.id} {s['technique']} {s['technique_name']} -> {to}")
    text = (f"{alert.id} was assigned to {to} by {by}.\n\n{s['technique']} {s['technique_name']}, host {s['host'] or s['affected_ip'] or '?'}, "
            f"score {s['score']:.2f}, status {alert.status}, CERT-In time left: {left}.\n" + (f"\nNote from {by}: {note}\n" if note else ""))
    payload = {"schema": SCHEMA, "event": "incident.assigned", "severity": "info", "test": False, "text": subject, "sent_at": _iso(now),
               "alert": s, "assigned_by": by, "assigned_to": to}
    return Message("incident.assigned", alert.id, subject, text, payload, None, recipients)


def build_storm_message(alerts: list, now: float) -> Message:
    rows = sorted(alerts, key=lambda a: a.due_at)
    lines = [f"{len(rows)} critical alert(s) could not be notified individually because the hourly notification cap was reached.",
             "They are recorded and their CERT-In clocks are running. Review them now:", ""]
    for a in rows[:50]:
        s = alert_summary(a, now)
        lines.append(f"  {a.id}  {s['technique']} {s['technique_name']}  host {s['host'] or s['affected_ip'] or '?'}  "
                     f"score {s['score']:.2f}  due {cert_in.ts_pair(a.due_at)['ist']} IST  ({cert_in.fmt_remaining(a.due_at - now)} left)")
    text = "\n".join(lines) + "\n\nAPI: GET /api/v1/alerts?status=active (X-API-Key required)\n"
    subject = f"[ALERT STORM] {len(rows)} critical alert(s) pending: earliest CERT-In deadline {cert_in.ts_pair(rows[0].due_at)['ist']} IST"
    payload = {"schema": SCHEMA, "event": "incident.storm", "severity": "critical", "test": False, "text": subject,
               "sent_at": _iso(now), "alerts": [alert_summary(a, now) for a in rows[:50]]}
    return Message("incident.storm", None, clean(subject), text, payload)


def build_test_message(org: cert_in.OrgProfile, now: float) -> Message:
    text = ("TEST message from LogUnify alerting.\n\nThis verifies that this channel can deliver critical alerts. It is not an "
            "incident, no CERT-In clock is running, and nothing needs to be reported.\n")
    subject = "[TEST] LogUnify alerting channel check (not an incident)"
    payload = {"schema": SCHEMA, "event": "test", "severity": "test", "test": True, "text": subject, "sent_at": _iso(now),
               "organization": org.name or None}
    return Message("test", None, subject, text, payload)


# ---------------------------------------------------------------------------------------------- signing
def sign(secret: str, timestamp: int, body: bytes) -> str:
    """HMAC-SHA256 over "<timestamp>.<raw body>". The timestamp is part of the signed data so a captured request
    cannot be replayed later (receivers reject stale timestamps)."""
    return hmac.new(secret.encode("utf-8"), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, timestamp: str, body: bytes, signature: str, *, tolerance: int = 300,
                     now: float | None = None) -> bool:
    """Receiver-side check for headers X-LogUnify-Timestamp and X-LogUnify-Signature ("v1=<hex>")."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs((time.time() if now is None else now) - ts) > tolerance:
        return False
    expected = "v1=" + sign(secret, ts, body)
    return hmac.compare_digest(expected, signature or "")
