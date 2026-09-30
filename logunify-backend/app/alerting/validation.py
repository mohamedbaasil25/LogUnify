"""Fail-fast parsing/validation of alerting settings. A silently mis-parsed recipient or threshold means a critical
alert that never arrives, so misconfiguration raises at start-up instead of being tolerated."""
import ipaddress
import re
from urllib.parse import urlsplit

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
DEADLINE_MINUTES = 6 * 60


class AlertConfigError(ValueError):
    pass


def _items(csv: str) -> list[str]:
    return [x.strip() for x in re.split(r"[,;]", csv or "") if x.strip()]


def parse_techniques(csv: str) -> frozenset[str]:
    out = set()
    for t in _items(csv):
        t = t.upper()
        if not TECHNIQUE_RE.match(t):
            raise AlertConfigError(
                f"invalid MITRE technique id {t!r} in alert_critical_techniques (expected e.g. T1070 or T1070.001)")
        out.add(t)
    if not out:
        raise AlertConfigError("alert_critical_techniques must list at least one technique")
    return frozenset(out)


def parse_minutes(csv: str) -> tuple[int, ...]:
    vals = set()
    for x in _items(csv):
        if not x.isdigit() or not 0 < int(x) < DEADLINE_MINUTES:
            raise AlertConfigError(
                f"invalid reminder {x!r}: minutes before the 6-hour deadline must be 1..{DEADLINE_MINUTES - 1}")
        vals.add(int(x))
    return tuple(sorted(vals, reverse=True))


def parse_emails(csv: str) -> tuple[str, ...]:
    out = []
    for e in _items(csv):
        if not EMAIL_RE.match(e):
            raise AlertConfigError(f"invalid email address {e!r}")
        out.append(e)
    return tuple(out)


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_webhook_url(url: str, allow_http: bool = False) -> str:
    u = urlsplit(url)
    if u.scheme not in ("https", "http") or not u.hostname:
        raise AlertConfigError("alert_webhook_url must be an absolute http(s) URL")
    if u.username or u.password:
        raise AlertConfigError(
            "alert_webhook_url must not embed credentials (they leak into logs); use the signing secret")
    if u.scheme == "http" and not (allow_http or _is_loopback(u.hostname)):
        raise AlertConfigError(
            "alert_webhook_url must be https (plain http only for loopback, or set alert_webhook_allow_http)")
    return url


def safe_url_label(url: str) -> str:
    """scheme://host[:port] only: webhook paths/queries usually ARE the credential (e.g. chat incoming webhooks)."""
    u = urlsplit(url)
    return f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")
