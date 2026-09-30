import re

from .base import ParsedLog, ParseError

FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
              "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2",
              "local3", "local4", "local5", "local6", "local7"]
SEVERITIES = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]

_5424 = re.compile(r"^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(?:\[.*?\]|-)?\s*(.*)$", re.S)
_3164 = re.compile(r"^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d)\s+(\S+)\s+([^\s:\[]+)(?:\[(\d+)\])?:?\s*(.*)$", re.S)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER = re.compile(r"(?:for(?: invalid user)?|user)\s+([\w.\-]+)", re.I)


def _pri(pri: str) -> dict:
    n = int(pri)
    fac, sev = n >> 3, n & 7
    if fac > 23:
        raise ParseError(f"invalid syslog PRI {n}")
    return {"log.syslog.facility.code": fac, "log.syslog.facility.name": FACILITIES[fac],
            "log.syslog.priority": n, "log.level": SEVERITIES[sev], "event.severity": sev}


def _enrich(message: str, f: dict) -> None:
    if (m := _IP.search(message)):
        f["source.ip"] = m.group(0)
    if (m := _USER.search(message)):
        f["user.name"] = m.group(1)
    low = message.lower()
    if "failed password" in low or "authentication failure" in low:
        f.update({"event.category": "authentication", "event.outcome": "failure", "event.action": "logon-failed"})
    elif "accepted password" in low or "accepted publickey" in low:
        f.update({"event.category": "authentication", "event.outcome": "success", "event.action": "logon"})


def parse_syslog(raw: str) -> ParsedLog:
    raw = raw.strip()
    if (m := _5424.match(raw)):
        pri, _ver, ts, host, app, procid, msgid, msg = m.groups()
        f = _pri(pri)
        f["host.name"] = None if host == "-" else host
        f["process.name"] = None if app == "-" else app
        if procid.isdigit():
            f["process.pid"] = int(procid)
        if msgid != "-":
            f["event.code"] = msgid
        _enrich(msg, f)
        return ParsedLog("syslog", raw, None if ts == "-" else ts, msg, f)
    if (m := _3164.match(raw)):
        pri, ts, host, app, pid, msg = m.groups()
        f = _pri(pri)
        f["host.name"], f["process.name"] = host, app
        if pid:
            f["process.pid"] = int(pid)
        _enrich(msg, f)
        return ParsedLog("syslog", raw, ts, msg, f)
    raise ParseError("not RFC3164/RFC5424 syslog")
