"""Normalise Windows Security (4624, 4625, 4688), PostgreSQL and MySQL log records to ECS.

Input is the raw line received on the socket. The returned dict always carries `event.original` (the untouched line), `@timestamp` (UTC ISO 8601),
`host.name`, and, where the source provides them, `user.name` and `source.ip`. Anything unrecognised returns None (the caller dead-letters it, never drops it).
"""
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

SOURCE_TZ = ZoneInfo(os.getenv("LOGUNIFY_SOURCE_TZ", "UTC"))     # zone of timestamps that carry no offset (NXLog EventTime, PostgreSQL %m, ...)

_PG = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?) (?P<tz>[A-Z]{2,5}) \[(?P<pid>\d+)\] (?:(?P<user>[^@\s]*)@(?P<db>\S*) )?(?P<level>[A-Z]+\d?):  (?P<msg>.*)$")
_MY = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)) (?P<thread>\d+) \[(?P<level>[A-Za-z]+)\] \[(?P<code>MY-\d+)\] \[(?P<sub>\w+)\] (?P<msg>.*)$")
_MY_DENIED = re.compile(r"Access denied for user '(?P<user>[^']*)'@'(?P<host>[^']*)'")
_PG_AUTH_FAIL = re.compile(r"authentication failed|no pg_hba\.conf entry|role \".*\" does not exist")


def _utc(value, default_tz=None) -> str | None:
    """Any of: ISO 8601 (with or without offset), 'YYYY-MM-DD HH:MM:SS[.ffffff]', epoch seconds -> UTC ISO string. None when unparsable."""
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=default_tz or SOURCE_TZ)
        return dt.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def _ip(value) -> str | None:
    """Valid IP only; '-', '::1' placeholders and junk are dropped. Loopback is kept (it is a real value for local logons)."""
    if not value or value == "-":
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _base(raw: str, ts: str | None, host: str | None) -> dict:
    ev = {"event.original": raw, "@timestamp": ts or datetime.now(timezone.utc).isoformat(), "ecs.version": "8.11.0", "event.kind": "event"}
    if ts is None:
        ev["labels.timestamp_source"] = "ingest_time"          # event time missing/unparsable: say so instead of passing receive time off as event time
    if host:
        ev["host.name"] = str(host).lower()
    return ev


def _windows(raw: str, d: dict) -> dict | None:
    try:
        eid = int(d.get("EventID"))
    except (TypeError, ValueError):
        return None
    if eid not in (4624, 4625, 4688):
        return None
    ev = _base(raw, _utc(d.get("EventTime") or d.get("TimeCreated")), d.get("Hostname") or d.get("Computer"))
    ev.update({"event.module": "windows_security", "event.dataset": "windows.security", "event.code": str(eid), "event.provider": "Microsoft-Windows-Security-Auditing"})
    if eid in (4624, 4625):
        ok = eid == 4624
        ev.update({"event.category": ["authentication"], "event.type": ["start"] + ([] if ok else ["denied"]),
                   "event.action": "logon-success" if ok else "logon-failed", "event.outcome": "success" if ok else "failure"})
        user = d.get("TargetUserName")
        if d.get("LogonType") is not None:
            ev["labels.logon_type"] = str(d["LogonType"])
        if (ip := _ip(d.get("IpAddress"))):
            ev["source.ip"] = ip
        if d.get("WorkstationName"):
            ev["source.domain"] = str(d["WorkstationName"])
    else:                                                       # 4688 process creation: the actor is the SubjectUserName
        user = d.get("SubjectUserName")
        ev.update({"event.category": ["process"], "event.type": ["start"], "event.action": "process-created"})
        if d.get("NewProcessName"):
            ev["process.executable"] = d["NewProcessName"]
            ev["process.name"] = re.split(r"[\\/]", d["NewProcessName"])[-1]
        if d.get("CommandLine"):
            ev["process.command_line"] = d["CommandLine"]
    if user:
        ev["user.name"] = str(user)
    return ev


def _postgres(raw: str) -> dict | None:
    m = _PG.match(raw)
    if not m:
        return None
    ev = _base(raw, _utc(m["ts"]), None)                         # the zone abbreviation is ignored: LOGUNIFY_SOURCE_TZ must match the server's log_timezone
    ev.update({"event.module": "postgresql", "event.dataset": "postgresql.log", "event.category": ["database"], "event.type": ["info"],
               "log.level": m["level"].lower(), "process.pid": int(m["pid"]), "message": m["msg"]})
    if m["user"]:
        ev["user.name"] = m["user"]
    if m["db"]:
        ev["labels.db_name"] = m["db"]
    if _PG_AUTH_FAIL.search(m["msg"]):
        ev.update({"event.category": ["authentication", "database"], "event.type": ["start", "denied"], "event.action": "authentication-failed", "event.outcome": "failure"})
    return ev


def _mysql(raw: str) -> dict | None:
    m = _MY.match(raw)
    if not m:
        return None
    ev = _base(raw, _utc(m["ts"]), None)
    ev.update({"event.module": "mysql", "event.dataset": "mysql.error", "event.category": ["database"], "event.type": ["info"], "event.code": m["code"],
               "log.level": m["level"].lower(), "message": m["msg"]})
    if (d := _MY_DENIED.search(m["msg"])):
        ev.update({"event.category": ["authentication", "database"], "event.type": ["start", "denied"], "event.action": "access-denied", "event.outcome": "failure",
                   "user.name": d["user"]})
        if (ip := _ip(d["host"])):
            ev["source.ip"] = ip
    return ev


def to_ecs(raw: str, default_host: str | None = None) -> dict | None:
    """Raw line -> ECS dict, or None when no parser matches. `default_host` fills host.name for sources that do not carry it (DB logs)."""
    raw = raw.rstrip("\r\n")
    ev = None
    if raw.startswith("{"):
        try:
            d = json.loads(raw)
        except ValueError:
            d = None
        if isinstance(d, dict):
            ev = _windows(raw, d)
    else:
        ev = _postgres(raw) or _mysql(raw)
    if ev is not None and "host.name" not in ev and default_host:
        ev["host.name"] = default_host.lower()
    return ev
