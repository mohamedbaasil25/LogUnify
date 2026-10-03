"""Log search over the events the backend still holds (the in-memory ring buffer, `LOGUNIFY_RECENT_BUFFER`, restored after a restart when
`LOGUNIFY_STATE_PERSIST_LOGS` is on). It is NOT a history store: once an event leaves the ring it is only in your SIEM. Every
response says what window it covered (`coverage`), so an empty result is never mistaken for "it did not happen".

Query language (whitespace-separated terms, AND-ed; quote phrases):
    failed password            words: case-insensitive substring of the message / original line
    source.ip:203.0.113.9      field:value, exact (case-insensitive); `*` is a wildcard: user.name:adm*
    -user.name:root            a leading `-` negates a term
    host.name:db-01 "audit log"
Time range: `from` / `to` accept ISO-8601 or relative `-15m`, `-6h`, `-7d`.
"""
import re
import shlex
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase

from .ecs.validate import flatten

_REL = re.compile(r"^-(\d+)([smhdw])$")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
MAX_TERMS = 20


class SearchError(ValueError):
    pass


def parse_time(v: str | None, now: datetime | None = None) -> datetime | None:
    if not v:
        return None
    now = now or datetime.now(timezone.utc)
    if m := _REL.match(v.strip()):
        return now - timedelta(seconds=int(m.group(1)) * _UNIT[m.group(2)])
    try:
        t = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    except ValueError:
        raise SearchError(f"bad time {v!r}: use ISO-8601 (2026-10-01T09:00:00Z) or relative (-15m, -6h, -7d)") from None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def parse_query(q: str | None) -> list[tuple[bool, str | None, str]]:
    """-> [(negated, field or None, value)]"""
    if not q or not q.strip():
        return []
    try:
        parts = shlex.split(q)
    except ValueError:
        raise SearchError("unbalanced quote in query") from None
    if len(parts) > MAX_TERMS:
        raise SearchError(f"at most {MAX_TERMS} terms")
    out = []
    for t in parts:
        neg = t.startswith("-") and len(t) > 1
        if neg:
            t = t[1:]
        m = re.match(r"^([A-Za-z_@][\w.@-]*):(.+)$", t)
        out.append((neg, m.group(1), m.group(2)) if m else (neg, None, t))
    return out


def _match(flat: dict, text: str, term: tuple[bool, str | None, str]) -> bool:
    neg, fld, val = term
    val_l = val.lower()
    if fld is None:
        hit = val_l in text
    else:
        got = flat.get(fld)
        vals = got if isinstance(got, list) else [got]
        hit = any(v is not None and fnmatchcase(str(v).lower(), val_l) for v in vals)
    return hit != neg


def _ts(doc: dict) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(doc.get("@timestamp", "")).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def search_logs(events, *, q: str | None = None, t_from: str | None = None, t_to: str | None = None, fmt: str | None = None,
                min_score: float | None = None, limit: int = 100, offset: int = 0) -> dict:
    now = datetime.now(timezone.utc)
    lo, hi = parse_time(t_from, now), parse_time(t_to, now)
    if lo and hi and lo > hi:
        raise SearchError("`from` is after `to`")
    terms = parse_query(q)
    snapshot = list(events)                                   # one consistent copy; the ring keeps moving
    matched, oldest, newest = [], None, None
    for doc in reversed(snapshot):                            # newest first
        ts = _ts(doc)
        if ts is not None:
            oldest, newest = ts, newest or ts
        if ts is not None and ((lo and ts < lo) or (hi and ts > hi)):
            continue
        if fmt and (doc.get("logunify") or {}).get("source_format") != fmt:
            continue
        if min_score is not None and float((((doc.get("logunify") or {}).get("anomaly")) or {}).get("score") or 0) < min_score:
            continue
        if terms:
            flat = dict(flatten(doc))
            text = f"{doc.get('message', '')}\n{(doc.get('event') or {}).get('original', '')}".lower()
            if not all(_match(flat, text, t) for t in terms):
                continue
        matched.append(doc)
    return {"total": len(matched), "offset": offset, "items": matched[offset:offset + limit],
            "coverage": {"events_held": len(snapshot), "oldest": oldest.isoformat() if oldest else None,
                         "newest": newest.isoformat() if newest else None,
                         "note": "only events still held by this instance are searched (LOGUNIFY_RECENT_BUFFER); older history is in your SIEM"}}
