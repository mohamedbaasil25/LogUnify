import re

from .base import ParsedLog, ParseError

_EXT = re.compile(r"(\w+)=(.*?)(?=\s+\w+=|$)", re.S)
_MAP = {
    "src": "source.ip", "dst": "destination.ip", "spt": "source.port", "dpt": "destination.port",
    "suser": "user.name", "duser": "user.target.name", "shost": "source.domain", "dhost": "destination.domain",
    "proto": "network.transport", "act": "event.action", "outcome": "event.outcome", "msg": "message",
    "request": "url.original", "requestMethod": "http.request.method", "fname": "file.name",
    "deviceHostName": "host.name", "in": "source.bytes", "out": "destination.bytes", "app": "network.protocol",
}
_INT = {"source.port", "destination.port", "source.bytes", "destination.bytes"}
_NAMED_SEV = {"low": 3, "medium": 6, "high": 8, "very-high": 10, "unknown": 0}


def _split_header(s: str) -> list[str]:
    """Split on unescaped '|' into at most 8 parts (7 header fields + extension)."""
    parts, cur, esc = [], [], False
    for ch in s:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == "|" and len(parts) < 7:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def parse_cef(raw: str) -> ParsedLog:
    raw = raw.strip()
    idx = raw.find("CEF:")
    if idx < 0:
        raise ParseError("no CEF header")
    parts = _split_header(raw[idx + 4:])
    if len(parts) != 8:
        raise ParseError("CEF header needs 7 pipe-delimited fields")
    ver, vendor, product, dev_ver, sig, name, sev, ext = parts
    sev_l = sev.strip().lower()
    if sev_l in _NAMED_SEV:
        severity = _NAMED_SEV[sev_l]
    elif sev_l.isdigit() and int(sev_l) <= 10:
        severity = int(sev_l)
    else:
        raise ParseError("bad CEF severity")
    f: dict = {"observer.vendor": vendor, "observer.product": product, "observer.version": dev_ver,
               "event.code": sig, "event.reason": name, "event.severity": severity}
    for k, v in _EXT.findall(ext):
        v = v.strip()
        key = _MAP.get(k)
        if not key:
            f[f"labels.{k}"] = v
        else:
            f[key] = int(v) if key in _INT and v.isdigit() else v
    msg = f.pop("message", None) or name
    ts = f.pop("labels.rt", None) or f.pop("labels.start", None)
    return ParsedLog("cef", raw, ts, msg, f)
