import json

from .base import ParsedLog, ParseError

_ALIASES = {
    "host": "host.name", "hostname": "host.name", "src_ip": "source.ip", "source_ip": "source.ip",
    "srcip": "source.ip", "dst_ip": "destination.ip", "dest_ip": "destination.ip", "user": "user.name",
    "username": "user.name", "level": "log.level", "severity": "log.level", "service": "service.name",
    "app": "process.name", "pid": "process.pid", "action": "event.action",
    "status": "http.response.status_code", "method": "http.request.method", "url": "url.original",
    "path": "url.path", "port": "source.port",
}
_ECS_ROOTS = {"source", "destination", "host", "user", "event", "process", "http", "url",
              "network", "file", "log", "service"}
_TS_KEYS = ("@timestamp", "timestamp", "time", "ts", "datetime")
_MSG_KEYS = ("message", "msg", "log")


def _flatten(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(_flatten(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def parse_json(raw: str) -> ParsedLog:
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError(f"invalid JSON: {e.msg}") from e
    if not isinstance(obj, dict):
        raise ParseError("JSON log must be an object")
    flat = _flatten(obj)
    ts = next((flat.pop(k) for k in _TS_KEYS if k in flat), None)
    msg = next((str(flat.pop(k)) for k in _MSG_KEYS
                if k in flat and not isinstance(flat[k], (list, dict))), None)
    fields = {}
    for k, v in flat.items():
        if k in _ALIASES:
            fields[_ALIASES[k]] = v
        elif "." in k and k.split(".")[0] in _ECS_ROOTS:
            fields[k] = v
        else:
            fields[f"labels.{k}"] = v
    return ParsedLog("json", raw, None if ts is None else str(ts), msg, fields)
