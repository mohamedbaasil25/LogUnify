import ipaddress
import json
import re
import zlib
from datetime import datetime, timezone
from typing import Any

from ..parsers.base import ParsedLog

ECS_VERSION = "8.11.0"
_SYS_TS = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d$")
_LEVEL_TO_SEV = {"emergency": 0, "alert": 1, "critical": 2, "fatal": 2, "error": 3, "err": 3,
                 "warning": 4, "warn": 4, "notice": 5, "info": 6, "debug": 7}


def to_iso(ts: Any, now: datetime | None = None) -> str:
    """Best-effort conversion to ISO-8601 UTC; falls back to ingest time."""
    now = now or datetime.now(timezone.utc)
    if ts is None:
        return now.isoformat()
    try:
        if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.replace(".", "", 1).isdigit()):
            v = float(ts)
            v = v / 1000 if v > 1e11 else v
            return datetime.fromtimestamp(v, timezone.utc).isoformat()
        s = str(ts).strip()
        if _SYS_TS.match(s):
            dt = datetime.strptime(f"{now.year} {' '.join(s.split())}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return now.isoformat()


def _nest(flat: dict[str, Any]) -> dict:
    root: dict = {}
    for k, v in flat.items():
        if v is None:
            continue
        node = root
        *path, leaf = k.split(".")
        for p in path:
            nxt = node.setdefault(p, {})
            if not isinstance(nxt, dict):      # scalar collides with object: keep scalar under _value
                nxt = node[p] = {"_value": nxt}
            node = nxt
        if isinstance(node.get(leaf), dict):
            node[leaf]["_value"] = v
        else:
            node[leaf] = v
    return root


def to_ecs(p: ParsedLog, now: datetime | None = None) -> dict:
    f = dict(p.fields)
    for k in ("source.ip", "destination.ip"):      # drop invalid IPs rather than break ES mappings later
        if k in f:
            try:
                ipaddress.ip_address(str(f[k]))
            except ValueError:
                f.pop(k)
    if isinstance(f.get("log.level"), str):
        f["log.level"] = f["log.level"].lower()
        if f.get("event.severity") is None:
            f["event.severity"] = _LEVEL_TO_SEV.get(f["log.level"])
    f.setdefault("event.kind", "event")
    f["event.original"] = p.original
    f["event.dataset"] = f"logunify.{p.format}"
    f["event.ingested"] = (now or datetime.now(timezone.utc)).isoformat()
    f["@timestamp"] = to_iso(p.timestamp, now)
    f["ecs.version"] = ECS_VERSION
    f["logunify.source_format"] = p.format
    if p.message is not None:
        f["message"] = p.message
    return _nest(f)


class StreamCompressor:
    """Shared-dictionary zlib stream, sync-flushed per document.

    Mimics batch compression on the wire (Kafka gzip/zstd): repeated ECS keys cost almost nothing after
    the first few documents, unlike compressing each tiny document in isolation.
    """

    def __init__(self, level: int = 6):
        self._c = zlib.compressobj(level)

    def size(self, doc: dict) -> int:
        data = json.dumps(doc, separators=(",", ":")).encode()
        return len(self._c.compress(data) + self._c.flush(zlib.Z_SYNC_FLUSH))
