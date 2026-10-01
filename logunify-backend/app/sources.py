"""Registry of configured log input feeds (what the dashboard's Source Configurator manages); persisted by app/state."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass
class LogSource:
    id: str
    name: str
    type: str                     # syslog | http | api
    format: str                   # auto | syslog | json | cef | text
    config: dict
    tags: list[str]
    created_at: str
    status: str                   # active (accepting data) | registered (config stored, no listener yet)
    token: str | None = None      # HTTP feeds only; in memory ONLY between creation and the response, never persisted
    received: int = 0
    error: str | None = None      # why a syslog source is still "registered" (e.g. port in use / no privilege)
    token_hash: str | None = None  # SHA-256 of the token: what is compared on ingest and what is saved to disk

    def check_token(self, supplied: str) -> bool:
        return self.token_hash is not None and hmac.compare_digest(self.token_hash, hash_token(supplied))

    def public(self, reveal_token: bool = False) -> dict:
        d = asdict(self)
        d.pop("token_hash")
        d["token"] = self.token if reveal_token else None
        d["has_token"] = self.token_hash is not None
        return d


def hash_token(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


class SourceRegistry:
    def __init__(self):
        self._items: dict[str, LogSource] = {}
        self._lock = threading.Lock()

    def add(self, name: str, type_: str, format_: str, config: dict, tags: list[str]) -> LogSource:
        with self._lock:
            if any(s.name.lower() == name.lower() for s in self._items.values()):
                raise ValueError(f"a source named '{name}' already exists")
            sid = "src-" + secrets.token_hex(4)
            token = secrets.token_urlsafe(24) if type_ == "http" else None
            src = LogSource(sid, name, type_, format_, config, tags, datetime.now(timezone.utc).isoformat(),
                            status="active" if type_ == "http" else "registered", token=token,
                            token_hash=hash_token(token) if token else None)
            self._items[sid] = src
            return src

    def get(self, sid: str) -> LogSource | None:
        return self._items.get(sid)

    def list(self) -> list[LogSource]:
        return sorted(self._items.values(), key=lambda s: s.created_at, reverse=True)

    def delete(self, sid: str) -> bool:
        with self._lock:
            return self._items.pop(sid, None) is not None

    # ---- persistence (app/state) ------------------------------------------------------------------------------
    def snapshot(self) -> list[dict]:
        """Persistable view of every source. The plaintext token is deliberately absent; status/error are recomputed on start."""
        with self._lock:
            items = list(self._items.values())
        return [{"id": s.id, "name": s.name, "type": s.type, "format": s.format, "config": s.config, "tags": s.tags,
                 "created_at": s.created_at, "received": s.received, "token_hash": s.token_hash} for s in items]

    def restore(self, rows: list[dict]) -> int:
        with self._lock:
            for r in rows:
                self._items[r["id"]] = LogSource(r["id"], r["name"], r["type"], r["format"], r["config"], r["tags"],
                                                 r["created_at"], "active" if r["type"] == "http" else "registered",
                                                 None, r.get("received", 0), None, r.get("token_hash"))
        return len(rows)
