"""ThreatIntel: feed sync loop + per-log cross-referencing against the IOC store."""
import asyncio
import ipaddress
import logging
import re
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..config import Settings
from ..parsers.base import ParsedLog
from .misp import FeedError, MispClient
from .mock import mock_iocs
from .store import IOC, IOCStore, normalize

log = logging.getLogger("logunify.threatintel")

_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HASH_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
_DOMAIN_RE = re.compile(r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z][a-zA-Z0-9-]{1,23}(?![\w-])")
_MAX_TEXT_OBSERVABLES = 200        # a hostile 64 KB line must not turn into thousands of lookups

# structured ECS fields checked first: field -> kind
_FIELDS = {"source.ip": "ip", "destination.ip": "ip", "client.ip": "ip", "server.ip": "ip",
           "source.domain": "domain", "destination.domain": "domain", "url.domain": "domain",
           "dns.question.name": "domain", "host.hostname": "domain",
           "file.hash.md5": "hash", "file.hash.sha1": "hash", "file.hash.sha256": "hash"}

_ECS_TYPE = {"ip": "ipv4-addr", "cidr": "ipv4-addr", "domain": "domain-name", "md5": "file", "sha1": "file", "sha256": "file"}


@dataclass(frozen=True)
class Match:
    ioc: IOC
    observed: str
    field: str


class ThreatIntel:
    def __init__(self, settings: Settings):
        self.s = settings
        self.store = IOCStore()
        self.recent: deque[dict] = deque(maxlen=200)
        self.matches = 0
        self.status: dict[str, dict] = {}
        self._misp: MispClient | None = None
        if settings.misp_url and settings.misp_key:
            self._misp = MispClient(settings.misp_url, settings.misp_key.get_secret_value(),
                                    verify_ssl=settings.misp_verify_ssl, lookback=settings.misp_lookback)
            self.status["misp"] = self._blank("misp", "misp", settings.misp_url)
        elif settings.ti_mock_feed:
            iocs = mock_iocs()
            self.store.replace_feed("mock-misp", iocs)
            self.status["mock-misp"] = {**self._blank("mock-misp", "mock", None), "ioc_count": len(iocs),
                                        "last_sync": datetime.now(timezone.utc).isoformat()}

    @staticmethod
    def _blank(name, kind, url) -> dict:
        return {"name": name, "kind": kind, "url": url, "ioc_count": 0, "last_sync": None, "last_error": None}

    # ---- persistence (app/state) ----------------------------------------------
    def restore_feeds(self, feeds: dict[str, tuple[list[IOC], str]]) -> dict[str, int]:
        """Reload saved indicators: name -> (iocs, saved_at). Demo feeds are never restored, and a saved MISP feed only if MISP
        is still configured (otherwise nothing would ever refresh it)."""
        out = {}
        for name, (iocs, saved_at) in feeds.items():
            if name.startswith("mock") or (name == "misp" and self._misp is None) or not iocs:
                continue
            self.store.replace_feed(name, iocs)
            self.status[name] = {**self.status.get(name, self._blank(name, "manual" if name == "manual" else "misp", None)),
                                 "ioc_count": len(iocs), "last_sync": saved_at, "restored_from_disk": True}
            out[name] = len(iocs)
        return out

    # ---- feed management ----------------------------------------------
    async def sync(self) -> dict:
        """Refresh the MISP feed. On failure the previous indicators stay in force and the error is recorded."""
        if self._misp is None:
            return self.status
        st = self.status["misp"]
        try:
            iocs = await self._misp.fetch("misp")
            self.store.replace_feed("misp", iocs)
            st.update(ioc_count=len(iocs), last_sync=datetime.now(timezone.utc).isoformat(), last_error=None)
            log.info("MISP sync ok: %d indicators", len(iocs))
        except FeedError as e:
            st["last_error"] = str(e)
            log.warning("MISP sync failed: %s", e)
        return self.status

    async def run(self) -> None:
        if self._misp is None:
            return
        while True:
            await self.sync()
            await asyncio.sleep(self.s.misp_sync_minutes * 60)

    def import_manual(self, items: list[dict]) -> dict:
        """Add analyst-supplied indicators to the 'manual' feed. Returns accepted / rejected counts."""
        current = list(self.store.feed_iocs("manual"))
        added, rejected = 0, 0
        for it in items:
            kind = "hash" if it["type"] in ("md5", "sha1", "sha256") else it["type"]
            n = normalize(kind, it["value"])
            if not n or (kind == "hash" and n[0] != it["type"]):
                rejected += 1
                continue
            current.append(IOC(n[0], n[1], "manual", it.get("category", ""), it.get("threat_level"),
                               "", it.get("description", "")[:200], ()))
            added += 1
        self.store.replace_feed("manual", current)
        self.status["manual"] = {**self._blank("manual", "manual", None), "ioc_count": len(current),
                                 "last_sync": datetime.now(timezone.utc).isoformat()}
        return {"added": added, "rejected": rejected}

    def lookup(self, value: str) -> IOC | None:
        v = value.strip()
        try:
            ipaddress.ip_address(v)
            return self.store.lookup_ip(v)
        except ValueError:
            pass
        if (n := normalize("hash", v)):
            return self.store.lookup_hash(n[1])
        if (n := normalize("domain", v)):
            return self.store.lookup_domain(n[1])
        return None

    # ---- log cross-referencing ----------------------------------------
    def _observables(self, p: ParsedLog):
        seen: set[tuple[str, str]] = set()
        for fld, kind in _FIELDS.items():
            v = p.fields.get(fld)
            if isinstance(v, str) and (kind, v) not in seen:
                seen.add((kind, v))
                yield kind, v, fld
        url = p.fields.get("url.original")
        if isinstance(url, str) and (host := urlparse(url if "//" in url else "//" + url).hostname):
            seen.add(("domain", host))
            yield "domain", host, "url.original"
        text = (p.message or p.original)[:65536]
        n = 0
        for rx, kind in ((_IP_RE, "ip"), (_HASH_RE, "hash"), (_DOMAIN_RE, "domain")):
            for m in rx.finditer(text):
                if n >= _MAX_TEXT_OBSERVABLES:
                    return
                if (kind, m.group(0)) not in seen:
                    seen.add((kind, m.group(0)))
                    n += 1
                    yield kind, m.group(0), "message"

    def check(self, p: ParsedLog) -> list[Match]:
        out: list[Match] = []
        for kind, val, fld in self._observables(p):
            hit = (self.store.lookup_ip(val) if kind == "ip" else
                   self.store.lookup_domain(val) if kind == "domain" else self.store.lookup_hash(val))
            if hit:
                out.append(Match(hit, val, fld))
        return out

    def enrich(self, p: ParsedLog) -> list[Match]:
        """Cross-reference a parsed log; on a hit, add ECS threat.indicator.* fields and mark it as an alert."""
        matches = self.check(p)
        if not matches:
            return matches
        top = min(matches, key=lambda m: m.ioc.threat_level or 9)      # highest-severity indicator wins
        i, f = top.ioc, p.fields
        f["threat.indicator.type"] = "ipv6-addr" if ":" in top.observed else _ECS_TYPE[i.type]
        if i.type in ("ip", "cidr"):
            f["threat.indicator.ip"] = top.observed
        elif i.type == "domain":
            f["threat.indicator.url.domain"] = i.value
        else:
            f[f"threat.indicator.file.hash.{i.type}"] = i.value
        f["threat.indicator.provider"] = i.feed
        f["threat.indicator.confidence"] = i.confidence
        f["threat.indicator.description"] = i.description or i.category
        if i.event_id and self.s.misp_url and i.feed == "misp":
            f["threat.indicator.reference"] = f"{self.s.misp_url.rstrip('/')}/events/view/{i.event_id}"
        f["event.kind"] = "alert"
        f["logunify.ti.matched"] = True
        f["logunify.ti.match_count"] = len(matches)
        f["logunify.ti.matched_field"] = top.field
        f["logunify.ti.matches"] = [{"type": m.ioc.type, "value": m.observed, "feed": m.ioc.feed,
                                     "field": m.field} for m in matches[:5]]
        self.matches += 1
        return matches
