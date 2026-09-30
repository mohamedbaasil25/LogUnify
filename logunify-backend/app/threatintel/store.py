"""Indicator-of-compromise (IOC) model, normalisation and in-memory index.

Lookups are O(1) dict hits (exact IP, domain with parent-domain walk, hash) plus a short CIDR list, so
matching every ingested log stays cheap. Indexes are rebuilt off to the side and swapped in atomically, so
readers on other threads never see a half-built index.
"""
import ipaddress
import re
from dataclasses import dataclass, field

_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}$")
_HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX = re.compile(r"^[0-9a-f]+$")
_CONF = {1: "High", 2: "Medium", 3: "Low", 4: "Low"}


@dataclass(frozen=True)
class IOC:
    type: str                 # ip | cidr | domain | md5 | sha1 | sha256
    value: str                # normalised
    feed: str
    category: str = ""
    threat_level: int | None = None       # MISP scale: 1 high .. 4 undefined
    event_id: str = ""
    description: str = ""
    tags: tuple[str, ...] = ()

    @property
    def confidence(self) -> str:
        return _CONF.get(self.threat_level or 4, "Low")


def normalize(kind: str, value: str) -> tuple[str, str] | None:
    """Return (canonical_type, canonical_value) or None if the value isn't a usable indicator."""
    v = (value or "").strip()
    if not v:
        return None
    if kind == "ip":
        if "/" in v:
            try:
                n = ipaddress.ip_network(v, strict=False)
            except ValueError:
                return None
            # refuse catch-all networks: one bad feed row must not flag the whole internet
            if n.prefixlen < (8 if n.version == 4 else 32):
                return None
            return ("cidr", str(n)) if n.num_addresses > 1 else ("ip", str(n.network_address))
        try:
            a = ipaddress.ip_address(v)
        except ValueError:
            return None
        if a.is_unspecified or a.is_loopback or a.is_multicast:
            return None
        return "ip", str(a)
    if kind == "domain":
        d = v.lower().rstrip(".")
        if _DOMAIN.match(d):
            try:
                ipaddress.ip_address(d)
                return None
            except ValueError:
                return "domain", d
        return None
    if kind == "hash":
        h = v.lower()
        t = _HASH_LEN.get(len(h))
        return (t, h) if t and _HEX.match(h) else None
    return None


@dataclass
class _Index:
    ip: dict[str, IOC] = field(default_factory=dict)
    domain: dict[str, IOC] = field(default_factory=dict)
    hash: dict[str, IOC] = field(default_factory=dict)
    nets: list[tuple[ipaddress._BaseNetwork, IOC]] = field(default_factory=list)


def _better(new: IOC, old: IOC | None) -> bool:
    """Keep the higher-severity indicator (lower MISP threat level number) on conflicts."""
    return old is None or (new.threat_level or 9) < (old.threat_level or 9)


class IOCStore:
    def __init__(self):
        self._feeds: dict[str, list[IOC]] = {}
        self._idx = _Index()

    def replace_feed(self, name: str, iocs: list[IOC]) -> None:
        feeds = {**self._feeds, name: list(iocs)}
        idx = _Index()
        for lst in feeds.values():
            for i in lst:
                if i.type == "ip":
                    if _better(i, idx.ip.get(i.value)):
                        idx.ip[i.value] = i
                elif i.type == "cidr":
                    idx.nets.append((ipaddress.ip_network(i.value), i))
                elif i.type == "domain":
                    if _better(i, idx.domain.get(i.value)):
                        idx.domain[i.value] = i
                elif _better(i, idx.hash.get(i.value)):
                    idx.hash[i.value] = i
        self._feeds, self._idx = feeds, idx          # atomic swap

    def feeds(self) -> dict[str, list[IOC]]:
        """name -> indicator list. The lists are replaced, never mutated, so identity tells a caller whether a feed changed."""
        return dict(self._feeds)

    def feed_iocs(self, name: str) -> list[IOC]:
        return self._feeds.get(name, [])

    def lookup_ip(self, ip: str) -> IOC | None:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        idx = self._idx
        if (hit := idx.ip.get(str(a))):
            return hit
        best = None
        for net, ioc in idx.nets:
            if net.version == a.version and a in net and _better(ioc, best):
                best = ioc
        return best

    def lookup_domain(self, domain: str) -> IOC | None:
        d, idx = domain.lower().rstrip("."), self._idx
        while d.count(".") >= 1:                      # sub.evil.com also matches a listed evil.com
            if (hit := idx.domain.get(d)):
                return hit
            d = d.split(".", 1)[1]
        return None

    def lookup_hash(self, h: str) -> IOC | None:
        return self._idx.hash.get(h.lower())

    def counts(self) -> dict:
        i = self._idx
        return {"ip": len(i.ip) + len(i.nets), "domain": len(i.domain),
                "hash": len(i.hash), "total": len(i.ip) + len(i.nets) + len(i.domain) + len(i.hash)}
