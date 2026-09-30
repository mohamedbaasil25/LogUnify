"""MISP REST client: pulls to_ids attributes (IPs, domains/URLs, file hashes) into IOCs.

Uses POST /attributes/restSearch with the API key in the Authorization header (MISP's documented auth).
The key is never logged or returned by any endpoint. Not exercised against a live MISP in this repo's tests;
see tests/test_threatintel.py for the mocked-transport coverage.
"""
from urllib.parse import urlparse

import httpx

from .store import IOC, normalize

# MISP attribute type -> our kind. Composite types ("domain|ip", "filename|sha256", "ip-dst|port") are split.
_KIND = {"ip-src": "ip", "ip-dst": "ip", "ip": "ip", "domain": "domain", "hostname": "domain",
         "md5": "hash", "sha1": "hash", "sha256": "hash", "url": "url", "uri": "url"}
QUERY_TYPES = ["ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain", "hostname", "domain|ip", "url",
               "md5", "sha1", "sha256", "filename|md5", "filename|sha1", "filename|sha256"]


class FeedError(RuntimeError):
    pass


def _parts(mtype: str, value: str) -> list[tuple[str, str]]:
    """Expand one MISP attribute into (kind, value) candidates."""
    if "|" in mtype:
        types, vals = mtype.split("|"), value.split("|")
        if len(types) != len(vals):
            return []
        return [(k, v) for t, v in zip(types, vals) if (k := _KIND.get(t))]
    if (k := _KIND.get(mtype)):
        return [(k, value)]
    return []


def attribute_to_iocs(attr: dict, feed: str) -> list[IOC]:
    ev = attr.get("Event") or {}
    try:
        level = int(ev.get("threat_level_id")) if ev.get("threat_level_id") else None
    except (TypeError, ValueError):
        level = None
    tags = tuple(t.get("name", "") for t in (attr.get("Tag") or [])[:8] if t.get("name"))
    out = []
    for kind, val in _parts(str(attr.get("type", "")), str(attr.get("value", ""))):
        if kind == "url":                       # index the host of a malicious URL
            host = urlparse(val if "//" in val else "//" + val).hostname or ""
            kind, val = ("ip", host) if host.replace(".", "").isdigit() else ("domain", host)
        n = normalize(kind, val)
        if n:
            out.append(IOC(n[0], n[1], feed, str(attr.get("category", "")), level, str(attr.get("event_id", "")),
                           str(ev.get("info", ""))[:200], tags))
    return out


class MispClient:
    def __init__(self, url: str, api_key: str, *, verify_ssl: bool = True, lookback: str = "7d",
                 page_size: int = 2000, max_pages: int = 20, transport: httpx.AsyncBaseTransport | None = None):
        self.base = url.rstrip("/")
        self._key = api_key
        self.lookback, self.page_size, self.max_pages = lookback, page_size, max_pages
        self._client_kw = {"verify": verify_ssl, "timeout": 30.0, "transport": transport}

    async def fetch(self, feed_name: str = "misp") -> list[IOC]:
        headers = {"Authorization": self._key, "Accept": "application/json", "Content-Type": "application/json"}
        iocs: list[IOC] = []
        async with httpx.AsyncClient(headers=headers, **self._client_kw) as c:
            for page in range(1, self.max_pages + 1):
                body = {"returnFormat": "json", "type": QUERY_TYPES, "to_ids": 1, "last": self.lookback,
                        "limit": self.page_size, "page": page, "includeContext": 1, "deleted": 0}
                try:
                    r = await c.post(f"{self.base}/attributes/restSearch", json=body)
                except httpx.HTTPError as e:
                    raise FeedError(f"MISP unreachable: {type(e).__name__}") from None
                if r.status_code in (401, 403):
                    raise FeedError("MISP rejected the API key (HTTP %d)" % r.status_code)
                if r.status_code != 200:
                    raise FeedError(f"MISP returned HTTP {r.status_code}")
                try:
                    attrs = r.json()["response"]["Attribute"]
                except (ValueError, KeyError, TypeError):
                    raise FeedError("unexpected MISP response format") from None
                for a in attrs:
                    iocs.extend(attribute_to_iocs(a, feed_name))
                if len(attrs) < self.page_size:
                    break
        return iocs
