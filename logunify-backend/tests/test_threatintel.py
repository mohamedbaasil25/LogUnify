import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.parsers.detect import parse_auto
from app.threatintel.misp import FeedError, MispClient, attribute_to_iocs
from app.threatintel.mock import MOCK_DOMAINS, MOCK_HASHES, MOCK_IPS
from app.threatintel.service import ThreatIntel
from app.threatintel.store import IOC, IOCStore, normalize


def ti(**kw) -> ThreatIntel:
    return ThreatIntel(Settings(**kw))


def test_normalize_rejects_junk_and_catch_alls():
    assert normalize("ip", "0.0.0.0/0") is None and normalize("ip", "10.0.0.0/4") is None
    assert normalize("ip", "127.0.0.1") is None and normalize("ip", "0.0.0.0") is None
    assert normalize("ip", "8.8.8.0/24") == ("cidr", "8.8.8.0/24")
    assert normalize("domain", "Evil.Example.COM.") == ("domain", "evil.example.com")
    assert normalize("domain", "1.2.3.4") is None and normalize("domain", "localhost") is None
    assert normalize("hash", "A" * 64)[0] == "sha256" and normalize("hash", "g" * 32) is None
    assert normalize("hash", "abc") is None


def test_store_lookups_and_priority():
    s = IOCStore()
    s.replace_feed("a", [IOC("domain", "evil.com", "a", threat_level=3), IOC("cidr", "203.0.113.0/24", "a", threat_level=2)])
    s.replace_feed("b", [IOC("domain", "evil.com", "b", threat_level=1)])
    assert s.lookup_domain("cdn.sub.evil.com").feed == "b"            # parent-domain match, higher severity wins
    assert s.lookup_domain("notevil.com") is None and s.lookup_domain("com") is None
    assert s.lookup_ip("203.0.113.9").type == "cidr" and s.lookup_ip("203.0.114.9") is None
    assert s.lookup_ip("garbage") is None


def test_enrich_ip_domain_hash_in_message_and_fields():
    t = ti()
    p = parse_auto(f"Outbound connection from 10.0.0.5 to {MOCK_IPS[0]} port 443 established")
    assert t.enrich(p) and p.fields["threat.indicator.ip"] == MOCK_IPS[0]
    assert p.fields["event.kind"] == "alert" and p.fields["threat.indicator.provider"] == "mock-misp"
    assert p.fields["threat.indicator.confidence"] == "High" and p.fields["logunify.ti.matched_field"] == "message"

    p = parse_auto(f"DNS query for cdn.{MOCK_DOMAINS[1]} from 10.0.0.5")
    assert t.enrich(p) and p.fields["threat.indicator.type"] == "domain-name"

    p = parse_auto(f"Process created image hash {MOCK_HASHES[0].upper()}")
    assert t.enrich(p) and p.fields["threat.indicator.file.hash.sha256"] == MOCK_HASHES[0]

    p = parse_auto(json.dumps({"message": "x", "src_ip": MOCK_IPS[1]}))          # structured field, not text
    assert t.enrich(p) and p.fields["logunify.ti.matched_field"] == "source.ip"

    clean = parse_auto("Cache refresh completed on web-01 from 8.8.8.8 in 55 ms")
    assert not t.enrich(clean) and "threat.indicator.type" not in clean.fields


def test_text_scan_is_bounded():
    t = ti()
    p = parse_auto(" ".join(f"h{i}.example.org" for i in range(5000)))
    assert t.check(p) == []                                                       # returns, doesn't blow up


def test_manual_import_and_lookup():
    t = ti(ti_mock_feed=False)
    r = t.import_manual([{"type": "ip", "value": "9.9.9.9", "threat_level": 1}, {"type": "ip", "value": "0.0.0.0/0"},
                         {"type": "sha256", "value": "abc"}, {"type": "md5", "value": "d" * 32}])
    assert r == {"added": 2, "rejected": 2}
    assert t.lookup("9.9.9.9").feed == "manual" and t.lookup("d" * 32).type == "md5" and t.lookup("1.1.1.1") is None


# ------------------------------------------------------------------ MISP client (mocked transport)
def misp_attr(**kw):
    return {"type": "ip-dst", "value": "198.51.100.50", "category": "Network activity", "event_id": "42", "to_ids": True,
            "Event": {"threat_level_id": "1", "info": "APT test"}, "Tag": [{"name": "tlp:red"}], **kw}


def test_attribute_parsing_composites():
    assert attribute_to_iocs(misp_attr(type="ip-dst|port", value="198.51.100.50|443"), "m")[0].value == "198.51.100.50"
    d = attribute_to_iocs(misp_attr(type="domain|ip", value="bad.example.net|198.51.100.51"), "m")
    assert {(i.type, i.value) for i in d} == {("domain", "bad.example.net"), ("ip", "198.51.100.51")}
    h = attribute_to_iocs(misp_attr(type="filename|sha256", value="a.exe|" + "b" * 64), "m")
    assert [i.type for i in h] == ["sha256"]
    u = attribute_to_iocs(misp_attr(type="url", value="http://evil.example.net/x.php"), "m")
    assert u[0].type == "domain" and u[0].value == "evil.example.net"
    assert attribute_to_iocs(misp_attr(type="comment", value="hi"), "m") == []
    assert attribute_to_iocs(misp_attr(), "m")[0].confidence == "High"


def test_misp_sync_sends_key_and_indexes(monkeypatch):
    seen = {}

    def handler(req: httpx.Request):
        seen["auth"], seen["url"], seen["body"] = req.headers.get("authorization"), str(req.url), json.loads(req.content)
        return httpx.Response(200, json={"response": {"Attribute": [misp_attr(), misp_attr(type="domain", value="bad.example.net")]}})

    t = ti(misp_url="https://misp.test", misp_key="SECRET-KEY")
    t._misp = MispClient("https://misp.test", "SECRET-KEY", transport=httpx.MockTransport(handler))
    asyncio.run(t.sync())
    assert seen["auth"] == "SECRET-KEY" and seen["url"] == "https://misp.test/attributes/restSearch"
    assert seen["body"]["to_ids"] == 1 and seen["body"]["last"] == "7d"
    assert t.lookup("198.51.100.50").feed == "misp" and t.lookup("x.bad.example.net")
    assert t.status["misp"]["ioc_count"] == 2 and t.status["misp"]["last_error"] is None
    assert "SECRET-KEY" not in json.dumps(t.status)
    p = parse_auto("connect to 198.51.100.50 port 80")
    t.enrich(p)
    assert p.fields["threat.indicator.reference"] == "https://misp.test/events/view/42"


def test_misp_failure_keeps_previous_indicators():
    good = httpx.MockTransport(lambda r: httpx.Response(200, json={"response": {"Attribute": [misp_attr()]}}))
    t = ti(misp_url="https://misp.test", misp_key="k")
    t._misp = MispClient("https://misp.test", "k", transport=good)
    asyncio.run(t.sync())
    for status in (403, 500):
        t._misp = MispClient("https://misp.test", "k", transport=httpx.MockTransport(lambda r, s=status: httpx.Response(s)))
        asyncio.run(t.sync())
        assert t.status["misp"]["last_error"] and t.lookup("198.51.100.50") is not None   # stale data beats no data


def test_misp_pagination_and_bad_payload():
    pages = []

    def handler(req):
        page = json.loads(req.content)["page"]
        pages.append(page)
        n = 2 if page == 1 else 1
        return httpx.Response(200, json={"response": {"Attribute": [misp_attr(value=f"198.51.100.{page * 10 + i}") for i in range(n)]}})

    c = MispClient("https://m", "k", page_size=2, transport=httpx.MockTransport(handler))
    assert len(asyncio.run(c.fetch())) == 3 and pages == [1, 2]
    bad = MispClient("https://m", "k", transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"nope": 1})))
    with pytest.raises(FeedError):
        asyncio.run(bad.fetch())


# ------------------------------------------------------------------ API + pipeline
def test_api_end_to_end():
    with TestClient(create_app(Settings(mock_enabled=False))) as c:
        r = c.post("/api/v1/parse", json={"log": f"DNS query for {MOCK_DOMAINS[0]} from 10.0.0.9"}).json()
        assert r["ecs"]["threat"]["indicator"]["provider"] == "mock-misp" and r["ecs"]["event"]["kind"] == "alert"
        st = c.get("/api/v1/threatintel/status").json()
        assert st["using_mock_feed"] and st["indicators"]["total"] == 9 and st["matches"] == 1
        m = c.get("/api/v1/metrics").json()["threat_intel"]
        assert m["matches"] == 1 and m["iocs"] == 9
        assert c.get("/api/v1/threatintel/matches").json()["items"][0]["threat"]["indicator"]["type"] == "domain-name"
        assert c.get(f"/api/v1/threatintel/lookup?value={MOCK_IPS[0]}").json()["malicious"] is True
        assert c.get("/api/v1/threatintel/lookup?value=1.1.1.1").json()["malicious"] is False
        imp = c.post("/api/v1/threatintel/iocs", json={"iocs": [{"type": "ip", "value": "9.9.9.9"}, {"type": "ip", "value": "0.0.0.0/0"}]})
        assert imp.json() == {"added": 1, "rejected": 1}
        assert c.get("/api/v1/threatintel/lookup?value=9.9.9.9").json()["indicator"]["feed"] == "manual"
        assert c.post("/api/v1/threatintel/iocs", json={"iocs": [{"type": "url", "value": "x"}]}).status_code == 422
        assert c.post("/api/v1/threatintel/sync").status_code == 200


def test_disabled():
    with TestClient(create_app(Settings(mock_enabled=False, ti_enabled=False))) as c:
        assert c.get("/api/v1/threatintel/status").status_code == 503
        assert c.get("/api/v1/metrics").json()["threat_intel"]["enabled"] is False
        assert c.post("/api/v1/parse", json={"log": "hello 193.32.162.157"}).json()["ok"] is True
