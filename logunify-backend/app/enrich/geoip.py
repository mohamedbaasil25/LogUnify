"""MOCK GeoIP lookup (no database): deterministic demo values so the UI can render geo badges.

Replace `lookup` with a MaxMind GeoLite2 reader for real data. Internal addresses are labelled 'Internal'.
"""
import hashlib
import ipaddress

_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                "169.254.0.0/16")]
_KNOWN = {"185.220.101.4": ("DE", "Germany"), "45.155.205.233": ("RU", "Russia"),
          "91.240.118.172": ("UA", "Ukraine"), "203.0.113.77": ("NL", "Netherlands"),
          "198.51.100.23": ("CN", "China"), "8.8.8.8": ("US", "United States")}
_POOL = [("US", "United States"), ("DE", "Germany"), ("NL", "Netherlands"), ("FR", "France"),
         ("BR", "Brazil"), ("IN", "India"), ("SG", "Singapore"), ("CN", "China"), ("RU", "Russia")]


def lookup(ip) -> dict:
    """Flat ECS fields for source.geo.*, or {} for an unparseable address."""
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return {}
    if any(a in n for n in _INTERNAL if n.version == a.version) or a.is_loopback:
        iso, name = "--", "Internal"
    else:
        iso, name = _KNOWN.get(str(a)) or _POOL[hashlib.sha256(str(a).encode()).digest()[0] % len(_POOL)]
    return {"source.geo.country_iso_code": iso, "source.geo.country_name": name, "logunify.geoip": "mock"}
