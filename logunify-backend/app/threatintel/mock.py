"""Demo indicators used when no MISP instance is configured. Clearly labelled MOCK in status output.

All values are fictional: reserved example domains, documentation-adjacent IPs, hashes of made-up strings.
"""
import hashlib

from .store import IOC

MOCK_IPS = ["193.32.162.157", "194.26.135.80", "80.66.76.132"]
MOCK_DOMAINS = ["c2.malware-delivery.example", "login-verify.phish.example", "update-cdn.badhost.example"]
MOCK_HASHES = [hashlib.sha256(f"logunify-mock-malware-{i}".encode()).hexdigest() for i in range(3)]


def mock_iocs(feed: str = "mock-misp") -> list[IOC]:
    out = [IOC("ip", ip, feed, "Network activity", 1, "1001", "Mock botnet C2 infrastructure", ("tlp:amber", "botnet"))
           for ip in MOCK_IPS]
    out += [IOC("domain", d, feed, "Network activity", 2, "1002", "Mock phishing / malware delivery", ("tlp:green", "phishing"))
            for d in MOCK_DOMAINS]
    out += [IOC("sha256", h, feed, "Payload delivery", 1, "1003", "Mock ransomware dropper", ("tlp:amber", "ransomware"))
            for h in MOCK_HASHES]
    return out
