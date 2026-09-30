"""Mock log generators (Syslog, JSON, CEF) and a rate-limited producer.

Run standalone against Kafka:
    python -m app.mock.generators --rate 200 --seconds 30
"""
import argparse
import asyncio
import json
import random
from datetime import datetime, timezone

HOSTS = ["web-01", "web-02", "db-01", "fw-edge", "vpn-gw", "auth-01"]
USERS = ["alice", "bob", "root", "admin", "svc_backup", "jdoe"]
INTERNAL = ["10.0.1.15", "10.0.2.44", "192.168.1.20", "172.16.5.9"]
EXTERNAL = ["185.220.101.4", "45.155.205.233", "91.240.118.172", "203.0.113.77", "198.51.100.23"]


def _ip(pool):
    return random.choice(pool)


def gen_syslog() -> str:
    host, ts = random.choice(HOSTS), datetime.now(timezone.utc)
    ip, user, pid = _ip(EXTERNAL), random.choice(USERS), random.randint(100, 65000)
    kind = random.random()
    if kind < 0.5:
        return f"<38>{ts:%b %e %H:%M:%S} {host} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {random.randint(1024, 65535)} ssh2"
    if kind < 0.75:
        return f"<38>{ts:%b %e %H:%M:%S} {host} sshd[{pid}]: Accepted publickey for {user} from {_ip(INTERNAL)} port 50022 ssh2"
    if kind < 0.9:
        return f"<86>1 {ts.isoformat()} {host} sudo {pid} - - {user} : TTY=pts/0 ; COMMAND=/usr/bin/apt update"
    return f"<30>{ts:%b %e %H:%M:%S} {host} cron[{pid}]: (root) CMD (/usr/local/bin/backup.sh)"


def gen_json() -> str:
    status = random.choices([200, 200, 200, 301, 404, 500, 403], k=1)[0]
    return json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": random.choice(["api-gateway", "checkout", "auth"]),
        "level": "error" if status >= 500 else random.choice(["info", "warn"]),
        "host": random.choice(HOSTS), "src_ip": _ip(EXTERNAL + INTERNAL),
        "method": random.choice(["GET", "POST", "PUT"]),
        "path": random.choice(["/login", "/api/v1/items", "/admin", "/health", "/.env"]),
        "status": status, "latency_ms": random.randint(2, 900),
        "message": f"request completed status={status}",
    })


def gen_cef() -> str:
    sig, name, sev = random.choice([
        ("100", "Port scan detected", 5), ("200", "SQL injection attempt", 8),
        ("300", "Connection blocked", 3), ("400", "Malware callback", 10)])
    return (f"CEF:0|Acme|NGFW|2.4.1|{sig}|{name}|{sev}|src={_ip(EXTERNAL)} dst={_ip(INTERNAL)} "
            f"spt={random.randint(1024, 65535)} dpt={random.choice([22, 80, 443, 3389])} proto=TCP "
            f"act={random.choice(['blocked', 'allowed'])} msg={name} on {random.choice(HOSTS)}")


def gen_ioc_line() -> str:
    """A log that mentions a (mock) MISP indicator: C2 IP, malicious domain or dropper hash."""
    from ..threatintel.mock import MOCK_DOMAINS, MOCK_HASHES, MOCK_IPS
    return random.choice([
        f"Outbound connection from {_ip(INTERNAL)} to {random.choice(MOCK_IPS)} port 443 established",
        f"DNS query for {random.choice(MOCK_DOMAINS)} from {_ip(INTERNAL)} resolved",
        f"Process created on {random.choice(HOSTS)} image hash {random.choice(MOCK_HASHES)}",
    ])


def gen_text(rare_rate: float = 0.01) -> str:
    """Unstructured app logs (Drain3 territory). A small share are rare, high-signal events."""
    if random.random() < rare_rate:
        return random.choice([
            f"Privilege escalation detected: user {random.choice(USERS)} added to group wheel from {_ip(EXTERNAL)}",
            f"Audit log cleared by user {random.choice(USERS)} on {random.choice(HOSTS)}",
            f"Unexpected outbound transfer of {random.randint(500, 900)} MB to {_ip(EXTERNAL)} port 4444",
        ])
    return random.choice([
        f"Connection from {_ip(INTERNAL)} port {random.randint(1024, 65535)} closed after {random.randint(1, 900)} ms",
        f"Session opened for user {random.choice(USERS)} from {_ip(INTERNAL)}",
        f"Request served status {random.choice([200, 200, 404, 500])} bytes {random.randint(100, 90000)}",
        f"Cache refresh completed on {random.choice(HOSTS)} in {random.randint(5, 400)} ms",
    ])


def gen_malformed() -> str:
    return random.choice(["", "   ", "{not: valid json", "CEF:0|too|few|fields",
                          "<999>Jan  1 00:00:00 host app: bad pri"])


def gen_log(malformed_rate: float = 0.03) -> tuple[str, str | None]:
    """Returns (raw_line, expected_format or None if malformed)."""
    if random.random() < malformed_rate:
        return gen_malformed(), None
    if random.random() < 0.01:
        return gen_ioc_line(), "text"
    fmt = random.choices(["syslog", "json", "cef", "text"], weights=[4, 3, 2, 3])[0]
    return {"syslog": gen_syslog, "json": gen_json, "cef": gen_cef, "text": gen_text}[fmt](), fmt


async def produce(submit, rate: int, seconds: float | None = None, malformed_rate: float = 0.03) -> None:
    """Call `submit(raw: bytes)` at ~`rate` events/s (in 50 ms ticks) for `seconds` (forever if None)."""
    tick, per_tick, carry, elapsed = 0.05, rate * 0.05, 0.0, 0.0
    while seconds is None or elapsed < seconds:
        carry += per_tick
        n, carry = int(carry), carry - int(carry)
        for _ in range(n):
            await submit(gen_log(malformed_rate)[0].encode())
        await asyncio.sleep(tick)
        elapsed += tick


async def _cli(rate: int, seconds: float | None) -> None:
    from ..config import settings
    from ..pipeline.bus import KafkaBus
    bus = KafkaBus(settings)
    await bus.start()
    try:
        await produce(bus.publish, rate, seconds)
    finally:
        await bus.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Publish mock logs to the Kafka raw topic")
    ap.add_argument("--rate", type=int, default=100)
    ap.add_argument("--seconds", type=float, default=None)
    a = ap.parse_args()
    asyncio.run(_cli(a.rate, a.seconds))
