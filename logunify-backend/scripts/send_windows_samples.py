"""Send SYNTHETIC Windows Security events (NXLog-style JSON, one per line) to a LogUnify TCP listener.

    python scripts/send_windows_samples.py --host 127.0.0.1 --port 5514 --count 5000 --rate 500

Purpose: prove the path end to end (listener -> windows_security parser -> pipeline -> search / calibration) BEFORE real hosts are
connected, and measure memory / throughput for a given LOGUNIFY_RECENT_BUFFER. The events are generated, not observed.
Never send them to the instance you are calibrating on real traffic: they would pollute the score distribution, the funnel and the
feedback. Use a scratch instance, or delete the source and restart with an empty state before real data arrives.

The mix is deliberately boring (mostly 4624/4634/4672 logons, some 4625 failures, 4688 process starts) plus a handful of rare
critical events (log cleared, Domain Admins change, audit policy change) so a replay has something to find.
"""
import argparse
import json
import random
import socket
import sys
import time
from datetime import datetime, timedelta, timezone

USERS = [f"user{i:03d}" for i in range(80)] + ["svc-backup", "svc-sql", "administrator"]
HOSTS = [f"WS-{i:04d}.corp.example.com" for i in range(200)] + ["DC01.corp.example.com", "DC02.corp.example.com", "SRV-FS1.corp.example.com"]
SRC = "Microsoft-Windows-Security-Auditing"


def event(rng: random.Random, t: datetime, rare: bool, local_tz: timezone) -> dict:
    host = rng.choice(HOSTS)
    base = {"EventTime": t.astimezone(local_tz).strftime("%Y-%m-%d %H:%M:%S"), "Hostname": host, "Channel": "Security", "SourceName": SRC}
    user = rng.choice(USERS)
    ip = f"10.{rng.randint(1, 5)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    if rare:
        pick = rng.choice(("clear", "group", "policy"))
        if pick == "clear":
            return {**base, "EventID": 1102, "SourceName": "Microsoft-Windows-Eventlog", "SubjectUserName": user, "Message": "The audit log was cleared."}
        if pick == "group":
            return {**base, "EventID": 4728, "TargetUserName": "Domain Admins", "TargetDomainName": "CORP", "SubjectUserName": user,
                    "TargetSid": "S-1-5-21-1004336348-1177238915-682003330-512", "MemberName": f"CN={user},OU=Users,DC=corp,DC=example,DC=com",
                    "Message": "A member was added to a security-enabled global group."}
        return {**base, "EventID": 4719, "SubjectUserName": user, "Message": "System audit policy was changed."}
    r = rng.random()
    if r < 0.45:
        return {**base, "EventID": 4624, "TargetUserName": user, "TargetDomainName": "CORP", "LogonType": rng.choice([2, 3, 3, 3, 10]), "IpAddress": ip,
                "IpPort": str(rng.randint(40000, 60000)), "WorkstationName": host.split(".")[0], "Message": "An account was successfully logged on."}
    if r < 0.75:
        return {**base, "EventID": 4634, "TargetUserName": user, "TargetDomainName": "CORP", "LogonType": 3, "Message": "An account was logged off."}
    if r < 0.85:
        return {**base, "EventID": 4672, "SubjectUserName": user, "Message": "Special privileges assigned to new logon."}
    if r < 0.93:
        return {**base, "EventID": 4688, "NewProcessName": rng.choice([r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\cmd.exe", r"C:\Program Files\App\agent.exe"]),
                "ParentProcessName": r"C:\Windows\System32\services.exe", "CommandLine": "x" * rng.randint(10, 200), "SubjectUserName": user,
                "Message": "A new process has been created."}
    return {**base, "EventID": 4625, "TargetUserName": user, "TargetDomainName": "CORP", "LogonType": 3, "IpAddress": ip, "IpPort": str(rng.randint(40000, 60000)),
            "Status": "0xc000006d", "Message": "An account failed to log on."}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--count", type=int, default=5000)
    ap.add_argument("--rate", type=int, default=0, help="events/second (0 = as fast as the listener accepts)")
    ap.add_argument("--rare", type=float, default=0.002, help="share of rare critical events")
    ap.add_argument("--utc-offset", type=float, default=5.5, help="hours: NXLog writes EventTime in the host's LOCAL time (default IST)")
    ap.add_argument("--realtime", action="store_true", help="stamp each event with the current time (default: spread over the last COUNT seconds, a backlog)")
    ap.add_argument("--tls-ca", help="CA file: connect with TLS and verify the server against it (server name = --host, so use the name in the certificate)")
    ap.add_argument("--tls-cert", help="client certificate (mutual TLS)")
    ap.add_argument("--tls-key", help="client private key")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    rng, local_tz = random.Random(a.seed), timezone(timedelta(hours=a.utc_offset))
    t0 = datetime.now(timezone.utc) - timedelta(seconds=a.count)
    sent, start = 0, time.perf_counter()
    raw = socket.create_connection((a.host, a.port), timeout=10)
    if a.tls_ca:
        import ssl
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=a.tls_ca)
        if a.tls_cert:
            ctx.load_cert_chain(a.tls_cert, a.tls_key)
        raw = ctx.wrap_socket(raw, server_hostname=a.host)                  # verifies the chain AND that the certificate matches --host
    with raw as s:
        batch = []
        for i in range(a.count):
            ev = event(rng, datetime.now(timezone.utc) if a.realtime else t0 + timedelta(seconds=i), rng.random() < a.rare, local_tz)
            batch.append(json.dumps(ev, separators=(",", ":")) + "\n")
            if len(batch) >= 200:
                s.sendall("".join(batch).encode())
                sent += len(batch)
                batch = []
                if a.rate:
                    time.sleep(max(0.0, sent / a.rate - (time.perf_counter() - start)))
        if batch:
            s.sendall("".join(batch).encode())
            sent += len(batch)
    print(f"sent {sent} events in {time.perf_counter() - start:.1f}s to {a.host}:{a.port}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
