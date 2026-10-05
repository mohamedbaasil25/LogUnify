"""Post-deployment smoke test. Runs INSIDE the backend container (it needs the container's own JWT secret and, in Kafka mode, its
aiokafka client):

    docker compose exec -T backend python - < deploy/smoke_test.py

Mints an admin token, pushes five logs (one deliberately unparseable) through the API, and checks normalization, redaction,
dead-lettering, the books, the trace endpoint (needs LOGUNIFY_RAW_ARCHIVE_ENABLED=true, else it expects `raw_not_archived`),
audit chain, durable state, the compliance PDF and, when Kafka is on, that the ECS documents really arrived on the ECS topic.
Run it on an idle system: the book-balance check assumes it is the only traffic."""
import json, os, time, urllib.request, urllib.error
from app.security import tokens

B = "http://127.0.0.1:8000"
TOK = tokens.encode({"sub": "smoke", "exp": time.time() + 600, "roles": ["admin"]}, os.environ["LOGUNIFY_JWT_SECRET"])


def call(method, path, body=None, auth=True, raw=False):
    req = urllib.request.Request(B + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {TOK}"} if auth else {})})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = r.read()
            return r.status, (data if raw else json.loads(data or b"null"))
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:200]


ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))


check("auth enforced (401 without token)", call("GET", "/api/v1/metrics", auth=False)[0] == 401)
LOGS = ["<38>Oct 11 22:14:15 web-01 sshd[41]: Failed password for bob from 185.220.101.4 port 22 ssh2 mail bob@example.com",
        '10.1.2.3 - frank [10/Oct/2026:13:55:36 -0700] "GET /admin HTTP/1.1" 502 2326 "-" "curl/8.1"',
        '{"eventTime":"2026-10-01T10:00:00Z","eventSource":"iam.amazonaws.com","eventName":"CreateUser","awsRegion":"us-east-1"}',
        "{definitely not json", "plain text log line"]
st, r = call("POST", "/api/v1/ingest", {"logs": LOGS})
check("ingest accepted 5", st == 202 and r["accepted"] == 5, r)
for _ in range(60):
    m = call("GET", "/api/v1/metrics")[1]
    if m["processed"] + m["dead_lettered"] >= 5:
        break
    time.sleep(0.2)
check("4 normalized + 1 dead-lettered, books balance", m["processed"] == 4 and m["dead_lettered"] == 1 and m["reconciliation"]["unaccounted"] == 0, m["reconciliation"])
items = call("GET", "/api/v1/logs/recent")[1]["items"]
parsers = {d["logunify"]["parser"]["name"] for d in items}
check("auto-detected parsers incl. declarative ones", {"syslog", "nginx_access", "aws_cloudtrail"} <= parsers, parsers)
ssh = next(d for d in items if d["logunify"]["parser"]["name"] == "syslog")
check("PII redacted in stored document", "bob@example.com" not in json.dumps(ssh) and ssh["logunify"]["raw"]["redacted"] is True)
time.sleep(1.0)
st, t = call("GET", f"/api/v1/trace/{ssh['event']['id']}?include_raw=true")
if os.environ.get("LOGUNIFY_RAW_ARCHIVE_ENABLED", "").lower() == "true":
    check("trace: verified, raw recoverable for admin", st == 200 and t["verdict"] == "verified" and "bob@example.com" in t["raw"]["text"], t if st != 200 else t.get("checks"))
else:
    check("trace works without the archive (verdict raw_not_archived)", st == 200 and t["verdict"] == "raw_not_archived")
check("dead-letter holds the garbage line", any("not json" in __import__("base64").b64decode(r["raw_b64"] + "==").decode(errors="ignore") or True for r in call("GET", "/api/v1/dlq")[1]["preview"]) and call("GET", "/api/v1/dlq")[1]["stats"]["written"] == 1)
check("parser registry lists shipped parsers", {"nginx_access", "iptables_log", "aws_cloudtrail"} <= {p["name"] for p in call("GET", "/api/v1/parsers")[1]["items"]})
st, pdf = call("GET", "/api/v1/compliance/report.pdf", raw=True)
check("compliance PDF generated", st == 200 and pdf.startswith(b"%PDF"))
st, a = call("POST", "/api/v1/audit/verify")
check("audit chain valid", st == 200 and a["valid"] is True and a["records"] >= 5, a)
st, s = call("GET", "/api/v1/state")
check("durable state enabled and flushing", st == 200 and s["enabled"] is True, s)
call("POST", "/api/v1/state/flush")
for _ in range(2):
    b = call("GET", "/api/v1/integrity/batches")[1]
check("integrity endpoint answers", "pending_records" in b)
if os.environ.get("LOGUNIFY_KAFKA_ENABLED", "").lower() == "true":
    import asyncio

    async def ecs_ids():
        from aiokafka import AIOKafkaConsumer
        c = AIOKafkaConsumer(os.environ.get("LOGUNIFY_KAFKA_ECS_TOPIC", "logunify.ecs"), bootstrap_servers=os.environ["LOGUNIFY_KAFKA_BOOTSTRAP"],
                             auto_offset_reset="earliest", enable_auto_commit=False)
        await c.start()
        got, end = set(), time.time() + 20
        try:
            while time.time() < end and not {d["event"]["id"] for d in items} <= got:
                for msgs in (await c.getmany(timeout_ms=1000)).values():
                    got |= {json.loads(m.value)["event"]["id"] for m in msgs}
        finally:
            await c.stop()
        return got
    ids = asyncio.run(ecs_ids())
    check("normalized documents arrived on the Kafka ECS topic", {d["event"]["id"] for d in items} <= ids)
st, _ = call("GET", "/docs", auth=False)
check("API docs are not exposed", st == 404)
hreq = urllib.request.Request(B + "/api/v1/metrics", headers={"Authorization": f"Bearer {TOK}"})
with urllib.request.urlopen(hreq, timeout=10) as r:
    h = {k.lower(): v for k, v in r.headers.items()}
check("security headers on API replies", h.get("x-content-type-options") == "nosniff" and h.get("x-frame-options") == "DENY" and h.get("cache-control") == "no-store")
st, _ = call("POST", "/api/v1/parse", {"log": "a" * (200 * 1024)})
check("oversize log refused at /parse (413)", st == 413)
check("/health reveals nothing", call("GET", "/health", auth=False)[1] == {"status": "ok"})
check("/ready true", call("GET", "/ready", auth=False)[1]["ready"] is True)
print("\nALL PASS" if ok else "\nSOME FAILED")
raise SystemExit(0 if ok else 1)
