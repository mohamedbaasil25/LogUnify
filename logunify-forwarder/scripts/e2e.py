"""End-to-end test: LogUnify backend (Kafka mode) -> Kafka -> Vector -> {Elasticsearch mock, Splunk HEC mock, Wazuh file}.

    python scripts/e2e.py            # needs Kafka on 127.0.0.1:9092; run with a Python that has confluent-kafka

Real: LogUnify backend, Kafka broker, Vector 0.58 with the shipped configs. Mocked (see mock_receivers.py): Elasticsearch,
Splunk HEC. Wazuh is checked as the NDJSON file the agent would tail.
Stages: baseline fan-out + payload shape | dead-letter queue | one destination down | Vector hard-kill | replay idempotency.
"""
import glob
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from confluent_kafka import Consumer, ConsumerGroupTopicPartitions, Producer, TopicPartition
from confluent_kafka.admin import AdminClient, NewTopic

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / ".e2e"
BOOT = "127.0.0.1:9092"
BACKEND_PY = os.environ.get("BACKEND_PYTHON", r"C:\Users\MOHAMED BAASIL\AppData\Local\Programs\Python\Python313\python.exe")
BACKEND_DIR = ROOT.parent / "logunify-backend"
VECTOR = ROOT / "tools" / "vector" / "bin" / "vector.exe"
KCONF = {"bootstrap.servers": BOOT, "broker.address.family": "v4"}
RUN = str(int(time.time()))
RAW, ECS, DLQ = f"e2e{RUN}.raw", f"e2e{RUN}.ecs", f"e2e{RUN}.dlq"
ES_PORT, HEC_PORT, API_PORT = 19200, 18088, 18000
FAILS: list[str] = []
PROCS: list[subprocess.Popen] = []


def check(cond: bool, msg: str) -> None:
    print(("  PASS  " if cond else "  FAIL  ") + msg, flush=True)
    if not cond:
        FAILS.append(msg)


def wait_for(fn, timeout: float, what: str, every: float = 1.0):
    end, last = time.time() + timeout, None
    while time.time() < end:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:                      # noqa: BLE001 - services may still be starting
            last = e
        time.sleep(every)
    raise SystemExit(f"TIMEOUT waiting for {what} (last: {last!r})")


def http(method: str, url: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read() or b"{}")


def mock(path: str, port: int = ES_PORT) -> dict:
    return http("POST" if "/fail" in path or "/reset" in path else "GET", f"http://127.0.0.1:{port}{path}")


def state(ids: bool = False) -> dict:
    return mock("/_test/state" + ("?ids=1" if ids else ""))


def wazuh_lines() -> list[dict]:
    out = []
    for f in glob.glob(str(WORK / "wazuh" / "ecs-*.json")):
        out += [json.loads(l) for l in Path(f).read_text(encoding="utf-8").splitlines() if l.strip()]
    return out


def end_offset(topic: str) -> int:
    c = Consumer({**KCONF, "group.id": f"probe-{time.time_ns()}"})
    try:
        return c.get_watermark_offsets(TopicPartition(topic, 0), timeout=15)[1]
    finally:
        c.close()


def committed(group: str, topic: str) -> int:
    a = AdminClient(KCONF)
    res = a.list_consumer_group_offsets([ConsumerGroupTopicPartitions(group, [TopicPartition(topic, 0)])])[group].result(15)
    return max((tp.offset for tp in res.topic_partitions), default=-1)


def read_all(topic: str, n: int, timeout: int = 60) -> list[bytes]:
    c = Consumer({**KCONF, "group.id": f"read-{time.time_ns()}", "enable.auto.commit": False})
    c.assign([TopicPartition(topic, 0, 0)])
    vals, end = [], time.time() + timeout
    while len(vals) < n and time.time() < end:
        m = c.poll(1.0)
        if m and not m.error():
            vals.append(m.value())
    c.close()
    return vals


def lines(start: int, count: int) -> list[str]:
    out = []
    for i in range(start, start + count):
        k = i % 3
        if k == 0:
            out.append(f"<38>Oct 11 22:14:15 web-01 sshd[{i}]: Failed password for user{i} from 10.1.{i // 250 % 250}.{i % 250} port {2000 + i} ssh2")
        elif k == 1:
            out.append(json.dumps({"timestamp": "2026-09-30T03:49:38Z", "host": f"h{i}", "src_ip": f"172.16.{i // 250 % 250}.{i % 250}", "message": f"login ok user{i}"}))
        else:
            out.append(f"CEF:0|Acme|NGFW|1.0|100|Port scan|5|src=193.32.162.157 dst=10.0.{i // 250 % 250}.{i % 250} dpt=22 msg=scan {i}")
    return out


def start(cmd, name: str, env: dict | None = None, cwd=None) -> subprocess.Popen:
    log = open(WORK / f"{name}.log", "ab")
    p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=cwd, env={**os.environ, **(env or {})})
    PROCS.append(p)
    return p


def vector_env(group: str) -> dict:
    return {"VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION": "true", "KAFKA_BOOTSTRAP": BOOT, "KAFKA_ADDRESS_FAMILY": "v4",
            "ECS_TOPIC": ECS, "DLQ_TOPIC": DLQ, "FORWARDER_GROUP": group, "LOGUNIFY_ENV": "prod",
            "ES_URL": f"http://127.0.0.1:{ES_PORT}", "SPLUNK_HEC_URL": f"http://127.0.0.1:{HEC_PORT}",
            "WAZUH_LOG_DIR": (WORK / "wazuh").as_posix(), "SECRETS_DIR": (WORK / "secrets").as_posix(),
            "VECTOR_DATA_DIR": (WORK / "vector-data").as_posix()}


def start_vector(group: str, name: str, extra: dict | None = None) -> subprocess.Popen:
    files = sorted(f for f in glob.glob(str(ROOT / "vector" / "vector.d" / "*.yaml")))
    cmd = [str(VECTOR)] + [x for f in files for x in ("-c", f)]
    return start(cmd, name, {**vector_env(group), **(extra or {})})


def stop(p: subprocess.Popen) -> None:
    if p.poll() is None:
        p.kill()
        p.wait(10)


def main() -> int:
    WORK.mkdir(exist_ok=True)
    for d in ("wazuh", "secrets", "vector-data"):
        (WORK / d).mkdir(exist_ok=True)
    (WORK / "secrets" / "es_authorization").write_text("ApiKey e2e-test-key")
    (WORK / "secrets" / "splunk_hec_token").write_text("test-hec-token")
    for f in glob.glob(str(WORK / "wazuh" / "*.json")):
        os.remove(f)

    admin = AdminClient(KCONF)
    for f in admin.create_topics([NewTopic(t, 1, 1) for t in (RAW, ECS, DLQ)]).values():
        f.result(30)

    start([sys.executable, str(ROOT / "scripts" / "mock_receivers.py"), "--es-port", str(ES_PORT), "--hec-port", str(HEC_PORT)], "mocks")
    benv = {"LOGUNIFY_KAFKA_ENABLED": "true", "LOGUNIFY_KAFKA_BOOTSTRAP": BOOT, "LOGUNIFY_KAFKA_RAW_TOPIC": RAW,
            "LOGUNIFY_KAFKA_ECS_TOPIC": ECS, "LOGUNIFY_KAFKA_GROUP": f"backend-{RUN}", "LOGUNIFY_MOCK_ENABLED": "false"}
    start([BACKEND_PY, "-m", "uvicorn", "app.main:app", "--port", str(API_PORT), "--host", "127.0.0.1"], "backend", benv, BACKEND_DIR)
    wait_for(lambda: state() is not None, 20, "mock receivers")
    wait_for(lambda: http("GET", f"http://127.0.0.1:{API_PORT}/health").get("bus") == "kafka", 60, "LogUnify backend (kafka mode)")

    def ingest(start_i: int, n: int) -> None:
        http("POST", f"http://127.0.0.1:{API_PORT}/api/v1/ingest", {"logs": lines(start_i, n)})
        wait_for(lambda: end_offset(ECS) >= start_i + n, 90, f"backend to publish {start_i + n} ECS docs")

    # ------------------------------------------------------------------ 1. baseline fan-out
    print("\n[1] baseline: backend -> Kafka -> Vector -> ES / Splunk HEC / Wazuh file")
    N = 300
    ingest(0, N)
    vec = start_vector(f"fwd-{RUN}", "vector1")
    wait_for(lambda: state()["es_docs"] >= N and state()["hec_events"] >= N and len(wazuh_lines()) >= N, 120, f"all {N} events at all 3 destinations")
    s = state(ids=True)
    check(s["es_docs"] == N and s["hec_events"] == N and len(wazuh_lines()) == N, f"each destination received exactly {N} events (ES {s['es_docs']}, HEC {s['hec_events']}, Wazuh {len(wazuh_lines())})")
    es = next(iter(s["es_sample"]))
    doc = es["_source"]
    check(es["_index"] == "logs-logunify-prod", f"ES index is the data stream {es['_index']}")
    check("es_id" not in doc and doc["event"]["id"].startswith(f"{ECS}:0:"), "ES doc keeps ECS event.id and the helper es_id is not leaked")
    check(sorted(s["es_ids"]) == sorted(f"{ECS}:0:{i}" for i in range(N)), "ES _id = topic:partition:offset for every record (idempotent key)")
    check(isinstance(doc.get("@timestamp"), str) and doc["labels"]["forwarder"] == "vector" and "logunify" in doc, "ES doc has @timestamp, forwarder label and the LogUnify enrichment fields")
    check(s["es_auth_values"] == ["ApiKey e2e-test-key"], "ES Authorization header came from the secret backend (SECRET[fwd.es_authorization])")
    h = s["hec_sample"][0]
    check(h.get("index") == "logunify" and h.get("sourcetype") == "logunify:ecs" and h.get("source") == "logunify-forwarder", "HEC metadata: index / sourcetype / source")
    check(isinstance(h.get("time"), (int, float)) and h.get("host"), "HEC time + host set from the ECS timestamp / host.name")
    if os.environ.get("E2E_DEBUG"):
        print("  HEC top-level keys:", sorted(h), "| event keys:", sorted(h["event"]), "| host meta:", h["host"], "| event.host:", h["event"].get("host"), "| time:", h["time"], "| event.@timestamp:", h["event"].get("@timestamp")); print("  state:", {k: v for k, v in s.items() if k.startswith("hec")  and "sample" not in k and "ids" not in k})
    check(h["event"].get("host", {}).get("name") == h["host"] and "@timestamp" in h["event"] and not {"es_id", "splunk_time"} & set(h["event"]), "HEC payload keeps host.name and @timestamp; helper keys are not leaked")
    check(h["event"]["event"]["id"].startswith(f"{ECS}:0:") and "logunify" in h["event"], "HEC payload keeps the full ECS document (event.id, logunify.*)")
    wait_for(lambda: state()["hec_acks_polled"] > 0, 45, "Vector to poll Splunk indexer acknowledgements (query_interval 10 s)")
    s = state()
    check(s["hec_calls"] > 0 and s["hec_acks_polled"] > 0 and s["hec_channels"] >= 1, "Splunk indexer acknowledgement in use (channel + /ack polling)")
    w = wazuh_lines()
    check(all("@timestamp" in x and "event" in x for x in w) and len({x["event"]["id"] for x in w}) == N, "Wazuh file: valid NDJSON ECS docs, one per event")
    ti = [x for x in w if x.get("threat", {}).get("indicator", {}).get("provider")]
    check(len(ti) == N // 3, f"threat-intel matches survived the pipeline ({len(ti)} of {N // 3} CEF events with the IOC IP)")
    time.sleep(8)
    check(committed(f"fwd-{RUN}", ECS) >= N, f"Kafka offset committed after delivery (committed {committed(f'fwd-{RUN}', ECS)} of {N})")

    if os.environ.get("E2E_STOP_AFTER") == "1":
        return 1 if FAILS else 0

    # ------------------------------------------------------------------ 2. DLQ
    print("\n[2] dead-letter queue")
    p = Producer(KCONF)
    p.produce(ECS, b"this is not json")
    p.produce(ECS, b"[1,2,3]")
    p.flush(20)
    dlq = read_all(DLQ, 2, 60)
    check(len(dlq) == 2, f"2 malformed payloads landed in the DLQ topic (got {len(dlq)})")
    dl = [json.loads(x) for x in dlq]
    check({d["message"] for d in dl} == {"this is not json", "[1,2,3]"}, "DLQ preserves the original payloads unmodified")
    time.sleep(3)
    check(state()["es_docs"] == N, "malformed payloads did not reach any destination")

    # ------------------------------------------------------------------ 3. one destination down
    print("\n[3] Splunk down: other destinations must keep flowing, Splunk must catch up with no loss")
    mock("/_test/fail?target=hec&n=100000")
    ingest(N, 200)
    total = N + 200
    wait_for(lambda: state()["es_docs"] >= total and len(wazuh_lines()) >= total, 90, "ES + Wazuh to continue while Splunk is failing")
    s = state()
    check(s["es_docs"] == total and len(wazuh_lines()) == total and s["hec_events"] == N, f"ES {s['es_docs']}/{total}, Wazuh {len(wazuh_lines())}/{total} delivered; Splunk held at {s['hec_events']} (503s)")
    mock("/_test/fail?target=hec&n=0")
    wait_for(lambda: len(set(state(ids=True)["hec_event_ids"])) >= total, 120, "Splunk to catch up after recovery (unique events)")
    hids = state(ids=True)["hec_event_ids"]
    check(len(set(hids)) == total, f"Splunk received all {total} unique events after recovery (no loss; {len(hids) - len(set(hids))} duplicates)")

    # ------------------------------------------------------------------ 4. Vector hard-kill with undelivered data
    print("\n[4] Vector kill -9 while events sit undelivered in its disk buffer (Splunk failing), restart, same consumer group")
    mock("/_test/fail?target=hec&n=100000")
    ingest(total, 300)
    total += 300
    wait_for(lambda: state()["es_docs"] >= total and len(wazuh_lines()) >= total, 90, "ES + Wazuh to receive the new events")
    time.sleep(6)                                                    # let Vector commit offsets: the buffer is now the ONLY copy for Splunk
    undelivered = total - state()["hec_events"]
    vec.kill(); vec.wait(10)
    mock("/_test/fail?target=hec&n=0")                               # Splunk healthy again, but Vector is dead
    check(undelivered == 300, f"killed Vector (kill -9) with {undelivered} events undelivered to Splunk; Kafka offsets already committed past them")
    vec = start_vector(f"fwd-{RUN}", "vector2")
    wait_for(lambda: len(set(state(ids=True)["hec_event_ids"])) >= total, 150, "Splunk to receive every unique buffered event after restart")
    time.sleep(5)
    s = state(ids=True)
    check(len(set(s["hec_event_ids"])) == total, f"Splunk has all {total} unique events: the disk buffer survived the hard kill ({len(s['hec_event_ids']) - total} duplicates)")
    check(len(set(s["es_ids"])) == total == s["es_docs"], f"ES still has exactly {total} unique documents (no duplicates)")
    check(len({x["event"]["id"] for x in wazuh_lines()}) == total, f"Wazuh file has all {total} unique events ({len(wazuh_lines()) - total} duplicates)")

    # ------------------------------------------------------------------ 5. replay idempotency
    print("\n[5] replay whole topic with a new consumer group (simulates offset reset / DR replay)")
    before_conf = state()["es_conflicts"]
    (WORK / "vector-data-replay").mkdir(exist_ok=True)      # own disk-buffer dir + API port: two Vectors can't share either
    replay = start_vector(f"replay-{RUN}", "vector3", {"VECTOR_DATA_DIR": (WORK / "vector-data-replay").as_posix(), "VECTOR_API_ADDR": "127.0.0.1:8687"})
    wait_for(lambda: state()["es_conflicts"] >= before_conf + total, 150, "ES to answer 409 for every replayed document")
    time.sleep(10)
    s = state()
    check(s["es_docs"] == total, f"ES still holds exactly {total} documents after the replay ({s['es_conflicts'] - before_conf} duplicate creates rejected with 409)")
    check(replay.poll() is None and vec.poll() is None, "Vector kept running: 409 duplicates are not treated as a delivery failure")

    print("\nRESULT:", "ALL CHECKS PASSED" if not FAILS else f"{len(FAILS)} CHECK(S) FAILED")
    return 1 if FAILS else 0


if __name__ == "__main__":
    try:
        rc = main()
    finally:
        for p in PROCS:
            stop(p)
    sys.exit(rc)
