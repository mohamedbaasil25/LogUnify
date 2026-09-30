"""End-to-end check against a real Kafka broker.

    python scripts/e2e.py [--bootstrap localhost:9092]

Produces a known workload with explicit Kafka timestamps (so event time is deterministic), runs the job in
--bounded mode as a subprocess, then reads the SIEM and stats topics back from the wire and asserts on them.
Run with the PyFlink venv first on PATH (see README).
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from confluent_kafka import OFFSET_BEGINNING, Consumer, Producer, TopicPartition
from confluent_kafka.admin import AdminClient, NewTopic

ROOT = Path(__file__).resolve().parent.parent
V4 = {"broker.address.family": "v4"}       # localhost resolves to ::1 first on Windows; the broker listens on IPv4
sys.path.insert(0, str(ROOT))
from logunify_flink.codec import ZSTD_MAGIC, read_frame  # noqa: E402

ATTACKERS = [f"185.220.101.{i}" for i in (4, 5, 6, 7)]
REPEATS = 50            # per attacker, spread over 290 s: all inside one 5-minute window
NORMAL = 2000           # distinct users -> distinct fingerprints -> all must pass
NOISE = 200


def workload(base_ms: int):
    """[(ts_ms, raw)] ascending in time."""
    ev = []
    for a_i, ip in enumerate(ATTACKERS):
        for r in range(REPEATS):
            t = base_ms + r * 5800 + a_i * 100
            ev.append((t, f"<38>Oct 11 22:14:15 web-01 sshd[{1000 + r}]: Failed password for root from {ip} port {20000 + r} ssh2"))
    ev.append((base_ms + 310_000, f"<38>Oct 11 22:19:25 web-01 sshd[1]: Failed password for root from {ATTACKERS[0]} port 1 ssh2"))
    for i in range(NORMAL):
        ev.append((base_ms + i * 140, f'{{"timestamp":"2026-01-01T00:00:00Z","user":"user{i}","action":"login","src_ip":"10.0.{i % 200}.{i % 250}","request_id":"r{i}"}}'))
    for i in range(NOISE):
        ev.append((base_ms + i * 1400, ["GET /healthz 200 1ms", "app heartbeat ok", "<15>Oct 11 22:14:15 h app: verbose internals", ""][i % 4]))
    return sorted(ev, key=lambda e: e[0])


def create_topics(bootstrap: str, names: list[str]) -> None:
    admin = AdminClient({"bootstrap.servers": bootstrap, **V4})
    for name, fut in admin.create_topics([NewTopic(n, num_partitions=1, replication_factor=1) for n in names]).items():
        fut.result(30)


def produce(bootstrap: str, topic: str, events) -> None:
    p = Producer({"bootstrap.servers": bootstrap, "linger.ms": 20, **V4})
    for ts, line in events:
        p.produce(topic, value=line.encode(), timestamp=ts)
        p.poll(0)
    p.flush(60)


def drain(bootstrap: str, topic: str, timeout_s: int = 90) -> list[bytes]:
    """Read partition 0 from the beginning up to its end offset at the time of the call.

    Stops on consumer *position*, not message count: transactional topics contain commit markers that occupy
    offsets but are never delivered to consumers.
    """
    c = Consumer({"bootstrap.servers": bootstrap, "group.id": f"e2e-check-{time.time_ns()}",
                  "enable.auto.commit": False, "isolation.level": "read_committed", **V4})
    tp = TopicPartition(topic, 0, OFFSET_BEGINNING)
    c.assign([tp])
    _low, high = c.get_watermark_offsets(tp, timeout=30)
    vals, deadline = [], time.time() + timeout_s
    while time.time() < deadline:
        m = c.poll(1.0)
        if m is not None and not m.error():
            vals.append(m.value())
        pos = c.position([tp])[0].offset
        if pos >= high or (m is not None and not m.error() and m.offset() >= high - 1):
            break
    else:
        c.close()
        raise SystemExit(f"timed out reading {topic} (position never reached {high})")
    c.close()
    return vals


def run_case(bootstrap: str, mode: str, base_ms: int, tag: str, delivery: str = "at_least_once") -> dict:
    raw, out, stats = f"e2e.{tag}.raw", f"e2e.{tag}.siem", f"e2e.{tag}.stats"
    create_topics(bootstrap, [raw, out, stats])
    events = workload(base_ms)
    produce(bootstrap, raw, events)

    t0 = time.time()
    cmd = [sys.executable, "-m", "logunify_flink.job", "--bootstrap", bootstrap, "--bounded", "--in-topic", raw,
           "--out-topic", out, "--stats-topic", stats, "--group-id", f"e2e-{tag}", "--compression", mode, "--delivery", delivery]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=300)
    took = time.time() - t0
    if proc.returncode != 0:
        print(proc.stdout[-3000:], proc.stderr[-6000:])
        raise SystemExit(f"job failed ({mode})")
    return {"events": events, "out": drain(bootstrap, out), "stats": drain(bootstrap, stats), "seconds": took}


def check(mode: str, r: dict) -> None:
    events = r["events"]
    exp_pass = len(ATTACKERS) + 1 + NORMAL            # one per attacker, +1 re-pass after the window, all normals
    exp_supp = len(ATTACKERS) * (REPEATS - 1)
    stats = [json.loads(v) for v in r["stats"]]
    if mode == "frame":
        assert r["out"] and all(v[:4] == ZSTD_MAGIC for v in r["out"]), "SIEM messages are not raw zstd frames"
        records = [rec for v in r["out"] for rec in read_frame(v)]
    else:
        records = [json.loads(v) for v in r["out"]]
    wire = sum(len(v) for v in r["out"])
    raw_in = sum(len(l.encode()) for _, l in events)
    raws = [x["raw"] for x in records]
    assert len(records) == exp_pass, f"{mode}: expected {exp_pass} records, got {len(records)}"
    assert not any("healthz" in x or "heartbeat" in x or "verbose" in x or not x.strip() for x in raws), "noise leaked"
    assert sum(s["suppressed"] for s in stats) == exp_supp, f"suppressed {sum(s['suppressed'] for s in stats)} != {exp_supp}"
    per_ip = {ip: sum(1 for x in raws if f"from {ip} " in x) for ip in ATTACKERS}
    assert per_ip == {ATTACKERS[0]: 2, **{ip: 1 for ip in ATTACKERS[1:]}}, per_ip
    print(f"[{mode:5}] OK  in={len(events)} events / {raw_in:,} B  ->  out={len(records)} records in {len(r['out'])} "
          f"kafka msgs / {wire:,} B on the wire | suppressed={exp_supp} ({len(stats)} summaries) | job {r['seconds']:.0f}s")


def streaming_smoke(bootstrap: str) -> None:
    """Unbounded job with checkpointing: frames must appear via the processing-time linger, without a final watermark."""
    tag = f"stream{int(time.time())}"
    raw, out, stats = f"e2e.{tag}.raw", f"e2e.{tag}.siem", f"e2e.{tag}.stats"
    create_topics(bootstrap, [raw, out, stats])
    proc = subprocess.Popen([sys.executable, "-m", "logunify_flink.job", "--bootstrap", bootstrap, "--in-topic", raw,
                             "--out-topic", out, "--stats-topic", stats, "--group-id", f"e2e-{tag}",
                             "--checkpoint-ms", "5000"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(25)                                        # let the job reach RUNNING before producing
        now = int(time.time() * 1000)
        produce(bootstrap, raw, [(now + i, f"<38>Oct 11 22:14:15 web-01 sshd[{i}]: Failed password for root from 9.9.9.{i % 3} port {i} ssh2")
                                 for i in range(60)] + [(now + 100, "GET /healthz 200")])
        got, deadline = [], time.time() + 90
        while time.time() < deadline and not got:
            time.sleep(5)
            c = Consumer({"bootstrap.servers": bootstrap, "group.id": f"chk-{time.time_ns()}", "enable.auto.commit": False, **V4})
            tp = TopicPartition(out, 0, OFFSET_BEGINNING)
            c.assign([tp])
            low, high = c.get_watermark_offsets(tp, timeout=30)
            while len(got) < high - low:
                m = c.poll(2.0)
                if m is None:
                    break
                if not m.error():
                    got.append(m.value())
            c.close()
        assert got and all(v[:4] == ZSTD_MAGIC for v in got), "no zstd frame appeared in streaming mode"
        recs = [r for v in got for r in read_frame(v)]
        assert len(recs) == 3 and proc.poll() is None, f"expected 3 deduped records, got {len(recs)}"
        print(f"[stream] OK  job still RUNNING; {len(recs)} records (60 events, 3 distinct, 1 noise) in {len(got)} zstd frame(s) via linger flush")
    finally:
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootstrap", default="localhost:9092")
    ap.add_argument("--delivery", default="at_least_once", choices=["at_least_once", "exactly_once"])
    ap.add_argument("--streaming", action="store_true", help="also run the unbounded-job smoke test")
    a = ap.parse_args()
    base = int(time.time() * 1000) - 30 * 60 * 1000          # 30 min ago: recent, deterministic ordering
    stamp = str(int(time.time()))
    for mode in ("frame", "kafka"):
        check(mode, run_case(a.bootstrap, mode, base, f"{mode}{stamp}", a.delivery))
    if a.streaming:
        streaming_smoke(a.bootstrap)
    print("E2E PASSED")
