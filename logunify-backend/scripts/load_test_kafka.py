"""End-to-end throughput test against a real Kafka broker: raw topic -> N backend workers -> ECS topic (acks=all, idempotent).

    python scripts/load_test_kafka.py --bootstrap 127.0.0.1:9092 --n 100000 --workers 2

Preloads N mixed logs into a fresh raw topic (partitions = workers), then starts `workers` consumer PROCESSES in one consumer group
(the real scale-out model: each owns some partitions, has its own worker id and stores) and times how long until all N logs are
normalized AND acknowledged on the ECS topic. Reports events/s, the reconciliation books and the ECS topic's message count.

What it measures: normalization + Kafka I/O with durable (acks=all) publishing, on this machine, with mock logs. What it does NOT:
a cluster with replication, network latency, Elasticsearch, alerting storms, or real log diversity. Treat the number as a ceiling for
this hardware, and measure again on yours.
"""
import argparse
import asyncio
import multiprocessing as mp
import os
import random
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _worker(idx: int, bootstrap: str, tag: str, counter, stop, tmp: str) -> None:
    os.environ.update(LOGUNIFY_AUDIT_DB_PATH=":memory:", LOGUNIFY_STATE_DB_PATH=":memory:", LOGUNIFY_ALERT_DB_PATH=":memory:")
    import logging
    logging.disable(logging.CRITICAL)
    from app.config import Settings
    from app.pipeline.bus import make_bus
    from app.pipeline.metrics import MetricsRegistry
    from app.pipeline.processor import Pipeline

    async def go():
        s = Settings(kafka_enabled=True, kafka_bootstrap=bootstrap, kafka_raw_topic=f"raw.{tag}", kafka_ecs_topic=f"ecs.{tag}",
                     kafka_group=f"g.{tag}", mock_enabled=False, worker_id=f"w{idx}", dlq_path=f"{tmp}/dlq-{idx}.jsonl",
                     batch_max=500, process_chunk=64, kafka_batch_wait_s=0.2, taxonomy_mode=os.environ.get("LT_TAXONOMY", "off"),
                     kafka_compression=os.environ.get("LT_COMPRESSION", "gzip"))
        p = Pipeline(make_bus(s), MetricsRegistry(), s)
        await p.start()
        last = 0
        while not stop.is_set():
            await asyncio.sleep(0.1)
            n = p.metrics.processed + sum(p.metrics.dead_lettered.values())
            with counter.get_lock():
                counter.value += n - last
            last = n
        await p.stop()

    asyncio.run(go())


async def _preload(bootstrap: str, tag: str, n: int, partitions: int) -> float:
    from aiokafka import AIOKafkaProducer
    from aiokafka.admin import AIOKafkaAdminClient, NewTopic
    from app.mock.generators import gen_cef, gen_json, gen_syslog
    from app.pipeline.envelope import uuid7
    admin = AIOKafkaAdminClient(bootstrap_servers=bootstrap)
    await admin.start()
    await admin.create_topics([NewTopic(f"raw.{tag}", partitions, 1), NewTopic(f"ecs.{tag}", partitions, 1)])
    await admin.close()
    random.seed(7)
    pool = [random.choice((gen_syslog, gen_json, gen_cef))().encode() for _ in range(5000)]
    prod = AIOKafkaProducer(bootstrap_servers=bootstrap, linger_ms=50, compression_type="gzip", acks=1)
    await prod.start()
    t = time.perf_counter()
    futs = []
    for i in range(n):
        futs.append(await prod.send(f"raw.{tag}", pool[i % len(pool)], key=uuid7().encode(), headers=[("event_id", uuid7().encode())]))
        if len(futs) >= 5000:
            await asyncio.gather(*futs)
            futs = []
    await asyncio.gather(*futs)
    await prod.stop()
    return n / (time.perf_counter() - t)


async def _count_ecs(bootstrap: str, tag: str, nparts: int) -> int:
    from aiokafka import AIOKafkaConsumer, TopicPartition
    c = AIOKafkaConsumer(bootstrap_servers=bootstrap)
    await c.start()
    try:
        tps = [TopicPartition(f"ecs.{tag}", p) for p in range(nparts)]
        c.assign(tps)
        return sum((await c.end_offsets(tps)).values())
    finally:
        try:
            await c.stop()
        except asyncio.CancelledError:                      # aiokafka cancels its own coordinator task on stop()
            pass


def run(bootstrap: str, n: int, workers: int) -> dict:
    tag = uuid.uuid4().hex[:8]
    prod_rate = asyncio.run(_preload(bootstrap, tag, n, workers))
    print(f"preloaded {n} logs into raw.{tag} ({workers} partitions) at {prod_rate:,.0f}/s")
    ctx = mp.get_context("spawn")
    counter, stop, tmp = ctx.Value("i", 0), ctx.Event(), tempfile.mkdtemp(prefix="lt-")
    procs = [ctx.Process(target=_worker, args=(i, bootstrap, tag, counter, stop, tmp)) for i in range(workers)]
    t0 = time.perf_counter()
    for p in procs:
        p.start()
    t_first, last_print = None, 0.0
    while counter.value < n:
        time.sleep(0.2)
        if t_first is None and counter.value > 0:
            t_first = time.perf_counter()                   # start the clock when the first worker is actually consuming
        if time.perf_counter() - last_print > 5 and t_first:
            last_print = time.perf_counter()
            print(f"  {counter.value:>8,} / {n:,}   {counter.value / (time.perf_counter() - t_first):8,.0f} events/s so far")
        if time.perf_counter() - t0 > 900:
            print("timeout")
            break
    elapsed = time.perf_counter() - (t_first or t0)
    stop.set()
    for p in procs:
        p.join(60)
    ecs = asyncio.run(_count_ecs(bootstrap, tag, workers))
    out = {"events": counter.value, "seconds": round(elapsed, 2), "events_per_second": round(counter.value / elapsed),
           "workers": workers, "ecs_topic_messages": ecs}
    print(out)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bootstrap", default="127.0.0.1:9092")
    ap.add_argument("--n", type=int, default=100_000)
    ap.add_argument("--workers", type=int, default=1)
    a = ap.parse_args()
    run(a.bootstrap, a.n, a.workers)
