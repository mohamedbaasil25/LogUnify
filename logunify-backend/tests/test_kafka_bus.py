"""No-loss tests against a REAL Kafka broker (skipped when Java / a Kafka distribution is not available)."""
import asyncio
import json
import shutil
import threading
import time
import uuid

import pytest

from app.config import Settings
from app.pipeline.bus import KafkaBus, make_bus
from app.pipeline.metrics import MetricsRegistry
from app.pipeline.processor import Pipeline
from tests.alert_helpers import run
from tests.kafka_harness import PORT, Broker, find_kafka

pytestmark = [pytest.mark.kafka, pytest.mark.skipif(find_kafka() is None or shutil.which("java") is None,
                                                      reason="needs Java and a local Kafka distribution")]

LOG = "<38>Oct 11 22:14:15 web-01 sshd[41]: Failed password for user{i} from 185.220.101.{j} port 22 ssh2"


@pytest.fixture(scope="module")
def broker():
    b = Broker(find_kafka())
    b.start()
    yield b
    b.close()


def settings(tmp_path, tag, **kw):
    base = dict(kafka_enabled=True, kafka_bootstrap=f"127.0.0.1:{PORT}", kafka_raw_topic=f"raw.{tag}", kafka_ecs_topic=f"ecs.{tag}",
                kafka_group=f"g.{tag}", mock_enabled=False, alert_db_path=":memory:", dlq_path=str(tmp_path / f"{tag}.dlq.jsonl"),
                kafka_request_timeout_ms=8000, kafka_batch_wait_s=0.2, batch_max=50, process_chunk=10)
    base.update(kw)
    return Settings(**base)


async def read_topic(topic, n_expected=None, timeout=30, group=None):
    from aiokafka import AIOKafkaConsumer
    c = AIOKafkaConsumer(topic, bootstrap_servers=f"127.0.0.1:{PORT}", auto_offset_reset="earliest", enable_auto_commit=False,
                         group_id=group)
    await c.start()
    out, end = [], time.time() + timeout
    try:
        while time.time() < end:
            data = await c.getmany(timeout_ms=500)
            for msgs in data.values():
                out += [json.loads(m.value) for m in msgs]
            if n_expected is not None and len({d["event"]["id"] for d in out}) >= n_expected:
                break
    finally:
        await c.stop()
    return out


async def committed_lag(settings_, topic):
    from aiokafka import AIOKafkaConsumer, TopicPartition
    c = AIOKafkaConsumer(bootstrap_servers=f"127.0.0.1:{PORT}", group_id=settings_.kafka_group, enable_auto_commit=False)
    await c.start()
    try:
        parts = [TopicPartition(topic, p) for p in range(3)]                    # the broker config creates 3 partitions per topic
        c.assign(parts)
        ends = await c.end_offsets(parts)
        assert sum(ends.values()) > 0, f"{topic} is empty: a vacuous lag of 0 would prove nothing"
        lag = 0
        for tp in parts:
            lag += ends[tp] - (await c.committed(tp) or 0)
        return lag
    finally:
        await c.stop()


async def wait_until(cond, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        await asyncio.sleep(0.1)
    return False


def test_roundtrip_acks_commit_and_ids(broker, tmp_path):
    async def go():
        s = settings(tmp_path, "rt" + uuid.uuid4().hex[:6])
        assert isinstance(make_bus(s), KafkaBus)
        p = Pipeline(make_bus(s), MetricsRegistry(), s)
        await p.start()
        raws = [LOG.format(i=i, j=i % 200 + 1).encode() for i in range(200)]
        assert await p.submit_many(raws, transport="http", source_id="src-1") == 200
        assert await wait_until(lambda: p.metrics.processed >= 200)
        await p.stop()
        docs = await read_topic(s.kafka_ecs_topic, 200)
        assert len({d["event"]["id"] for d in docs}) == 200
        d = docs[0]
        assert d["logunify"]["source"]["id"] == "src-1" and d["logunify"]["transport"] == "http"
        assert d["event"]["hash"] and d["logunify"]["origin"]["kafka"]["topic"] == s.kafka_raw_topic
        assert await committed_lag(s, s.kafka_raw_topic) == 0                  # offsets advanced only after publish
    run(go())


def test_crash_before_commit_redelivers_everything_with_same_ids(broker, tmp_path):
    async def go():
        tag = "crash" + uuid.uuid4().hex[:6]
        s = settings(tmp_path, tag)
        p1 = Pipeline(make_bus(s), MetricsRegistry(), s)
        await p1.start()
        assert await p1.submit_many([LOG.format(i=i, j=1).encode() for i in range(120)]) == 120
        # simulate a crash: the batch is processed and published but the offset commit never happens

        async def die(*a, **k):
            raise RuntimeError("process killed before commit")
        p1.bus._consumer.commit = die
        assert await wait_until(lambda: p1.metrics.processed >= 120)
        await p1.stop()
        assert await committed_lag(s, s.kafka_raw_topic) == 120                # nothing committed

        p2 = Pipeline(make_bus(s), MetricsRegistry(), s)                        # the restarted process
        await p2.start()
        assert await wait_until(lambda: p2.metrics.processed >= 120)
        await asyncio.sleep(1.0)
        await p2.stop()
        assert await committed_lag(s, s.kafka_raw_topic) == 0
        docs = await read_topic(s.kafka_ecs_topic, 120)
        ids = [d["event"]["id"] for d in docs]
        assert len(set(ids)) == 120 and len(ids) == 240                         # every log twice: at-least-once, same identities
        assert not (tmp_path / f"{tag}.dlq.jsonl").exists()
    run(go())


def test_broker_outage_during_publish_loses_nothing(broker, tmp_path):
    async def go():
        tag = "outage" + uuid.uuid4().hex[:6]
        s = settings(tmp_path, tag, kafka_publish_max_wait_s=120)
        p = Pipeline(make_bus(s), MetricsRegistry(), s)
        await p.start()
        n = 90
        assert await p.submit_many([LOG.format(i=i, j=2).encode() for i in range(n)]) == n
        real = p.bus.send_ecs
        state = {"killed": False}

        async def kill_once(docs):
            if not state["killed"]:
                state["killed"] = True
                await asyncio.to_thread(broker.kill)                               # the network blip / broker crash
                threading.Timer(4.0, broker.start).start()                         # ...and recovery four seconds later
            return await real(docs)
        p.bus.send_ecs = kill_once
        assert await wait_until(lambda: p.metrics.processed >= n, 90)
        assert state["killed"]                                                     # the outage really happened mid-publish
        # (the producer's own retries may ride out a short outage; pipeline-level retries then stay at 0: both outcomes are fine)
        await asyncio.sleep(1)
        await wait_until(lambda: broker.proc.poll() is None and p.metrics.reconciliation()["unaccounted"] == 0, 90)
        await p.stop()
        docs = await read_topic(s.kafka_ecs_topic, n, timeout=60)
        assert len({d["event"]["id"] for d in docs}) == n                          # every log arrived
        assert not p.metrics.dead_lettered and not (tmp_path / f"{tag}.dlq.jsonl").exists()
    run(go())
