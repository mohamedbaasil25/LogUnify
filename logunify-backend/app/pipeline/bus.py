"""Message-bus abstraction: Kafka in production, a bounded in-process queue for local dev/tests.

Delivery semantics (Kafka): AT-LEAST-ONCE end to end.
  * Producers use acks=all + idempotence, and every publish is awaited until the broker acknowledged it.
  * The consumer does NOT auto-commit. `consume_batches()` yields a Batch; the pipeline calls `batch.commit()` only after every
    log in it was normalized AND its ECS document was acknowledged by the broker (or dead-lettered). A crash before the commit
    re-reads the batch; event.id is derived from topic/partition/offset (or carried in a header), so the re-read produces the same
    ids and downstream writes are idempotent.
In-memory mode is for development: a full queue refuses new logs (the caller is told) and a restart loses what was queued.
"""
import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import AsyncIterator, Awaitable, Callable, Protocol

from ..config import Settings
from .envelope import IngestMeta

log = logging.getLogger("logunify.bus")

try:                                                    # optional speed-up for the hot serialisation path
    import orjson

    def dumps(o) -> bytes:
        return orjson.dumps(o, default=str)
except ImportError:                                     # pragma: no cover
    def dumps(o) -> bytes:
        return json.dumps(o, separators=(",", ":"), default=str).encode()


@dataclass
class Item:
    raw: bytes
    hint: str | None
    meta: IngestMeta = field(default_factory=IngestMeta)


async def _noop() -> None:
    return None


@dataclass
class Batch:
    items: list[Item]
    commit: Callable[[], Awaitable[None]] = _noop


class RawBus(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def publish(self, item: Item) -> bool: ...
    async def publish_many(self, items: list[Item]) -> list[bool]: ...
    async def publish_ecs_many(self, docs: list[dict]) -> list[Exception | None]: ...
    async def send_ecs(self, docs: list[dict]) -> list: ...
    async def wait_acks(self, handles: list) -> list[Exception | None]: ...
    def consume_batches(self, max_records: int, wait_s: float) -> AsyncIterator[Batch]: ...
    def depth(self) -> int: ...


class InMemoryBus:
    def __init__(self, maxsize: int):
        self._q: asyncio.Queue[Item | None] = asyncio.Queue(maxsize=maxsize)

    async def start(self) -> None: ...

    async def stop(self) -> None:
        try:
            self._q.put_nowait(None)          # wake the consumer
        except asyncio.QueueFull:
            pass

    def depth(self) -> int:
        return self._q.qsize()

    async def publish(self, item: Item) -> bool:
        try:
            self._q.put_nowait(item)
            return True
        except asyncio.QueueFull:
            return False

    async def publish_many(self, items: list[Item]) -> list[bool]:
        return [await self.publish(i) for i in items]

    async def publish_ecs_many(self, docs: list[dict]) -> list[Exception | None]:
        return [None] * len(docs)

    async def send_ecs(self, docs: list[dict]) -> list:
        return [None] * len(docs)

    async def wait_acks(self, handles: list) -> list[Exception | None]:
        return [None] * len(handles)

    async def consume_batches(self, max_records: int, wait_s: float = 0.05) -> AsyncIterator[Batch]:
        stop = False
        while not stop:
            first = await self._q.get()
            if first is None:
                return
            items = [first]
            while len(items) < max_records:
                try:
                    nxt = self._q.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if nxt is None:
                    stop = True
                    break
                items.append(nxt)
            yield Batch(items)


class KafkaBus:
    # a single document larger than the broker allows can never be delivered: dead-letter it instead of retrying forever
    _FATAL = ("MessageSizeTooLargeError", "RecordTooLargeError", "InvalidTopicError")

    def __init__(self, s: Settings):
        self._s = s
        self._producer = None
        self._consumer = None
        self._stopping = False

    async def start(self) -> None:
        from aiokafka import AIOKafkaConsumer, AIOKafkaProducer   # lazy: not needed in memory mode
        s = self._s
        self._producer = AIOKafkaProducer(bootstrap_servers=s.kafka_bootstrap, acks="all", enable_idempotence=True,
                                          linger_ms=s.kafka_linger_ms, compression_type=None if s.kafka_compression == "none" else s.kafka_compression,
                                          request_timeout_ms=s.kafka_request_timeout_ms)
        self._consumer = AIOKafkaConsumer(s.kafka_raw_topic, bootstrap_servers=s.kafka_bootstrap, group_id=s.kafka_group,
                                          auto_offset_reset="earliest", enable_auto_commit=False,
                                          max_poll_records=s.batch_max)
        await self._producer.start()
        await self._consumer.start()

    async def stop(self) -> None:
        self._stopping = True
        if self._consumer:
            await self._consumer.stop()
        if self._producer:
            await self._producer.stop()                      # flushes what is buffered

    def depth(self) -> int:
        return 0                                             # consumer lag lives in the broker, not here

    @staticmethod
    def _headers(item: Item) -> list[tuple[str, bytes]]:
        h = item.meta.to_headers()
        if item.hint:
            h.append(("format", item.hint.encode()))
        return h

    async def publish(self, item: Item) -> bool:
        return (await self.publish_many([item]))[0]

    async def publish_many(self, items: list[Item]) -> list[bool]:
        """Send all, then wait for every broker acknowledgement: batches on the wire, but never reports success unacknowledged."""
        futs: list = []
        for it in items:
            try:
                futs.append(await self._producer.send(self._s.kafka_raw_topic, it.raw, key=it.meta.event_id.encode(),
                                                      headers=self._headers(it)))
            except Exception as e:
                log.warning("raw publish rejected: %s", type(e).__name__)
                futs.append(None)
        res = await asyncio.gather(*(f for f in futs if f is not None), return_exceptions=True)
        it_res = iter(res)
        out = []
        for f in futs:
            out.append(False if f is None else not isinstance(next(it_res), BaseException))
        return out

    async def send_ecs(self, docs: list[dict]) -> list:
        """Hand documents to the producer WITHOUT waiting for the broker: returns one handle (a future, or the exception if the send
        itself was refused) per document. The caller must `wait_acks()` before committing offsets. Letting the next chunk be
        processed while earlier chunks are in flight is what keeps a durable (acks=all) pipeline from being latency-bound."""
        handles: list = []
        for d in docs:
            try:
                key = ((d.get("event") or {}).get("id") or "").encode() or None
                handles.append(await self._producer.send(self._s.kafka_ecs_topic, dumps(d), key=key))
            except Exception as e:
                handles.append(e)
        return handles

    async def wait_acks(self, handles: list) -> list[Exception | None]:
        waiting = [h for h in handles if not isinstance(h, Exception)]
        res = iter(await asyncio.gather(*waiting, return_exceptions=True)) if waiting else iter(())
        out: list[Exception | None] = []
        for h in handles:
            r = h if isinstance(h, Exception) else next(res)
            out.append(r if isinstance(r, Exception) else None)
        return out

    async def publish_ecs_many(self, docs: list[dict]) -> list[Exception | None]:
        return await self.wait_acks(await self.send_ecs(docs))

    @classmethod
    def is_fatal(cls, e: Exception) -> bool:
        return type(e).__name__ in cls._FATAL

    async def consume_batches(self, max_records: int, wait_s: float = 0.5) -> AsyncIterator[Batch]:
        from aiokafka import TopicPartition
        while not self._stopping:
            try:
                data = await self._consumer.getmany(timeout_ms=int(wait_s * 1000), max_records=max_records)
            except asyncio.CancelledError:
                raise
            except Exception as e:                       # rebalance, broker restart, coordinator change: keep trying, never die
                if self._stopping:
                    return
                log.warning("Kafka poll failed (%s); retrying", type(e).__name__)
                await asyncio.sleep(1.0)
                continue
            if not data:
                continue
            items: list[Item] = []
            ends: dict[TopicPartition, int] = {}
            for tp, msgs in data.items():
                for m in msgs:
                    meta = IngestMeta.from_headers(m.headers, (m.topic, m.partition, m.offset))
                    hint = next((v.decode() for k, v in (m.headers or []) if k == "format"), None)
                    items.append(Item(m.value, hint, meta))
                ends[tp] = msgs[-1].offset + 1

            async def commit(ends=ends) -> None:
                await self._consumer.commit(ends)

            yield Batch(items, commit)


def make_bus(s: Settings) -> RawBus:
    return KafkaBus(s) if s.kafka_enabled else InMemoryBus(s.queue_max)
