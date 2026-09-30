"""Message-bus abstraction: Kafka in production, a bounded in-process queue for local dev/tests."""
import asyncio
import json
from typing import AsyncIterator, Protocol

from ..config import Settings

Message = tuple[bytes, str | None]   # (raw log bytes, optional format hint)


class RawBus(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def publish(self, raw: bytes, hint: str | None = None) -> bool: ...
    async def publish_ecs(self, doc: dict) -> None: ...
    def consume(self) -> AsyncIterator[Message]: ...


class InMemoryBus:
    def __init__(self, maxsize: int):
        self._q: asyncio.Queue[Message | None] = asyncio.Queue(maxsize=maxsize)

    async def start(self) -> None: ...

    async def stop(self) -> None:
        try:
            self._q.put_nowait(None)          # wake consumer
        except asyncio.QueueFull:
            pass

    async def publish(self, raw: bytes, hint: str | None = None) -> bool:
        try:
            self._q.put_nowait((raw, hint))
            return True
        except asyncio.QueueFull:
            return False

    async def publish_ecs(self, doc: dict) -> None: ...

    async def consume(self) -> AsyncIterator[Message]:
        while (item := await self._q.get()) is not None:
            yield item


class KafkaBus:
    def __init__(self, s: Settings):
        self._s = s
        self._producer = None
        self._consumer = None

    async def start(self) -> None:
        from aiokafka import AIOKafkaConsumer, AIOKafkaProducer   # lazy: not needed in memory mode
        self._producer = AIOKafkaProducer(bootstrap_servers=self._s.kafka_bootstrap, linger_ms=20,
                                          compression_type="gzip")
        self._consumer = AIOKafkaConsumer(self._s.kafka_raw_topic, bootstrap_servers=self._s.kafka_bootstrap,
                                          group_id=self._s.kafka_group, auto_offset_reset="earliest",
                                          enable_auto_commit=True)
        await self._producer.start()
        await self._consumer.start()

    async def stop(self) -> None:
        if self._consumer:
            await self._consumer.stop()
        if self._producer:
            await self._producer.stop()

    async def publish(self, raw: bytes, hint: str | None = None) -> bool:
        headers = [("format", hint.encode())] if hint else None
        try:
            await self._producer.send(self._s.kafka_raw_topic, raw, headers=headers)
            return True
        except Exception:
            return False

    async def publish_ecs(self, doc: dict) -> None:
        await self._producer.send(self._s.kafka_ecs_topic, json.dumps(doc).encode())

    async def consume(self) -> AsyncIterator[Message]:
        async for msg in self._consumer:
            hint = next((v.decode() for k, v in (msg.headers or []) if k == "format"), None)
            yield msg.value, hint


def make_bus(s: Settings) -> RawBus:
    return KafkaBus(s) if s.kafka_enabled else InMemoryBus(s.queue_max)
