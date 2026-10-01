"""Ingest envelope: the facts about a raw log that must be fixed at the door and survive every later stage.

Traceability contract (what lets an auditor walk from a normalized document back to the exact bytes received):
  event.id        UUIDv7 minted when the log is first accepted (sortable by time). Logs that arrive on the Kafka raw topic from a
                  producer that did not set one get a deterministic UUIDv5 of topic/partition/offset, so re-reading the same
                  Kafka record always yields the same id (a replay can never create a second identity).
  event.hash      SHA-256 of the raw bytes exactly as received (ECS `event.hash`: "hash of raw field ... to demonstrate log integrity").
  event.created   when the log was received (ECS), as opposed to event.ingested (when it was processed) and @timestamp (when it happened).
  logunify.*      source id, transport, Kafka origin (topic/partition/offset) or network peer, parser name + version.
The normalized document is what the Merkle tree seals, and it contains event.id and event.hash, so the ledger anchor covers the link
to the raw log. `event.original` is the REDACTED text when PII redaction changed it (flag `logunify.raw.redacted`); the unredacted bytes
live only in the encrypted raw archive (app/archive), whose records are verified against event.hash.
"""
import hashlib
import os
import time
import uuid
from dataclasses import dataclass, field

_NS = uuid.UUID("6f1d6c53-4b0e-4b6f-9d5b-0c9a1c1f5a10")        # fixed namespace for deterministic ids (UUIDv5)


def uuid7(ms: int | None = None) -> str:
    """RFC 9562 UUIDv7: 48-bit unix-ms timestamp, then random bits. Time-sortable, no coordination between workers needed."""
    ms = int(time.time() * 1000) if ms is None else ms
    b = bytearray(ms.to_bytes(6, "big") + os.urandom(10))
    b[6] = (b[6] & 0x0F) | 0x70                                  # version 7
    b[8] = (b[8] & 0x3F) | 0x80                                  # RFC 4122 variant
    return str(uuid.UUID(bytes=bytes(b)))


def kafka_event_id(topic: str, partition: int, offset: int) -> str:
    return str(uuid.uuid5(_NS, f"kafka/{topic}/{partition}/{offset}"))


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass
class IngestMeta:
    """Travels with a raw log from the door to the normalized document (and through the Kafka raw topic as message headers)."""
    event_id: str = field(default_factory=uuid7)
    received_at: float = field(default_factory=time.time)
    source_id: str | None = None
    transport: str = "api"                      # http | syslog | api | kafka | replay
    tz: str | None = None                       # IANA zone for timestamps without an offset (per-source setting)
    peer: str | None = None                     # network peer address (syslog), informational only: spoofable over UDP
    kafka: tuple[str, int, int] | None = None   # (topic, partition, offset) once read from Kafka

    def to_headers(self) -> list[tuple[str, bytes]]:
        h = [("event_id", self.event_id.encode()), ("received_at", repr(self.received_at).encode()),
             ("transport", self.transport.encode())]
        for k, v in (("source_id", self.source_id), ("tz", self.tz), ("peer", self.peer)):
            if v:
                h.append((k, v.encode()))
        return h

    @classmethod
    def from_headers(cls, headers, kafka: tuple[str, int, int]) -> "IngestMeta":
        h = {k: v.decode("utf-8", "replace") for k, v in (headers or [])}
        try:
            received = float(h["received_at"])
        except (KeyError, ValueError):
            received = time.time()
        return cls(event_id=h.get("event_id") or kafka_event_id(*kafka), received_at=received, source_id=h.get("source_id"),
                   transport=h.get("transport", "kafka"), tz=h.get("tz"), peer=h.get("peer"), kafka=kafka)

    def to_fields(self, raw: bytes) -> dict:
        """Dotted ECS / logunify fields stamped on the document."""
        from datetime import datetime, timezone
        f = {"event.id": self.event_id, "event.hash": sha256_hex(raw),
             "event.created": datetime.fromtimestamp(self.received_at, timezone.utc).isoformat(),
             "logunify.transport": self.transport}
        if self.source_id:
            f["logunify.source.id"] = self.source_id
        if self.peer:
            f["logunify.origin.peer"] = self.peer
        if self.kafka:
            f["logunify.origin.kafka.topic"], f["logunify.origin.kafka.partition"], f["logunify.origin.kafka.offset"] = self.kafka
        return f
