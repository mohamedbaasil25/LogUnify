import time
from collections import Counter, deque


class MetricsRegistry:
    """In-process pipeline counters. Single event loop => no locking needed."""

    def __init__(self, history_seconds: int = 900):
        self._history = history_seconds
        self._buckets: deque[list[int]] = deque()      # [epoch_second, processed_count]
        self.started_at = time.time()
        self.received = 0
        self.processed = 0
        self.bytes_in = 0            # raw bytes of successfully processed logs
        self.bytes_out = 0           # zlib-compressed ECS bytes of those logs
        self.raw_bytes_received = 0  # raw bytes of everything received, incl. dropped
        self.dropped: Counter[str] = Counter()          # refused AT THE DOOR (oversize, queue overflow): the caller was told
        self.dead_lettered: Counter[str] = Counter()    # accepted but not normalized: kept in the dead-letter store, replayable
        self.ecs_publish_retries = 0
        self.consumer_restarts = 0
        self.schema_violations: Counter[str] = Counter()   # ECS validation findings by rule:field
        self.dead_after_normalize = 0
        self.by_format: Counter[str] = Counter()
        self.anomalies = 0           # logs scoring above the alert threshold (MITRE-tagged)
        self.batches_sealed = 0      # Merkle batches
        self.batches_anchored = 0
        self.pii_redactions: Counter[str] = Counter()   # values masked, by PII type (never the values themselves)
        self.pii_failures = 0                           # logs whose redaction raised (fail-closed: text was blanked)

    def record_received(self, nbytes: int) -> None:
        self.received += 1
        self.raw_bytes_received += nbytes

    def record_processed(self, fmt: str, raw_bytes: int, compressed_bytes: int) -> None:
        self.processed += 1
        self.bytes_in += raw_bytes
        self.bytes_out += compressed_bytes
        self.by_format[fmt] += 1
        now = int(time.time())
        if self._buckets and self._buckets[-1][0] == now:
            self._buckets[-1][1] += 1
        else:
            self._buckets.append([now, 1])
        while self._buckets and self._buckets[0][0] < now - self._history:
            self._buckets.popleft()

    def record_dropped(self, reason: str) -> None:
        self.dropped[reason] += 1

    def record_dead_lettered(self, reason: str, after_normalize: bool = False) -> None:
        self.dead_lettered[reason] += 1
        if after_normalize:                      # was already counted as normalized, then failed to publish
            self.dead_after_normalize += 1

    # ---- derived views -------------------------------------------------
    def rate(self, window: int) -> float:
        """Processed events per second over the last `window` seconds."""
        now = int(time.time())
        n = sum(c for s, c in self._buckets if s > now - window)
        return round(n / window, 2)

    def series(self, seconds: int) -> list[dict]:
        seconds = max(1, min(seconds, self._history))
        now = int(time.time())
        counts = {s: c for s, c in self._buckets}
        return [{"ts": s, "count": counts.get(s, 0)} for s in range(now - seconds + 1, now + 1)]

    @property
    def compression_ratio(self) -> float:
        return round(self.bytes_in / self.bytes_out, 3) if self.bytes_out else 0.0

    def reconciliation(self, in_flight: int = 0) -> dict:
        """Conservation check: every log the door accepted must be normalized, dead-lettered, or still in flight.
        accepted = received - dropped_at_door. `unaccounted` is meaningful when quiescent and on the in-memory bus (with Kafka,
        replays after a crash legitimately make processed exceed accepted)."""
        dropped = sum(self.dropped.values())
        accepted = self.received - dropped
        done = self.processed + sum(self.dead_lettered.values()) - self.dead_after_normalize
        return {"received": self.received, "dropped_at_door": dropped, "accepted": accepted, "normalized": self.processed,
                "dead_lettered": sum(self.dead_lettered.values()), "in_flight": in_flight, "unaccounted": accepted - done - in_flight}

    def summary(self) -> dict:
        dropped_total = sum(self.dropped.values())
        return {
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "received": self.received,
            "processed": self.processed,
            "dropped": dropped_total,
            "consumer_restarts": self.consumer_restarts,
            "dead_lettered": sum(self.dead_lettered.values()),
            "dead_lettered_by_reason": dict(self.dead_lettered),
            "reconciliation": self.reconciliation(),
            "drop_rate": round(dropped_total / self.received, 4) if self.received else 0.0,
            "throughput_eps": {"1s": self.rate(1), "10s": self.rate(10), "60s": self.rate(60)},
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "compression_ratio": self.compression_ratio,
            "by_format": dict(self.by_format),
            "anomalies": self.anomalies,
            "schema_violations": dict(self.schema_violations.most_common(20)),
            "pii": {"redactions": dict(self.pii_redactions), "failures": self.pii_failures},
            "integrity": {"batches_sealed": self.batches_sealed, "batches_anchored": self.batches_anchored},
        }
