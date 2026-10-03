import asyncio
import threading
import logging
import time
from collections import deque
from datetime import datetime, timezone

from ..config import Settings
from ..enrich import geoip
from ..ecs.normalizer import StreamCompressor, to_ecs
from ..ecs.taxonomy import categorize
from ..ecs.validate import validate
from ..integrity.batcher import BatchBuilder
from ..integrity.ledger import MockFabricLedger
from ..intel.engine import LogIntelligence
from ..parsers.base import ParseError
from ..privacy.pii import PiiRedactor
from ..threatintel.service import ThreatIntel
from ..alerting.manager import AlertManager
from ..forwarding.elasticsearch import ElasticsearchForwarder
from ..parsers.sdk import build_registry
from .bus import Item, KafkaBus, RawBus
from .dlq import DeadLetterFile
from .envelope import IngestMeta
from .metrics import MetricsRegistry
from .stream import StreamHub

log = logging.getLogger("logunify.pipeline")


class Pipeline:
    """consume raw -> parse -> redact -> enrich -> envelope -> ECS -> seal/forward/alert (+ ECS topic when Kafka is on).

    No-loss contract: a log the door accepted ends up normalized (and published), or in the dead-letter store with its raw bytes
    and envelope; it is never silently discarded. Only logs refused at the door (oversize, queue full) are dropped, and the
    caller is told. `metrics.reconciliation()` checks the books.
    """

    def __init__(self, bus: RawBus, metrics: MetricsRegistry, settings: Settings):
        self.bus, self.metrics, self.settings = bus, metrics, settings
        self.parsers = build_registry(settings.parser_dir)
        self.pii = PiiRedactor(_csv(settings.pii_types), settings.pii_mode,
                               settings.pii_hash_key.get_secret_value() if settings.pii_hash_key else None
                               ) if settings.pii_enabled else None
        self.recent: deque[dict] = deque(maxlen=settings.recent_buffer)
        self.recent_total = 0                                   # events ever appended to `recent` (monotonic: the state store saves only the new ones)
        self.recent_lock = threading.Lock()                     # append + counter move together; the state store snapshots under the same lock
        self.anomalies: deque[dict] = deque(maxlen=200)
        self.intel = LogIntelligence(settings.anomaly_threshold, settings.ml_warmup,
                                     settings.ml_refit_every, settings.ml_window) if settings.intel_enabled else None
        self.ti = ThreatIntel(settings) if settings.ti_enabled else None
        self.batcher = BatchBuilder(settings.integrity_batch_size, settings.integrity_max_batches,
                                    f"batch-{settings.worker_id}" if settings.worker_id else "batch")
        self.stream = StreamHub()
        self.dlq = DeadLetterFile(settings.dlq_path, settings.dlq_max_mb)
        self.archive = self._make_archive(settings)
        self.ledger = MockFabricLedger()
        self.source_lookup = None                               # set by the app: sid -> LogSource (tags decide `synthetic` handling)
        self.alerts = AlertManager(settings, evidence_locator=self.batcher.find_leaf) if settings.alerting_enabled else None
        self.forwarder = self._make_forwarder(settings)
        self._task: asyncio.Task | None = None
        self._ti_task: asyncio.Task | None = None
        self._compressor = StreamCompressor()
        self._n = 0

    @staticmethod
    def _make_archive(s: Settings):
        if not s.raw_archive_enabled:
            return None
        from ..archive.raw_store import ArchiveError, RawArchive, parse_key
        key = parse_key(s.raw_archive_key.get_secret_value()) if s.raw_archive_key else None
        if key is None and not s.raw_archive_allow_plaintext:
            raise ArchiveError("raw archive is enabled but LOGUNIFY_RAW_ARCHIVE_KEY is not set: refusing to store unredacted raw "
                               "logs unencrypted (set the key, or LOGUNIFY_RAW_ARCHIVE_ALLOW_PLAINTEXT=true for development)")
        return RawArchive(s.raw_archive_dir, key, s.raw_archive_segment_mb, s.raw_archive_retention_days, require_key=False)

    @staticmethod
    def _make_forwarder(s: Settings):
        if not s.es_forward_enabled:
            return None
        if not s.es_url:
            raise ValueError("LOGUNIFY_ES_FORWARD_ENABLED needs LOGUNIFY_ES_URL")
        if s.kafka_enabled:
            log.warning("Kafka is on: if the Vector Elasticsearch sink also writes logs-logunify-*, both use event.id as _id, so the "
                        "second `create` is a harmless 409, but it doubles the write load: run one of them")
        return ElasticsearchForwarder(
            s.es_url, s.es_forward_api_key.get_secret_value() if s.es_forward_api_key else None, s.es_forward_index,
            workers=s.es_forward_workers, batch_max_docs=s.es_forward_batch_docs, batch_max_bytes=s.es_forward_batch_bytes,
            flush_interval_s=s.es_forward_flush_interval_s, queue_max=s.es_forward_queue_max, max_retries=s.es_forward_max_retries,
            backoff_max_s=s.es_forward_backoff_max_s, request_timeout_s=s.es_forward_timeout_s, verify_ssl=s.es_verify_ssl,
            ca_file=s.es_forward_ca_file, allow_insecure_http=s.es_forward_allow_insecure_http,
            dlq_path=s.es_forward_dlq_path, dlq_max_mb=s.es_forward_dlq_max_mb)

    async def start(self) -> None:
        if self.forwarder:
            await self.forwarder.start()
        await self.bus.start()
        if self.alerts:
            await self.alerts.start()
        self._task = asyncio.create_task(self._run(), name="logunify-pipeline")
        if self.ti:
            self._ti_task = asyncio.create_task(self.ti.run(), name="logunify-threatintel")

    async def stop(self) -> None:
        await self.bus.stop()
        for t in (self._task, self._ti_task):
            if t:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
        if self.forwarder:
            await self.forwarder.stop()                       # after the consumer stopped: drains what was already queued
        if self.alerts:
            await self.alerts.stop()
        self.dlq.close()
        if self.archive:
            self.archive.close()

    # ---- the door ---------------------------------------------------------------------------------------------
    def _meta(self, source_id=None, transport="api", tz=None, peer=None) -> IngestMeta:
        return IngestMeta(source_id=source_id, transport=transport, tz=tz, peer=peer)

    async def submit(self, raw: bytes, hint: str | None = None, *, source_id: str | None = None, transport: str = "api",
                     tz: str | None = None, peer: str | None = None, meta: IngestMeta | None = None) -> bool:
        """Entry point for producers (REST ingest, listeners, mock generator). False => refused at the door (caller is told)."""
        return await self.submit_many([raw], hint, source_id=source_id, transport=transport, tz=tz, peer=peer,
                                      metas=[meta] if meta else None) == 1

    async def submit_many(self, raws: list[bytes], hint: str | None = None, *, source_id: str | None = None,
                          transport: str = "api", tz: str | None = None, peer: str | None = None,
                          metas: list[IngestMeta] | None = None) -> int:
        """Accept a list of raw logs; returns how many were accepted. One broker round-trip for the whole list on Kafka."""
        items: list[Item] = []
        for i, raw in enumerate(raws):
            self.metrics.record_received(len(raw))
            if len(raw) > self.settings.max_raw_bytes:
                self.metrics.record_dropped("oversize")
                continue
            items.append(Item(raw, hint, metas[i] if metas else self._meta(source_id, transport, tz, peer)))
        ok = await self.bus.publish_many(items) if items else []
        for okk in ok:
            if not okk:
                self.metrics.record_dropped("queue_overflow")
        return sum(ok)

    # ---- processing ---------------------------------------------------------------------------------------------
    def process(self, raw: bytes, hint: str | None = None, meta: IngestMeta | None = None) -> dict | None:
        """Process one log synchronously (dry-run endpoint, tests, CLI). Returns the ECS doc, or None if it was dead-lettered."""
        return self.process_batch([Item(raw, hint, meta or IngestMeta())])[0]

    def _is_synthetic(self, it: Item) -> bool:
        """True for events from a source tagged `synthetic` (test traffic): they are labelled, kept out of model learning and out of calibration."""
        sid = it.meta.source_id
        if not sid or self.source_lookup is None:
            return False
        try:
            src = self.source_lookup(sid)
        except Exception:
            return False
        return bool(src and "synthetic" in [t.lower() for t in src.tags])

    def _dead(self, it: Item, reason: str, stage: str, error: str = "", after_normalize: bool = False) -> None:
        self.metrics.record_dead_lettered(reason, after_normalize)
        self.dlq.put(it.raw, reason=reason, stage=stage, event_id=it.meta.event_id, hint=it.hint, source_id=it.meta.source_id,
                     transport=it.meta.transport, tz=it.meta.tz, error=error, received_at=it.meta.received_at)

    def process_batch(self, items: list[Item]) -> list[dict | None]:
        """Parse + normalize a batch. Slot i of the result is the ECS doc for items[i], or None if that log was dead-lettered.

        ML scoring is done once per batch (one Isolation Forest call instead of one per log), the rest is per log with per-log
        failure isolation: one bad log can never take the rest of the batch down with it.
        """
        out: list[dict | None] = [None] * len(items)
        staged: list[tuple[int, object, int]] = []                  # (slot, ParsedLog, redactions)
        for i, it in enumerate(items):
            try:
                parsed = self.parsers.parse(it.raw.decode("utf-8", errors="replace"), it.hint)
                staged.append((i, parsed, self._redact_pii(parsed)))
            except ParseError as e:
                self._dead(it, f"parse_error:{_reason(e)}", "parse", str(e))
            except Exception as e:
                log.exception("unexpected failure while parsing")
                self._dead(it, "internal_error", "parse", repr(e))
        synthetic = {i: self._is_synthetic(items[i]) for i, _, _ in staged}
        techniques = self._enrich_many([p for _, p, _ in staged], [synthetic[i] for i, _, _ in staged])
        for (i, parsed, n_red), technique in zip(staged, techniques):
            it = items[i]
            try:
                for k, v in geoip.lookup(parsed.fields.get("source.ip")).items():
                    parsed.fields.setdefault(k, v)
                ti_hit = self._cross_reference(parsed)
                self._stamp(parsed, it, n_red)
                if synthetic[i]:
                    parsed.fields["labels.synthetic"] = "true"
                doc = to_ecs(parsed, tz=it.meta.tz or self.settings.default_timezone,
                             received=datetime.fromtimestamp(it.meta.received_at, timezone.utc))
            except Exception as e:
                log.exception("unexpected failure while normalizing")
                self._dead(it, "internal_error", "normalize", repr(e))
                continue
            if self.settings.taxonomy_mode != "off" and self._schema_violations(it, parsed, doc):
                continue                                                       # strict mode: dead-lettered, replayable
            self._record(it, parsed, doc, technique, ti_hit)
            out[i] = doc
        return out

    def _schema_violations(self, it: Item, parsed, doc: dict) -> bool:
        """ECS validation. warn: count by rule+field and log the first occurrence; strict: dead-letter. True = log was dead-lettered."""
        try:
            viol = validate(doc)
        except Exception:
            log.exception("schema validation crashed; passing the log through")
            return False
        if not viol:
            return False
        sv = self.metrics.schema_violations
        for rule, fld, detail in viol:
            key = f"{rule}:{fld}"
            if key not in sv and len(sv) >= 500:
                key = "other"                                                   # bound the cardinality of the counter
            if key not in sv:
                log.warning("ECS violation (first seen) parser=%s %s %s: %s", parsed.parser or parsed.format, rule, fld, detail)
            sv[key] += 1
        if self.settings.taxonomy_mode == "strict":
            self._dead(it, f"schema_violation:{viol[0][0]}", "validate", "; ".join(f"{r} {f}: {d}" for r, f, d in viol[:3]))
            return True
        return False

    def _stamp(self, parsed, it: Item, n_red: int) -> None:
        """Envelope: identity + integrity link to the raw bytes, parser identity, taxonomy. Applied after redaction on purpose."""
        categorize(parsed.fields, parsed.parser or parsed.format)
        parsed.fields.update(it.meta.to_fields(it.raw))
        parsed.fields["logunify.parser.name"] = parsed.parser or parsed.format
        if parsed.parser_version:
            parsed.fields["logunify.parser.version"] = parsed.parser_version
        if n_red:
            parsed.fields["logunify.raw.redacted"] = True          # event.original differs from the received bytes (PII masked)

    def _record(self, it: Item, parsed, doc: dict, technique, ti_hit) -> None:
        m = self.metrics
        self._n += 1
        # compression ratio is an estimate: the first 64 documents are compressed exactly, then every 8th one counted x8
        # (running zlib on every log costs a large share of the CPU)
        n = self._n
        m.record_processed(parsed.format, len(it.raw),
                           self._compressor.size(doc) if n <= 64 else (self._compressor.size(doc) * 8 if n % 8 == 0 else 0))
        with self.recent_lock:
            self.recent.append(doc)
            self.recent_total += 1
        self.stream.publish(doc)
        if self.archive:
            self._archive(it, doc)
        self._forward(doc)
        if technique:
            m.anomalies += 1
            self.anomalies.append(doc)
        if ti_hit:
            self.ti.recent.append(doc)
        self._raise_alert(doc)
        self._on_sealed(self.batcher.add(doc))

    def _archive(self, it: Item, doc: dict) -> None:
        try:
            self.archive.put(it.meta.event_id, it.raw, doc)
        except Exception:
            log.exception("raw archive hand-off failed; the log itself is unaffected")

    def _redact_pii(self, parsed) -> int:
        """Mask PII in place; returns how many values were masked. Never drops the log; on failure it fails CLOSED (free text
        blanked, log kept)."""
        if not self.pii:
            return 0
        try:
            found = self.pii.redact_parsed(parsed)
            self.metrics.pii_redactions.update(found)
            return sum(found.values())
        except Exception:
            log.exception("PII redaction failed; blanking free text so nothing unredacted leaves the pipeline")
            self.metrics.pii_failures += 1
            parsed.original = parsed.message = "[PII:redaction_failed]"
            parsed.fields = {k: v for k, v in parsed.fields.items() if not isinstance(v, str)}
            return 1

    def _forward(self, doc: dict) -> None:
        """Hand the ECS document to the Elasticsearch forwarder (non-blocking). A failure here must never drop the log."""
        if not self.forwarder:
            return
        try:
            self.forwarder.submit(doc)
        except Exception:
            log.exception("forwarder hand-off failed; the log itself is unaffected")

    def _raise_alert(self, doc: dict) -> None:
        """Critical-alert check. Like every enrichment step, a failure here must never drop the log."""
        if not self.alerts:
            return
        try:
            self.alerts.on_event(doc)
        except Exception:
            log.exception("alerting failed for one event; the log itself is unaffected")

    def _cross_reference(self, parsed) -> bool:
        """MISP / IOC cross-reference. Like the ML step, a failure here must never drop the log."""
        if not self.ti:
            return False
        try:
            return bool(self.ti.enrich(parsed))
        except Exception:
            log.exception("threat-intel cross-reference failed; passing log through")
            return False

    # ---- integrity -----------------------------------------------------
    def _on_sealed(self, batch) -> None:
        if batch is None:
            return
        self.metrics.batches_sealed += 1
        if self.settings.integrity_auto_anchor:
            self.anchor_batch(batch)

    def seal_partial(self):
        batch = self.batcher.seal_partial()
        self._on_sealed(batch)
        return batch

    def anchor_batch(self, batch):
        """Commit the batch root to the (mock) ledger; idempotent."""
        if batch.anchor is None:
            batch.anchor = self.ledger.submit_anchor(batch.id, batch.root)
            self.metrics.batches_anchored += 1
        return batch.anchor

    def _enrich_many(self, parsed_list: list, no_learn: list | None = None) -> list:
        """Drain3 + Isolation Forest + MITRE for a batch. A failure here must never drop a log: fall back to per-log, then to none."""
        if not self.intel or not parsed_list:
            return [None] * len(parsed_list)
        try:
            return [a.technique for a in self.intel.analyze_many(parsed_list, no_learn)]
        except Exception:
            log.exception("batch intel enrichment failed; retrying log by log")
        out = []
        for p in parsed_list:
            try:
                out.append(self.intel.analyze(p).technique)
            except Exception:
                log.exception("intel enrichment failed; passing log through un-enriched")
                out.append(None)
        return out

    async def _run(self) -> None:
        """Supervisor: if the consumer loop itself ever dies (a bug, a library error), log it, back off and start it again. The
        process must not stay 'up' with nothing consuming (that is what /ready exists to expose)."""
        delay = 1.0
        while True:
            try:
                await self._consume()
                return                                              # the bus ended normally (shutdown)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.metrics.consumer_restarts += 1
                log.exception("consumer loop crashed; restarting in %.0fs (restart #%d)", delay, self.metrics.consumer_restarts)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30.0)

    async def _consume(self) -> None:
        cfg = self.settings
        async for batch in self.bus.consume_batches(cfg.batch_max, cfg.kafka_batch_wait_s):
            try:
                await self._handle_batch(batch)
            except asyncio.CancelledError:
                raise
            except Exception:                                       # last-resort net: keep the raw logs, then move on
                log.exception("batch handling failed unexpectedly; dead-lettering the batch")
                for it in batch.items:
                    self._dead(it, "batch_error", "pipeline")
            try:
                await batch.commit()                                # Kafka: offsets advance only now
            except Exception:
                log.exception("offset commit failed; the batch will be re-read (idempotent downstream)")

    @property
    def consumer_alive(self) -> bool:
        return self._task is not None and not self._task.done()

    async def _handle_batch(self, batch) -> None:
        step = max(1, self.settings.process_chunk)
        sent: list[tuple[Item, dict, object]] = []                  # (item, doc, broker handle) not yet acknowledged
        for i in range(0, len(batch.items), step):
            part = batch.items[i:i + step]
            docs = self.process_batch(part)
            if self.settings.kafka_enabled:
                live = [(it, d) for it, d in zip(part, docs) if d is not None]
                handles = await self.bus.send_ecs([d for _, d in live])      # does not wait: the next chunk is processed meanwhile
                sent += [(it, d, h) for (it, d), h in zip(live, handles)]
            await asyncio.sleep(0)                                  # yield: alert notifications / API stay responsive
        if sent:                                                    # one wait for the whole fetched batch, before the offsets commit
            errs = await self.bus.wait_acks([h for _, _, h in sent])
            failed = [(it, d, e) for (it, d, _), e in zip(sent, errs) if e is not None]
            if failed:
                await self._publish_ecs([it for it, _, _ in failed], [d for _, d, _ in failed])     # retry loop, only the failures

    async def _publish_ecs(self, part: list[Item], docs: list[dict | None]) -> None:
        """Publish normalized docs to the ECS topic and WAIT for the broker's acknowledgement. Transient broker trouble is retried
        (the offsets are not committed meanwhile, so nothing can be lost); after `kafka_publish_max_wait_s` or for a document the
        broker will never accept, the raw log goes to the dead-letter store."""
        live = [(it, d) for it, d in zip(part, docs) if d is not None]
        deadline, delay = time.monotonic() + self.settings.kafka_publish_max_wait_s, 0.5
        while live:
            errs = await self.bus.publish_ecs_many([d for _, d in live])
            retry = []
            for (it, d), e in zip(live, errs):
                if e is None:
                    continue
                if KafkaBus.is_fatal(e):
                    self._dead(it, "ecs_publish_rejected", "publish", repr(e), after_normalize=True)
                else:
                    retry.append((it, d))
            if not retry:
                return
            if time.monotonic() >= deadline:
                for it, _ in retry:
                    self._dead(it, "ecs_publish_failed", "publish", "broker unavailable past the retry window", after_normalize=True)
                return
            self.metrics.ecs_publish_retries += len(retry)
            log.warning("ECS publish: %d documents not acknowledged, retrying in %.1fs", len(retry), delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 10.0)
            live = retry

    # ---- dead-letter replay ----------------------------------------------------------------------------------------
    async def replay_dlq(self, limit: int = 1000) -> dict:
        """Re-submit dead-lettered logs (after fixing the parser / mapping). The original event.id is kept: idempotent."""
        recs = await asyncio.to_thread(self.dlq.take, limit)
        resubmitted, back = 0, []
        for r in recs:
            meta = IngestMeta(event_id=r["event_id"], received_at=r.get("received_at") or time.time(), source_id=r.get("source_id"),
                              transport="replay", tz=r.get("tz"))
            if await self.submit(r["raw"], r.get("hint"), meta=meta):
                resubmitted += 1
            else:
                back.append(r)
        if back:
            self.dlq.give_back(back)
        return {"taken": len(recs), "resubmitted": resubmitted, "returned_to_dlq": len(back)}


def _csv(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def _reason(e: ParseError) -> str:
    return str(e).split(":")[0][:40].replace(" ", "_")
