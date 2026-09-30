import asyncio
import logging
from collections import deque

from ..config import Settings
from ..enrich import geoip
from ..ecs.normalizer import StreamCompressor, to_ecs
from ..integrity.batcher import BatchBuilder
from ..integrity.ledger import MockFabricLedger
from ..intel.engine import LogIntelligence
from ..parsers.base import ParseError
from ..privacy.pii import PiiRedactor
from ..threatintel.service import ThreatIntel
from ..alerting.manager import AlertManager
from ..forwarding.elasticsearch import ElasticsearchForwarder
from ..parsers.detect import parse_auto
from .bus import RawBus
from .metrics import MetricsRegistry

log = logging.getLogger("logunify.pipeline")


class Pipeline:
    """consume raw -> parse -> ECS -> metrics + ring buffer (+ ECS topic when Kafka is on)."""

    def __init__(self, bus: RawBus, metrics: MetricsRegistry, settings: Settings):
        self.bus, self.metrics, self.settings = bus, metrics, settings
        self.pii = PiiRedactor(_csv(settings.pii_types), settings.pii_mode,
                               settings.pii_hash_key.get_secret_value() if settings.pii_hash_key else None
                               ) if settings.pii_enabled else None
        self.recent: deque[dict] = deque(maxlen=settings.recent_buffer)
        self.anomalies: deque[dict] = deque(maxlen=200)
        self.intel = LogIntelligence(settings.anomaly_threshold, settings.ml_warmup,
                                     settings.ml_refit_every, settings.ml_window) if settings.intel_enabled else None
        self.ti = ThreatIntel(settings) if settings.ti_enabled else None
        self.batcher = BatchBuilder(settings.integrity_batch_size, settings.integrity_max_batches)
        self.ledger = MockFabricLedger()
        self.alerts = AlertManager(settings, evidence_locator=self.batcher.find_leaf) if settings.alerting_enabled else None
        self.forwarder = self._make_forwarder(settings)
        self._task: asyncio.Task | None = None
        self._ti_task: asyncio.Task | None = None
        self._compressor = StreamCompressor()

    @staticmethod
    def _make_forwarder(s: Settings):
        if not s.es_forward_enabled:
            return None
        if not s.es_url:
            raise ValueError("LOGUNIFY_ES_FORWARD_ENABLED needs LOGUNIFY_ES_URL")
        if s.kafka_enabled:
            log.warning("Kafka is on: if the Vector Elasticsearch sink also writes logs-logunify-*, every log is indexed twice")
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

    async def submit(self, raw: bytes, hint: str | None = None) -> bool:
        """Entry point for producers (REST ingest, mock generator). False => dropped at the door."""
        self.metrics.record_received(len(raw))
        if len(raw) > self.settings.max_raw_bytes:
            self.metrics.record_dropped("oversize")
            return False
        if not await self.bus.publish(raw, hint):
            self.metrics.record_dropped("queue_overflow")
            return False
        return True

    def process(self, raw: bytes, hint: str | None = None) -> dict | None:
        """Parse + normalize one log. Records processed/dropped metrics; returns the ECS doc or None."""
        try:
            text = raw.decode("utf-8", errors="replace")
            parsed = parse_auto(text, hint)
            self._redact_pii(parsed)
            technique = self._enrich(parsed)
            for k, v in geoip.lookup(parsed.fields.get("source.ip")).items():
                parsed.fields.setdefault(k, v)
            ti_hit = self._cross_reference(parsed)
            doc = to_ecs(parsed)
        except ParseError as e:
            self.metrics.record_dropped(f"parse_error:{_reason(e)}")
            return None
        except Exception:
            log.exception("unexpected processing failure")
            self.metrics.record_dropped("internal_error")
            return None
        self.metrics.record_processed(parsed.format, len(raw), self._compressor.size(doc))
        self.recent.append(doc)
        self._forward(doc)
        if technique:
            self.metrics.anomalies += 1
            self.anomalies.append(doc)
        if ti_hit:
            self.ti.recent.append(doc)
        self._raise_alert(doc)
        self._on_sealed(self.batcher.add(doc))
        return doc

    def _redact_pii(self, parsed) -> None:
        """Mask PII in place. Never drops the log; on failure it fails CLOSED (free text blanked, log kept)."""
        if not self.pii:
            return
        try:
            self.metrics.pii_redactions.update(self.pii.redact_parsed(parsed))
        except Exception:
            log.exception("PII redaction failed; blanking free text so nothing unredacted leaves the pipeline")
            self.metrics.pii_failures += 1
            parsed.original = parsed.message = "[PII:redaction_failed]"
            parsed.fields = {k: v for k, v in parsed.fields.items() if not isinstance(v, str)}

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

    def _enrich(self, parsed) -> str | None:
        """Drain3 + Isolation Forest enrichment. A failure here must never drop the log."""
        if not self.intel:
            return None
        try:
            return self.intel.analyze(parsed).technique
        except Exception:
            log.exception("intel enrichment failed; passing log through un-enriched")
            return None

    async def _run(self) -> None:
        async for raw, hint in self.bus.consume():
            doc = self.process(raw, hint)
            if doc is not None and self.settings.kafka_enabled:
                try:
                    await self.bus.publish_ecs(doc)
                except Exception:
                    log.exception("failed publishing ECS doc")
                    self.metrics.record_dropped("ecs_publish_failed")


def _csv(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def _reason(e: ParseError) -> str:
    return str(e).split(":")[0][:40].replace(" ", "_")
