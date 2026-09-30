"""Flink operators. Kept thin: every decision is made by the pure-Python modules next to this file.

Element types along the pipeline
    source            str                       raw log (Kafka record timestamp = event time)
    Prepare           (fp, ts_ms, raw)          after noise filter + fingerprint
    Dedup             (ts_ms, fp, raw)          first occurrence per fingerprint per window
        side output   str (JSON)                suppression summary, emitted when a window closes
    ToShard           (shard, envelope, ts_ms)  frame mode only
    ZstdBatcher       str                       latin-1 view of one zstd frame (see codec.py)
"""
import json
import time

from pyflink.common import Types
from pyflink.datastream import KeyedProcessFunction, MapFunction, OutputTag, ProcessFunction
from pyflink.datastream.state import ListStateDescriptor, ValueStateDescriptor

from .codec import FrameWriter, envelope, to_wire
from .fingerprint import fingerprint
from .noise import NoiseFilter

SUMMARY_TAG = OutputTag("dedup-summary", Types.STRING())
PREPARED_TYPE = Types.TUPLE([Types.STRING(), Types.LONG(), Types.STRING()])
DEDUPED_TYPE = Types.TUPLE([Types.LONG(), Types.STRING(), Types.STRING()])
SHARDED_TYPE = Types.TUPLE([Types.INT(), Types.STRING(), Types.LONG()])


class Prepare(ProcessFunction):
    """Noise filter + fingerprint. Dropped logs are counted per reason (metric group `reason`)."""

    def __init__(self, drop_debug: bool):
        self._drop_debug = drop_debug

    def open(self, runtime_context):
        self._filter = NoiseFilter(drop_debug=self._drop_debug)
        self._mg = runtime_context.get_metrics_group()
        self._in = self._mg.counter("raw_in")
        self._kept = self._mg.counter("kept")
        self._dropped: dict = {}

    def process_element(self, value, ctx):
        self._in.inc()
        why = self._filter.reason(value)
        if why:
            c = self._dropped.get(why)
            if c is None:
                c = self._dropped[why] = self._mg.add_group("reason", why).counter("noise_dropped")
            c.inc()
            return
        ts = ctx.timestamp()
        self._kept.inc()
        yield fingerprint(value), (ts if ts is not None else int(time.time() * 1000)), value


class Dedup(KeyedProcessFunction):
    """Per-fingerprint tumbling window that starts at the first occurrence.

    First event passes. Later events with ts < first_ts + window are suppressed and counted. When the window
    closes a summary (fingerprint, suppressed count, sample) goes to the side output so the SIEM can still see
    the true volume. Correctness never depends on timer timing: a late-firing timer is caught in
    process_element, which closes the stale window itself.
    """

    def __init__(self, window_ms: int, sample_chars: int = 200):
        self._w, self._sample = window_ms, sample_chars

    def open(self, runtime_context):
        self._state = runtime_context.get_state(ValueStateDescriptor(
            "window", Types.TUPLE([Types.LONG(), Types.LONG(), Types.STRING()])))   # first_ts, suppressed, sample
        mg = runtime_context.get_metrics_group()
        self._passed, self._suppressed = mg.counter("dedup_passed"), mg.counter("dedup_suppressed")

    @staticmethod
    def _summary(fp, first_ts, window_ms, suppressed, sample) -> str:
        return json.dumps({"fingerprint": fp, "first_seen_ms": first_ts, "window_ms": window_ms,
                           "suppressed": suppressed, "sample": sample}, separators=(",", ":"), ensure_ascii=False)

    def process_element(self, value, ctx):
        fp, ts, raw = value
        st = self._state.value()
        if st is not None:
            first_ts, suppressed, sample = st
            if ts < first_ts + self._w:                       # duplicate (also earlier-stamped stragglers)
                self._state.update((first_ts, suppressed + 1, sample))
                self._suppressed.inc()
                return
            if suppressed > 0:                                # old window elapsed, its timer hasn't fired yet
                yield SUMMARY_TAG, self._summary(fp, first_ts, self._w, suppressed, sample)
            ctx.timer_service().delete_event_time_timer(first_ts + self._w)
        self._state.update((ts, 0, raw[:self._sample]))
        ctx.timer_service().register_event_time_timer(ts + self._w)
        self._passed.inc()
        yield ts, fp, raw

    def on_timer(self, timestamp, ctx):
        st = self._state.value()
        if st is not None and st[0] + self._w <= timestamp:   # ignore stale timers from replaced windows
            if st[1] > 0:
                yield SUMMARY_TAG, self._summary(ctx.get_current_key(), st[0], self._w, st[1], st[2])
            self._state.clear()


class ToShard(MapFunction):
    """(ts, fp, raw) -> (shard, envelope, ts). The shard key gives the batcher timers a keyed scope."""

    def __init__(self, shards: int):
        self._shards = shards

    def map(self, value):
        ts, fp, raw = value
        return int(fp[:8], 16) % self._shards, envelope(ts, fp, raw), ts


class ToEnvelope(MapFunction):
    def map(self, value):
        ts, fp, raw = value
        return envelope(ts, fp, raw)


class ZstdBatcher(KeyedProcessFunction):
    """Buffers envelopes per shard and emits one zstd frame when a size limit or linger timer trips.

    Flush triggers: record count, uncompressed bytes, a processing-time timer (latency bound while traffic
    flows) and an event-time timer (fires on the final watermark, so a bounded run or `stop --drain` never
    strands a partial batch). The buffer lives in checkpointed list state.
    """

    def __init__(self, max_records: int, max_bytes: int, linger_ms: int, level: int):
        self._max_records, self._max_bytes, self._linger, self._level = max_records, max_bytes, linger_ms, level

    def open(self, runtime_context):
        self._buf = runtime_context.get_list_state(ListStateDescriptor("buf", Types.STRING()))
        self._meta = runtime_context.get_state(ValueStateDescriptor("meta", Types.TUPLE([Types.LONG(), Types.LONG()])))
        self._writer = FrameWriter(self._level)
        mg = runtime_context.get_metrics_group()
        self._frames, self._raw_bytes, self._zst_bytes = (
            mg.counter("frames_out"), mg.counter("frame_bytes_uncompressed"), mg.counter("frame_bytes_compressed"))

    def process_element(self, value, ctx):
        _shard, env, ts = value
        self._buf.add(env)
        n, b = self._meta.value() or (0, 0)
        n, b = n + 1, b + len(env.encode("utf-8"))
        if n == 1:                                            # buffer just became non-empty: arm both timers
            ts_svc = ctx.timer_service()
            ts_svc.register_processing_time_timer(ts_svc.current_processing_time() + self._linger)
            ts_svc.register_event_time_timer((ctx.timestamp() or ts) + self._linger)
        if n >= self._max_records or b >= self._max_bytes:
            yield from self._flush()
        else:
            self._meta.update((n, b))

    def on_timer(self, timestamp, ctx):
        yield from self._flush()

    def _flush(self):
        lines = list(self._buf.get())
        if not lines:
            return
        frame = self._writer.compress(lines)
        self._buf.clear()
        self._meta.clear()
        self._frames.inc()
        self._raw_bytes.inc(sum(len(x.encode("utf-8")) for x in lines))
        self._zst_bytes.inc(len(frame))
        yield to_wire(frame)
