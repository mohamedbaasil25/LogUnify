"""In-process throughput benchmark of the normalization pipeline (no network, no Kafka).

    python scripts/bench_pipeline.py [--n 20000] [--chunk 32]

Reports events/second for the full pipeline and with expensive stages switched off, one core, mock logs. It measures
`Pipeline.process_batch` (what the consumer loop runs); it is a CPU ceiling for ONE worker, not an end-to-end figure: Kafka,
the ES forwarder and the Merkle ledger are outside it. Divide your target EPS by this number (and by your safety margin) for
the worker count; with Kafka, workers need at least that many partitions.
"""
import argparse
import logging
import os
import random
import sys
import time
from pathlib import Path

os.environ.setdefault("LOGUNIFY_AUDIT_DB_PATH", ":memory:")
os.environ.setdefault("LOGUNIFY_STATE_DB_PATH", ":memory:")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
logging.disable(logging.CRITICAL)

from app.config import Settings                      # noqa: E402
from app.mock.generators import gen_cef, gen_json, gen_syslog   # noqa: E402
from app.pipeline.bus import InMemoryBus, Item       # noqa: E402
from app.pipeline.metrics import MetricsRegistry     # noqa: E402
from app.pipeline.processor import Pipeline          # noqa: E402


def run(label: str, lines: list[bytes], chunk: int, **kw) -> float:
    import tempfile
    s = Settings(alert_db_path=":memory:", mock_enabled=False, dlq_path=os.path.join(tempfile.mkdtemp(), "dlq.jsonl"), **kw)
    p = Pipeline(InMemoryBus(10), MetricsRegistry(), s)
    items = [Item(raw, None) for raw in lines]
    for i in range(0, 400, chunk):                    # warm-up: model fit, caches
        p.process_batch(items[i:i + chunk])
    t0 = time.perf_counter()
    for i in range(400, len(items), chunk):
        p.process_batch(items[i:i + chunk])
    eps = (len(items) - 400) / (time.perf_counter() - t0)
    print(f"{label:44s} {eps:9.0f} events/s   ({eps * 86400 / 1e6:8.0f} M/day per core)")
    return eps


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--chunk", type=int, default=32)
    a = ap.parse_args()
    random.seed(1)
    lines = [random.choice((gen_syslog, gen_json, gen_cef))().encode() for _ in range(a.n)]
    print(f"{a.n} mixed syslog/JSON/CEF logs, chunk={a.chunk}, python {sys.version.split()[0]}")
    run("full pipeline (defaults)", lines, a.chunk)
    run("  batch size 1 (the old per-log path)", lines, 1)
    run("  ML scoring off", lines, a.chunk, intel_enabled=False)
    run("  ML + threat intel + alerting off", lines, a.chunk, intel_enabled=False, ti_enabled=False, alerting_enabled=False)
    run("  PII redaction off", lines, a.chunk, pii_enabled=False)


if __name__ == "__main__":
    main()
