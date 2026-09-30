"""Example downstream consumer: reads zstd frames from the SIEM topic and prints one NDJSON envelope per log.

    python scripts/consume_siem.py --topic logunify.siem --max 20

Shows how a SIEM ingester decodes the output: every Kafka message value is one zstd frame (magic 28 B5 2F FD)
holding newline-delimited JSON envelopes {"ts": <epoch ms>, "fp": <fingerprint>, "raw": <original log>}.
"""
import argparse
import json
import sys
from pathlib import Path

from confluent_kafka import Consumer

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from logunify_flink.codec import read_frame  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--bootstrap", default="localhost:9092")
ap.add_argument("--topic", default="logunify.siem")
ap.add_argument("--group", default="siem-ingest")
ap.add_argument("--max", type=int, default=0, help="stop after N records (0 = run until interrupted)")
a = ap.parse_args()

c = Consumer({"bootstrap.servers": a.bootstrap, "group.id": a.group, "auto.offset.reset": "earliest",
              "broker.address.family": "v4"})
c.subscribe([a.topic])
n = 0
try:
    while not a.max or n < a.max:
        m = c.poll(1.0)
        if m is None or m.error():
            continue
        for rec in read_frame(m.value()):
            print(json.dumps(rec, ensure_ascii=False))
            n += 1
            if a.max and n >= a.max:
                break
except KeyboardInterrupt:
    pass
finally:
    c.close()
