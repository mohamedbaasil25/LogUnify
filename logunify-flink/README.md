# LogUnify Flink: SIEM-prep stream job (PyFlink)

Consumes raw logs from Kafka, drops noise, deduplicates within a 5-minute window, compresses with **zstd**, and
publishes to a downstream Kafka topic for SIEM ingestion.

```
logunify.raw ─► noise filter ─► fingerprint ─► keyBy(fp) ─► Dedup (5 min, event time) ─┬─► zstd micro-batch ─► logunify.siem
 (any format)   drop chatter/    mask volatile                first passes, repeats     │    (frames of NDJSON)
                debug/empty      fields only                  counted                   └─► summaries ─► logunify.siem.dedup-stats
```

## Behaviour

**Noise filter** (`noise.py`): drops empty lines, health checks / heartbeats / keep-alives / cron session chatter,
and debug-level logs (syslog severity 7, JSON `level: debug|trace`, `DEBUG`/`TRACE` prefixes). A **security guard runs
first**: anything mentioning failed/denied/unauthorized/root/sudo/attack/malware/… is never dropped, even if it also
looks like chatter or debug (`<15>… authentication failed for admin` is kept).

**Deduplication** (`fingerprint.py`, `functions.Dedup`): fingerprint = BLAKE2b of the log with only volatile fields
masked (timestamps, epochs, PIDs, ephemeral `port N`/`spt=`, CEF `rt/start/end`; JSON keys `timestamp`, `request_id`,
`trace_id`, `latency_ms`, …). IPs, users, hosts, messages and syslog severity are **not** masked, so two different
attackers are never merged. Per fingerprint, a window opens at the first occurrence (event time = Kafka record
timestamp): the first log passes, repeats inside the window are suppressed. When the window closes, a summary
`{fingerprint, first_seen_ms, window_ms, suppressed, sample}` goes to the stats topic so the SIEM can still see the real
volume of a flood. An event after the window opens a new one.

**Output** (`--compression frame`, default): survivors are wrapped as NDJSON envelopes
`{"ts": <epoch ms>, "fp": <fingerprint>, "raw": <original log>}`, buffered per shard, and emitted as **one zstd frame per
Kafka message** (flush at 500 records / 512 KiB, by a 1 s processing-time linger, and on the final watermark so a bounded
run or `stop --drain` never strands a partial batch). Every message value starts with the zstd magic `28 B5 2F FD`;
`scripts/consume_siem.py` shows the decode. Alternative `--compression kafka`: plain envelopes with the Kafka producer's
own `compression.type=zstd` (transparent to consumers; needs the `zstd-jni` jar).

## Run

Requires Java 11/17 and Python 3.8-3.11 (PyFlink 1.20.1). On Windows, **put the venv first on PATH** (Flink launches
workers as `python`, and a venv path containing spaces can't be passed to it; the job says so if PATH is wrong).

```bash
pip install -r requirements.txt
# jars/: flink-sql-connector-kafka-3.3.0-1.20.jar (Maven Central), plus zstd-jni-1.5.6-4.jar for --compression kafka
python -m logunify_flink.job --bootstrap localhost:9092 --in-topic logunify.raw --out-topic logunify.siem
python scripts/consume_siem.py --topic logunify.siem --max 20
```
`python -m logunify_flink.job --help` lists every option (window, batch limits, zstd level, `--bounded`,
`--delivery exactly_once`, parallelism, checkpoint interval). To submit to a cluster: `flink run -py logunify_flink/job.py -pyfs logunify_flink ...`
with the connector jar in `lib/`. The LogUnify backend already publishes raw logs to `logunify.raw`; Flink ignores its `format` header.

## Tests
```bash
python -m pytest tests -q          # 27 pure-Python + 6 real Flink mini-cluster runs (event time, in-memory source)
python scripts/e2e.py --streaming  # needs a Kafka broker on localhost:9092; add --delivery exactly_once
```
Verified here against a real single-node Kafka 3.9.1 (KRaft) on Windows: workload of 2,401 events → **2,005** records
(4 attackers × 50 repeats collapsed to 4 + 1 re-pass after the window, 2,000 distinct logins kept, 200 noise lines
dropped), exactly **196** suppressed and reported in 4 summaries, 251 KB in → 65 KB of zstd frames (12 Kafka
messages); the same counts in `kafka` mode and with `exactly_once` (read_committed consumer); an unbounded job with
checkpointing delivered frames through the linger flush and stayed running.

## Operating notes
- **State size** = distinct fingerprints per window × ~(100 B + `--summary-sample-chars`). At millions of unique logs per
  5 min use the RocksDB state backend (`state.backend.type: rocksdb`) and lower the sample size (0 disables it).
- **Delivery**: default at-least-once (a restart can replay a few frames; dedup state itself is checkpointed).
  `--delivery exactly_once` uses Kafka transactions (`transaction.timeout.ms` 10 min, below the broker's 15 min cap);
  consumers must read with `isolation.level=read_committed`.
- **Event time**: uses the Kafka record timestamp, 30 s out-of-orderness, 30 s partition idleness. A record arriving
  after its window's state is gone counts as a new first occurrence (a rare extra pass, never a loss).
- **Low traffic**: frames are per shard (`--batch-shards`, default 4) so tiny volumes produce tiny frames; use 1 shard
  and a longer `--batch-linger-ms` there. The gain comes from batching at volume (~4× here on short, varied logs; more on repetitive ones).
- **Metrics** (Flink metric groups): `raw_in`, `kept`, `noise_dropped{reason}`, `dedup_passed`, `dedup_suppressed`,
  `frames_out`, `frame_bytes_uncompressed`, `frame_bytes_compressed`.
- The compressed frame travels through PyFlink as an ISO-8859-1 string (1 char per byte) because the Python Kafka
  sink only serialises strings and Flink's byte[] serializer would add a length prefix; the bytes on the wire are exactly the zstd frame.
- Kafka's official Windows support is limited; the broker used for testing is not a production setup.
