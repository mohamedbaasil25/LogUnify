# LogUnify multi-SIEM forwarding and 180-day retention workflow

Forward parsed, ECS-mapped LogUnify events to **Elasticsearch, Splunk HEC and Wazuh at the same time**, and keep them
for the **180 days** the CERT-In directions require, tiered hot → warm → cold to control cost.

> Compliance note: this document encodes our reading of CERT-In Directions No. 20(3)/2022-CERT-In (28 Apr 2022):
> ICT-system logs kept securely for a **rolling 180 days, within Indian jurisdiction** (Directions para (iv); note CERT-In's
> FAQ Q35 says copies may be stored outside India if they can be produced to CERT-In in reasonable time, and Q36 requires
> financial-transaction records in India, so treat India-region storage as the conservative default), producible to CERT-In on request;
> system clocks synced to NIC/NPL time sources; incidents reported within 6 hours. Have counsel confirm the current text
> and scope before relying on it. Nothing here is legal advice.

## 1. Architecture

```
LogUnify backend ──► Kafka  logunify.ecs  ──► Vector (forwarder) ──┬─► Elasticsearch  data stream logs-logunify-<env>
 (Drain3, ML, TI, ECS)   (durable log)          disk buffer / sink ├─► Splunk HEC     index logunify (indexer ack)
                                                 secrets via SECRET├─► Wazuh          NDJSON file ─► agent ─► manager ─► indexer
                                                 malformed ► DLQ   └─► (optional) syslog TCP to Wazuh, private segment only
Kafka logunify.ecs.dlq ◄── anything that is not a JSON object (kept untouched, alert on it)
```

- **Single source of truth = Kafka.** Every destination reads the same durable topic, so a destination can be rebuilt or
  added later by replaying it.
- **Vector** because one small binary provides all three delivery paths, per-sink disk buffers, end-to-end
  acknowledgements, a secret-backend interface and offline config validation/unit tests.
- **Files** (`vector/vector.d/`): `00-common` (source, secrets, transforms) · `05-dlq` · `10-…elasticsearch` ·
  `20-…splunk-hec` · `30-…wazuh-file` · `35-…wazuh-syslog.yaml.example`. Run them all in one process, **or one process per
  destination** (`vector -c 00-common.yaml -c 20-sink-splunk-hec.yaml`, each with its own `FORWARDER_GROUP` and
  `VECTOR_DATA_DIR`) so one blocked destination can never stall the others.

## 2. Delivery guarantees (each row was exercised by `scripts/e2e.py`)

| Situation | What happens | Verified |
|---|---|---|
| Normal | Every event reaches all three destinations; Kafka offset is committed only after delivery | yes |
| Splunk returns 503 for a while | ES and Wazuh continue; Splunk catches up afterwards, nothing lost | yes |
| Vector `kill -9` with events undelivered to Splunk | Disk buffer replays them after restart; nothing lost, some duplicates | yes |
| Whole topic replayed (offset reset / DR) | Elasticsearch answers 409 for every already-stored `_id`; count unchanged; Vector keeps running | yes (mock ES) |
| Malformed payload on `logunify.ecs` | Copied untouched to `logunify.ecs.dlq`; never reaches a destination | yes |
| Secrets | Read via `SECRET[...]` from a directory backend; never in files or env | yes (header seen by mock) |

**Semantics to design around**
- **At-least-once.** Elasticsearch is idempotent because `_id` = `topic:partition:offset`. **Splunk and Wazuh can show
  duplicates** after a crash (200 of 800 in the kill test). Every event carries `event.id`; dedupe at search time
  (`| dedup event.id` in Splunk, a rule/aggregation in Wazuh).
- **`when_full: block` = no silent drops.** A dead destination fills its buffer, then backpressure stops Kafka
  consumption (Kafka keeps the data). Size buffers for the outage you must survive:
  `python retention/capacity.py --eps 500 --outage-hours 4`. The shipped 10 GiB covers ~8 h at 300 EPS.
- **Elasticsearch rejects (HTTP 400 in the bulk response)** are not retried by Vector and would be logged and dropped.
  The template reduces the risk (`labels` and `logunify.ti.matches` are `flattened`, `ignore_malformed: true`), but this
  path could not be tested against a real cluster. Alert on Vector's `component_discarded_events_total` and
  `component_errors_total`.

## 3. Destination configuration and security

| Control | Elasticsearch | Splunk | Wazuh |
|---|---|---|---|
| Transport | HTTPS, verify cert + hostname (private CA via `tls.ca_file`) | HTTPS HEC, TLS 1.2+, verify | Wazuh agent → manager (1514, authenticated + encrypted) |
| Identity | API key, 90-day expiry, role `create_doc` on `logs-logunify-*` only (`api-key-logunify-forwarder.json`) | HEC token limited to `indexes = logunify`, `useACK = 1` | agent enrolment |
| Secret handling | `SECRET[fwd.es_authorization]` | `SECRET[fwd.splunk_hec_token]` | n/a |
| Write semantics | data stream, `create` only, deterministic `_id` | indexer acknowledgement, `time` = event time | `logall_json` archives + rules |
| Files | `elasticsearch/` | `splunk/` | `wazuh/` (localfile, manager snippet, rules `100100-100130`, ISM + snapshot policies) |

Wazuh via **file + agent**, not syslog: Wazuh's syslog listener has no TLS or authentication, so the syslog sink is
provided only as `.example` for private segments with `<allowed-ips>`.

Vector 0.5x+ expands `${VAR}` only with `--dangerously-allow-env-var-interpolation`; we use it for non-secret settings
(endpoints, topics, paths). **Secrets never go through it** (`policy_lint` V3 fails the build if a token/header is literal).

Residency and hygiene: run everything in India regions (`ap-south-1` Mumbai / `ap-south-2` Hyderabad or equivalent), the conservative reading
(`policy_lint` only *warns* about a non-India archive, because the FAQ permits it when logs can be produced promptly; counsel decides);
sync all hosts to NIC/NPL NTP (`samay1.nic.in`, `time.nplindia.org`); restrict cold/archive access; encrypt at rest;
the snapshot bucket should use **Object Lock (compliance mode, ≥ 180 days)** so archived logs cannot be altered or deleted
early. The Merkle batch anchors from LogUnify's integrity layer can be stored beside the archive as tamper evidence.

## 4. Data lifecycle: hot / warm / cold

| Tier | Age | Elasticsearch (ILM `logunify-cert-in`) | Splunk (`indexes.conf`) | Wazuh indexer (ISM) | Purpose |
|---|---|---|---|---|---|
| **Hot** | 0–7 d | rollover 1 d / 50 GB, 1 replica, priority 100, SSD | hot/warm on SSD volume | hot | live triage, dashboards, detections |
| **Warm** | 7–30 d | read-only, force-merge to 1 segment, best_compression, 1 replica | rolls to `coldPath` by size cap | warm: merge, priority 50 | investigations |
| **Cold** | 30–180 d | 0 replicas on cold nodes (snapshot is the safety net); Enterprise variant: searchable snapshot | HDD volume, `tsidx` reduction after 30 d, optional SmartStore (S3 Mumbai) | read-only, 0 replicas | compliance, audits, CERT-In requests |
| **Delete** | ≥ 180 d | only after `wait_for_snapshot` (`logunify-daily`) | freeze at 180 d → `coldToFrozenDir` archive | delete at **181 d** | end of retention |

**Age semantics: getting these wrong silently shortens retention** (each is a `policy_lint` rule):
- **Elasticsearch**: `min_age` counts from **rollover**. Every document is at least `min_age` old when its index is deleted; rollover
  every day bounds over-retention to ~1 day.
- **Splunk**: a bucket freezes when its **newest** event is older than 180 d, so all events are ≥ 180 d. But **size caps also freeze**:
  if `maxTotalDataSizeMB` or a volume cap is hit before day 180 you lose logs early. Size for the load and alert on it.
- **Wazuh/OpenSearch ISM**: `min_index_age` counts from index **creation**, and a daily index keeps receiving events for a day,
  so the delete threshold is **180 + 1 = 181 d**. (`policy_lint` W1 fails a 180 d setting.)

**Cost.** `python retention/capacity.py --eps 500` reads the tier boundaries from the ILM policy: at 500 EPS × 885 B
(38 GB/day raw) tiering plus object-store snapshots cost about **80 % less** than keeping 180 days on hot SSD with a
replica. Prices, index-expansion ratios and document size are **placeholders/assumptions**: replace with your contract
rates and your measured document size. The 885 B average was measured on LogUnify mock traffic only.

**Legal hold / early deletion.** Do not shorten retention or bypass the delete guard during an investigation or an open CERT-In
request: pause the policy (`POST _ilm/stop`, or remove the index from ISM) and remove the hold only with sign-off.

## 5. Rollout and operations

1. **CI gate** on every config change: `python retention/policy_lint.py --eps <load> --outage-hours <n>` ·
   `vector validate --no-environment vector/vector.d/*.yaml` · `vector test vector/vector.d/*.yaml vector/tests/transforms.yaml` · `pytest`.
2. Create topics `logunify.ecs`, `logunify.ecs.dlq` (retention ≥ the longest outage you accept, e.g. 7 d).
3. Elasticsearch: snapshot repository (India region, SSE, Object Lock) → `python elasticsearch/setup.py --url … --auth "ApiKey …" --repo s3 --create-data-stream`.
   Use `--profile enterprise` for searchable snapshots (needs that license).
4. Splunk: deploy `indexes.conf`, `inputs.conf`, `props.conf`; put the HEC token in the secret store.
5. Wazuh: agent `localfile`, manager snippet, `rules/0800-logunify_rules.xml`, ISM + snapshot policies; enable Filebeat archives.
6. Start Vector with the secret directory mounted; watch `vector top`, consumer lag, DLQ volume.
7. **Alert on**: DLQ volume > 0 · Vector discarded/errored events · disk-buffer fill > 50 % · consumer-group lag · ES `_ilm/explain` errors and
   unassigned shards · Splunk approaching `maxTotalDataSizeMB` · ISM failed indices · SLM/snapshot failures · NTP offset.
8. Quarterly: restore one snapshot into a scratch cluster and prove a day from ~170 days ago is searchable (CERT-In can ask any time).

## 6. What was and was not verified

**Verified by running it** (`scripts/e2e.py`, 25 checks; `vector test`; 54 pytest): the LogUnify backend in Kafka mode → Kafka → Vector 0.58 with the
shipped configs → three destinations; payload shape, secrets, acknowledgements, DLQ, destination outage, `kill -9` recovery, replay
idempotency; policy linter (every rule proven to fire by mutation tests); capacity model.

**Not verified: treat as unproven until run on real systems**
- **Elasticsearch, Splunk and Wazuh were not run.** The ES and HEC receivers in the tests are protocol mocks that enforce only the rules the
  forwarder depends on. A real Elasticsearch could not be started on the dev machine (its JDK 17+ fails opening a selector on this Windows build).
- ILM/SLM/index-template JSON, Splunk `.conf` files, Wazuh rules/decoding (check with `wazuh-logtest`, e.g. feed one line from `.e2e/wazuh`),
  and the ISM/snapshot-management policies are checked structurally and against documented semantics, **not against live clusters**.
  Phase timing (rollover-based `min_age`, `wait_for_snapshot`) has not been observed. Before go-live, run a scaled-time test on a real cluster.
- The Enterprise (searchable snapshot) profile and the S3 repository were not exercised; Elasticsearch security (API key/role) was not enabled in tests.
- Only one Kafka partition was used; multi-partition ordering and rebalancing are untested.
