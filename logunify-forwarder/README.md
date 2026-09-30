# LogUnify forwarder: multi-SIEM delivery + 180-day retention

Forwards LogUnify's ECS events from Kafka to **Elasticsearch, Splunk HEC and Wazuh simultaneously** (Vector), with a
hot/warm/cold lifecycle designed for the CERT-In 180-day rule. Read **[docs/WORKFLOW.md](docs/WORKFLOW.md)** first: it explains the design,
delivery guarantees, security controls, retention semantics per platform, the rollout runbook, and (importantly) what was **not** verified.

```
vector/vector.d/        forwarder config (common + DLQ + one file per destination)    vector/tests/   VRL unit tests
elasticsearch/          ILM policy (Basic + Enterprise), index template, SLM, repos, role/API key, setup.py
splunk/                 indexes.conf (tiering + retention), inputs.conf (HEC), props.conf
wazuh/                  agent localfile, manager snippet, rules, ISM + snapshot-management policies
retention/              policy_lint.py (CI guardrail for the 180-day rule), capacity.py (tier cost model)
scripts/                mock_receivers.py (ES + Splunk HEC protocol mocks), e2e.py (end-to-end test)
```

## Use
```bash
python -m pytest tests -q                              # 54 tests: every lint rule proven to fire, capacity model
python retention/policy_lint.py --eps 500 --outage-hours 4   # CI gate: 180-day rule, security baseline, sizing for YOUR load
python retention/capacity.py --eps 500                 # tier sizes + cost (prices/ratios are placeholders)
python elasticsearch/setup.py --url https://es:9200 --auth "ApiKey …" --repo s3 --create-data-stream   # or --dry-run

# forwarder
export VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true KAFKA_BOOTSTRAP=… ES_URL=… SPLUNK_HEC_URL=… SECRETS_DIR=/run/secrets …
vector validate --no-environment vector/vector.d/*.yaml
vector test vector/vector.d/*.yaml vector/tests/transforms.yaml
vector $(for f in vector/vector.d/*.yaml; do echo -c $f; done)
```
Secrets (`es_authorization`, `splunk_hec_token`) are files in `SECRETS_DIR`, resolved by Vector as `SECRET[fwd.<name>]`; never env vars or config.

End-to-end test (needs Kafka on 127.0.0.1:9092, Vector at `tools/vector/bin/`, the LogUnify backend next door, and a Python with `confluent-kafka`):
`python scripts/e2e.py` → 25 checks including a Splunk outage, a Vector `kill -9` with undelivered data, DLQ and full-topic replay.

## Status
Verified with real Kafka, the real LogUnify backend and real Vector; **Elasticsearch/Splunk are protocol mocks and Wazuh is a file check.** The platform-side
policies (ILM, Splunk `.conf`, Wazuh rules, ISM) are linted against documented semantics but not run on live clusters. See WORKFLOW.md §6 before go-live.
