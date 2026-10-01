# Containers and air-gapped deployment

**Verification status, read first.** Built and run for real (Docker 29, Windows/WSL2): the **backend** and **dashboard** images, and the **compose stack**
(Kafka + topic init + backend + dashboard) against a real Kafka broker:
* `deploy/smoke_test.py` passes inside the running backend: auth enforced, ingest, normalization, PII redaction, dead-lettering, books balance, trace verdict `verified`
  with the raw log recovered by an admin, audit chain, durable state, compliance PDF, and the normalized documents arriving on the Kafka ECS topic.
* Hardening confirmed: non-root users, read-only root filesystem, all capabilities dropped, `--network none` (air-gapped) still healthy and functional,
  the backend refuses to start without `LOGUNIFY_JWT_SECRET`.
* Re-creating the backend container keeps its identity (worker slot `w0`) and finds its state, raw archive and audit chain again; two replicas lease `w0`/`w1` and
  split the Kafka partitions between them.
**Not built or run:** the Flink image (needs ~1 GB of downloads; its lock file and Dockerfile are written), the Vector forwarder image and the `siem` profile (the base image tags
were checked to exist), and everything beyond one host. The CI workflow (`.github/workflows/ci.yml`) runs on GitHub Actions and passes: lint, all test suites, the real-Kafka tests, gitleaks, pip-audit, npm audit, and a Trivy scan of both images (0 fixable HIGH/CRITICAL). Image sizes: backend 669 MB, dashboard 322 MB.

## What is in the stack (`compose.yaml`)
Kafka (KRaft, topics created explicitly with `LOGUNIFY_PARTITIONS` partitions) -> backend -> dashboard; optional profiles `flink` (PyFlink job) and `siem` (Vector -> Elasticsearch / Splunk /
Wazuh). Hardened by default: non-root users, read-only root filesystems, all capabilities dropped, `no-new-privileges`, ports bound to 127.0.0.1, secrets as env/files from `.env`
(never baked into images), JWT auth **on** (the stack refuses to start without `LOGUNIFY_JWT_SECRET`).

```bash
cp deploy/.env.example .env      # set LOGUNIFY_JWT_SECRET etc.
docker compose up -d
docker compose up -d --scale backend=3     # more workers: needs LOGUNIFY_PARTITIONS >= 3; each replica gets its own id and stores (see docs/PIPELINE.md section 5)
```
Add parsers by dropping YAML/Python files into `parsers.d/` (mounted read-only). Parsing policy files for the compliance report come from `./logunify-forwarder` (read-only mount).

## Reproducible, hash-pinned dependencies
`requirements.in` -> `requirements.lock` (backend, Python 3.13) and flink (Python 3.11) are generated with `deploy/lock.sh` (uv, cross-platform, with hashes). Images install them with
`pip install --require-hashes`: a wheel that does not match its recorded hash is refused. Regenerate and review the diff on purpose, never implicitly. Base images are pinned by tag;
pin them by digest in your registry for production.

## Air-gapped workflow
On a **connected** build host:
```bash
deploy/offline/make-bundle.sh --version 1.0.0 [--with-flink] [--with-siem]
# -> dist/logunify-1.0.0/: images tarball (docker save), images.txt, wheelhouse, SBOMs (if syft is installed), compose + deploy files, SHA256SUMS
gpg --detach-sign dist/logunify-1.0.0/SHA256SUMS      # or cosign sign-blob: checksums only prove integrity if the checksum file is trusted
```
Move the folder across the gap (signed media / data diode). On the **isolated** host (Docker + compose plugin, no network):
```bash
cd logunify-1.0.0 && bash deploy/offline/load-bundle.sh      # verifies SHA256SUMS, docker load, starts the stack with --pull never
```
Nothing in LogUnify calls out to the internet by itself: egress happens only to endpoints you configure (Elasticsearch, Splunk, MISP, SMTP/webhook for alerts). GeoIP and threat intel are
mock/offline unless you provide data. The Flink image needs its two jars at build time (`deploy/fetch-jars.sh`, checksum-verified); do that on the connected host before bundling.

## Not done
No Helm chart / Kubernetes manifests (cannot be validated here); no TLS inside the stack (terminate it at a reverse proxy); single-node Kafka (replication factor 1) in the compose file:
use a real cluster for production.
