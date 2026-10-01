import re

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .alerting.defaults import DEFAULT_CRITICAL_TECHNIQUES


_SLOT: dict = {}


def acquire_slot(directory: str) -> tuple[str, object]:
    """Lease the lowest free replica slot with an advisory flock held for the life of the process. A restarted or RECREATED
    container (new container id, new hostname) gets its old slot back, so its SQLite files, dead-letter file, raw archive and
    Merkle batch sequence are found again. Returns (worker_id, open file). Linux/macOS only (fcntl)."""
    import fcntl
    import os
    os.makedirs(directory, exist_ok=True)
    for n in range(256):
        f = open(os.path.join(directory, f"w{n}.lock"), "a+")
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return f"w{n}", f
        except OSError:
            f.close()
    raise RuntimeError(f"no free worker slot in {directory} (256 replicas already running?)")


def _auto_worker_id(directory: str) -> str:
    """Once per process (several Settings objects can exist in one process); falls back to the hostname where fcntl is missing."""
    if "id" not in _SLOT:
        try:
            _SLOT["id"], _SLOT["fd"] = acquire_slot(directory)
        except ImportError:                          # Windows: development only
            import socket
            _SLOT["id"] = re.sub(r"[^A-Za-z0-9_.-]", "", socket.gethostname())[:24] or "0"
    return _SLOT["id"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LOGUNIFY_", env_file=".env", extra="ignore")

    kafka_enabled: bool = False
    kafka_bootstrap: str = "localhost:9092"
    kafka_raw_topic: str = "logunify.raw"
    kafka_ecs_topic: str = "logunify.ecs"
    kafka_group: str = "logunify-pipeline"

    kafka_linger_ms: int = 20
    kafka_compression: str = "gzip"   # gzip | none (| snappy / lz4 / zstd if the client library is installed). Compression runs on the event loop
    kafka_request_timeout_ms: int = 30_000
    kafka_publish_max_wait_s: float = 300.0   # ECS publish retried this long (broker outage) before the raw log is dead-lettered
    kafka_batch_wait_s: float = 0.5
    batch_max: int = 500          # logs fetched per poll / committed together
    process_chunk: int = 32       # logs processed per event-loop slice (then the loop yields), bounds alerting latency
    worker_id: str = ""           # set per replica when scaling out: prefixes batch ids so replicas never collide
    default_timezone: str = "UTC" # for source timestamps that carry no offset (override per source with its `timezone`)
    dlq_path: str = "data/dlq.jsonl"   # logs that could not be normalized: kept, counted, replayable
    dlq_max_mb: int = 512

    worker_slot_dir: str = "data/.slots"   # LOGUNIFY_WORKER_ID=auto leases w0, w1, ... here (flock); mount it on the shared volume
    version: str = "1.0.0"          # reported by /health (set LOGUNIFY_VERSION to the image tag)

    queue_max: int = 10_000       # in-memory bus capacity; overflow => dropped
    recent_buffer: int = 1_000    # parsed ECS events kept for /logs/recent
    max_raw_bytes: int = 64 * 1024

    intel_enabled: bool = True        # Drain3 templates + Isolation Forest scoring + MITRE tagging
    anomaly_threshold: float = 0.7
    ml_warmup: int = 200              # samples before the first Isolation Forest fit
    ml_refit_every: int = 1000
    ml_window: int = 5000

    ti_enabled: bool = True
    ti_mock_feed: bool = True         # demo indicators, used only when MISP is not configured
    misp_url: str = ""                # e.g. https://misp.example.org
    misp_key: SecretStr | None = None # MISP automation key (never returned by the API)
    misp_verify_ssl: bool = True
    misp_lookback: str = "7d"         # MISP 'last' filter: only recently changed attributes
    misp_sync_minutes: int = 15

    integrity_batch_size: int = 100   # ECS records per Merkle batch
    integrity_auto_anchor: bool = True  # mock-anchor each sealed batch on the simulated Fabric ledger
    integrity_max_batches: int = 50   # sealed batches (with records) kept in memory for proofs

    # ---- real forwarding to Elasticsearch (Bulk API, app/forwarding). Off by default. Do NOT also run Vector's ES sink on the
    # same index: ids differ, so documents would be indexed twice. ------------------------------------------------------
    es_forward_enabled: bool = False
    es_forward_api_key: SecretStr | None = None    # needs only create_doc/auto_configure on logs-logunify-* (see forwarder role file)
    es_forward_index: str = "logs-logunify-prod"   # a data stream matched by the shipped index template
    es_forward_workers: int = 2
    es_forward_batch_docs: int = 500
    es_forward_batch_bytes: int = 5 * 1024 * 1024
    es_forward_flush_interval_s: float = 1.0
    es_forward_queue_max: int = 50_000
    es_forward_max_retries: int = 6                # per document, then it goes to the dead-letter file (not dropped)
    es_forward_backoff_max_s: float = 30.0
    es_forward_timeout_s: float = 30.0
    es_forward_allow_insecure_http: bool = False   # plain http to a non-loopback host; leave false
    es_forward_ca_file: str = ""
    es_forward_dlq_path: str = "data/es-dlq.jsonl"
    es_forward_dlq_max_mb: int = 512

    # ---- durable state (app/state): sources, IOC feeds, Merkle batches + anchors, recent logs/anomalies ---------------
    state_enabled: bool = True
    state_db_path: str = "data/state.db"
    state_flush_interval_s: float = 5.0            # a crash loses at most this much
    state_persist_logs: bool = True                # recent logs + anomalies (PII-redacted) also saved; false = only the rest

    # ---- syslog listeners (app/listeners): unset port = off. 514 needs elevated rights on Linux; there is no TLS ----------
    syslog_bind: str = "127.0.0.1"                 # loopback by default: plain syslog is unauthenticated, expose deliberately
    syslog_udp_port: int | None = None
    syslog_tcp_port: int | None = None
    syslog_queue_max: int = 10_000
    syslog_max_message_bytes: int = 8192
    syslog_max_connections: int = 256
    syslog_idle_timeout_s: float = 300.0

    # ---- access control + audit (app/security) --------------------------------------------------------------------
    auth_mode: str = "off"                         # off (dev: everyone is admin, warned at startup) | jwt (bearer HS256)
    jwt_secret: SecretStr | None = None            # >= 32 bytes; required when auth_mode=jwt
    jwt_issuer: str = ""                           # if set, the token's iss must match
    jwt_audience: str = ""                         # if set, the token's aud must contain it
    jwt_roles_claim: str = "roles"                 # dotted path, e.g. realm_access.roles for Keycloak
    jwt_leeway_s: int = 30
    audit_db_path: str = "data/audit.db"           # hash-chained audit log of analyst/admin actions
    audit_hmac_key: SecretStr | None = None        # keyed chain: DB-write access alone cannot forge it

    # ---- compliance reporting (app/compliance) -------------------------------------------------------------------
    forwarder_root: str = "../logunify-forwarder"  # policy files (ILM / SLM / indexes.conf / ISM) the static retention proof reads
    es_url: str = ""                               # optional live check of ILM on a running Elasticsearch (read-only calls)
    es_api_key: SecretStr | None = None            # base64 "id:key" API key with monitor + read_ilm on logs-logunify-*
    es_verify_ssl: bool = True
    compliance_report_dir: str = "data/compliance"
    compliance_report_interval_hours: float = 0    # >0: write a signed-hash JSON + PDF report on this schedule (0 = on demand)

    taxonomy_mode: str = "warn"    # ECS validation of every document: off | warn (count violations) | strict (dead-letter violators)
    cors_origins: str = ""         # CSV of allowed browser origins; empty = no CORS (the dashboard uses a same-origin proxy). "*" is refused
    parser_dir: str = ""           # extra parsers: *.yaml (declarative) and *.py (plugins); see app/parsers/sdk.py

    # ---- raw archive (app/archive): encrypted unredacted originals, the evidence behind event.hash ----------------------
    raw_archive_enabled: bool = False
    raw_archive_dir: str = "data/raw"
    raw_archive_key: SecretStr | None = None       # base64 of 32 random bytes (AES-256-GCM); required when PII redaction is on
    raw_archive_allow_plaintext: bool = False      # explicit opt-in to store unredacted raw logs unencrypted: dev only
    raw_archive_segment_mb: int = 64
    raw_archive_retention_days: int = 0            # >0 deletes whole segments older than this; 0 keeps everything

    # ---- privacy: PII redaction before enrichment / batching / SIEM (GDPR, DPDP Act) — app/privacy/pii.py ---------------
    pii_enabled: bool = True
    pii_types: str = "card,email,ssn,aadhaar,pan"  # CSV of: card,email,ssn,aadhaar,pan,phone
    pii_mode: str = "mask"                         # mask -> [PII:card] | hash -> [PII:card:<keyed pseudonym>]
    pii_hash_key: SecretStr | None = None          # required for mode=hash

    # ---- alerting: critical alerts + CERT-In 6-hour incident workflow (docs/ALERTING.md) ----------------------------
    alerting_enabled: bool = True
    alert_score_threshold: float = 0.9             # alert when the anomaly score EXCEEDS this ...
    alert_critical_techniques: str = DEFAULT_CRITICAL_TECHNIQUES   # ... AND the log matches one of these MITRE ids (CSV)
    alert_require_rule_basis: bool = True          # ignore the placeholder T1078 fallback tag (logunify.mitre.basis=default)
    alert_dedup_minutes: int = 30                  # same technique+asset within this quiet period = same alert
    alert_max_notifications_per_hour: int = 20     # alert-storm guard; overflow is recorded and summarised, never dropped
    alert_reminder_minutes: str = "120,60,30"      # reminders this long before the 6-hour deadline (CSV)
    alert_overdue_repeat_minutes: int = 60
    alert_maintenance_seconds: int = 60            # reminder / retry sweep interval
    alert_retry_attempts: int = 4                  # per channel, per notification (exponential backoff)
    alert_retry_base_s: float = 2.0
    alert_db_path: str = "data/alerts.db"          # durable alert + audit store (created on first alert)
    alert_api_key: SecretStr | None = None         # required for /api/v1/alerts*; unset = the alert API is disabled

    alert_webhook_url: str = ""                    # https only (plain http for loopback); never logged beyond scheme://host
    alert_webhook_secret: SecretStr | None = None  # HMAC-SHA256 signing key for receivers
    alert_webhook_timeout_s: float = 10.0
    alert_webhook_allow_http: bool = False
    alert_webhook_ca_file: str = ""

    alert_smtp_host: str = ""
    alert_smtp_port: int = 587
    alert_smtp_security: str = "starttls"          # starttls | ssl | none (none only for loopback)
    alert_smtp_user: str = ""
    alert_smtp_password: SecretStr | None = None
    alert_smtp_timeout_s: float = 15.0
    alert_smtp_allow_plaintext: bool = False
    alert_email_from: str = ""
    alert_email_to: str = ""                       # CSV; recipients come from configuration only, never from log content

    # Reporter / Point-of-Contact details that fill the CERT-In form (Directions para (iii), Annexure II)
    org_name: str = ""
    org_address: str = ""
    org_location: str = ""                         # default location of affected systems: City, Region, Country
    org_isp: str = ""
    org_critical_assets: str = ""                  # CSV of fnmatch patterns over host names / IPs that are mission-critical
    poc_name: str = ""
    poc_designation: str = ""
    poc_email: str = ""
    poc_mobile: str = ""
    poc_phone: str = ""
    poc_fax: str = ""

    mock_enabled: bool = False    # demo traffic generator: opt in with LOGUNIFY_MOCK_ENABLED=true (never in production)
    mock_rate: int = 50           # events per second

    @model_validator(mode="after")
    def _expand_worker(self):
        """`{worker}` in any storage path becomes LOGUNIFY_WORKER_ID, so replicas never share (and corrupt) a SQLite file or a
        dead-letter file: LOGUNIFY_STATE_DB_PATH=/data/{worker}/state.db with LOGUNIFY_WORKER_ID=w3."""
        if self.worker_id == "auto":                # containers: a STABLE id per replica slot (w0, w1, ...), see acquire_slot()
            self.worker_id = _auto_worker_id(self.worker_slot_dir)
        w = self.worker_id or "0"
        for name in ("alert_db_path", "audit_db_path", "state_db_path", "dlq_path", "raw_archive_dir", "es_forward_dlq_path",
                     "compliance_report_dir"):
            setattr(self, name, getattr(self, name).replace("{worker}", w))
        return self


settings = Settings()
