from dataclasses import asdict, dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_KAFKA_JAR = str(_ROOT / "jars" / "flink-sql-connector-kafka-3.3.0-1.20.jar")


@dataclass(frozen=True)
class JobConfig:
    # Kafka
    bootstrap: str = "localhost:9092"
    in_topic: str = "logunify.raw"
    out_topic: str = "logunify.siem"
    stats_topic: str = "logunify.siem.dedup-stats"
    group_id: str = "logunify-flink-dedup"
    bounded: bool = False                    # read up to the offsets present at start, then finish (tests / backfill)
    delivery: str = "at_least_once"          # at_least_once | exactly_once (needs checkpointing + broker tx support)

    # dedup / noise
    window_seconds: int = 300                # dedup window, event time, measured from the first occurrence
    out_of_orderness_seconds: int = 30
    idle_timeout_seconds: int = 30           # an idle partition must not stall the watermark (and so the timers)
    drop_debug: bool = True
    summary_sample_chars: int = 200          # raw-text sample kept in dedup state per fingerprint (state size = keys x this)

    # output
    compression: str = "frame"               # frame: app-level zstd micro-batches | kafka: producer compression.type=zstd
    zstd_level: int = 3
    batch_max_records: int = 500
    batch_max_bytes: int = 512 * 1024        # uncompressed; keeps frames far below Kafka's 1 MB max.request.size
    batch_linger_ms: int = 1000
    batch_shards: int = 4

    # runtime
    parallelism: int = 1
    checkpoint_ms: int = 30_000
    kafka_jar: str = DEFAULT_KAFKA_JAR
    extra_jars: str = ""                     # comma-separated; --compression kafka needs zstd-jni (auto-found in jars/)

    def __post_init__(self):
        if self.compression not in ("frame", "kafka"):
            raise ValueError("compression must be 'frame' or 'kafka'")
        if self.delivery not in ("at_least_once", "exactly_once"):
            raise ValueError("delivery must be 'at_least_once' or 'exactly_once'")
        if not 0 <= self.summary_sample_chars <= 4096:
            raise ValueError("summary_sample_chars must be between 0 and 4096")
        if self.window_seconds < 1:
            raise ValueError("window_seconds must be >= 1")
        if not 1 <= self.zstd_level <= 19:
            raise ValueError("zstd_level must be between 1 and 19")
        if self.batch_max_records < 1 or self.batch_max_bytes < 1024 or self.batch_shards < 1:
            raise ValueError("batch limits must be positive (batch_max_bytes >= 1024)")

    @property
    def window_ms(self) -> int:
        return self.window_seconds * 1000

    def as_dict(self) -> dict:
        return asdict(self)
