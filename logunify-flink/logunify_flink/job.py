"""LogUnify SIEM-prep job: Kafka raw logs -> noise filter -> 5-min dedup -> zstd -> Kafka SIEM topic.

    python -m logunify_flink.job --bootstrap localhost:9092 [--bounded] [--compression frame|kafka]
"""
import argparse
from dataclasses import fields
from pathlib import Path

from pyflink.common import Duration, Types, WatermarkStrategy
from pyflink.common.serialization import SimpleStringSchema
from pyflink.datastream import StreamExecutionEnvironment
from pyflink.datastream.connectors.kafka import (DeliveryGuarantee, KafkaOffsetResetStrategy, KafkaOffsetsInitializer,
                                                 KafkaRecordSerializationSchema, KafkaSink, KafkaSource)

from .codec import WIRE_CHARSET
from .config import JobConfig
from .functions import (DEDUPED_TYPE, PREPARED_TYPE, SHARDED_TYPE, SUMMARY_TAG, Dedup, Prepare, ToEnvelope, ToShard,
                        ZstdBatcher)
from .pyenv import use_this_interpreter


def build_pipeline(stream, cfg: JobConfig):
    """Wire the operators onto `stream` (DataStream[str] with event timestamps). Returns (output, dedup_stats)."""
    prepared = stream.process(Prepare(cfg.drop_debug), output_type=PREPARED_TYPE).name("noise-filter+fingerprint")
    deduped = (prepared.key_by(lambda t: t[0], key_type=Types.STRING())
               .process(Dedup(cfg.window_ms, cfg.summary_sample_chars), output_type=DEDUPED_TYPE).name(f"dedup-{cfg.window_seconds}s"))
    stats = deduped.get_side_output(SUMMARY_TAG)

    if cfg.compression == "frame":
        out = (deduped.map(ToShard(cfg.batch_shards), output_type=SHARDED_TYPE)
               .key_by(lambda t: t[0], key_type=Types.INT())
               .process(ZstdBatcher(cfg.batch_max_records, cfg.batch_max_bytes, cfg.batch_linger_ms, cfg.zstd_level),
                        output_type=Types.STRING()).name("zstd-batch"))
    else:
        out = deduped.map(ToEnvelope(), output_type=Types.STRING()).name("envelope")
    return out, stats


def _sink(cfg: JobConfig, topic: str, charset: str, props: dict[str, str], tx_prefix: str) -> KafkaSink:
    ser = (KafkaRecordSerializationSchema.builder().set_topic(topic)
           .set_value_serialization_schema(SimpleStringSchema(charset)).build())
    b = KafkaSink.builder().set_bootstrap_servers(cfg.bootstrap).set_record_serializer(ser)
    if cfg.delivery == "exactly_once":
        b = (b.set_delivery_guarantee(DeliveryGuarantee.EXACTLY_ONCE).set_transactional_id_prefix(tx_prefix)
             .set_property("transaction.timeout.ms", "600000"))       # must stay below the broker's 15 min max
    else:
        b = b.set_delivery_guarantee(DeliveryGuarantee.AT_LEAST_ONCE)
    for k, v in props.items():
        b = b.set_property(k, v)
    return b.build()


def build_kafka_job(env: StreamExecutionEnvironment, cfg: JobConfig) -> None:
    src = (KafkaSource.builder().set_bootstrap_servers(cfg.bootstrap).set_topics(cfg.in_topic)
           .set_group_id(cfg.group_id)
           .set_starting_offsets(KafkaOffsetsInitializer.committed_offsets(KafkaOffsetResetStrategy.EARLIEST))
           .set_value_only_deserializer(SimpleStringSchema()))
    if cfg.bounded:
        src = src.set_bounded(KafkaOffsetsInitializer.latest())
    wm = (WatermarkStrategy.for_bounded_out_of_orderness(Duration.of_seconds(cfg.out_of_orderness_seconds))
          .with_idleness(Duration.of_seconds(cfg.idle_timeout_seconds)))
    stream = env.from_source(src.build(), wm, "kafka-raw")

    out, stats = build_pipeline(stream, cfg)
    if cfg.compression == "frame":
        out.sink_to(_sink(cfg, cfg.out_topic, WIRE_CHARSET, {}, "logunify-siem")).name("siem-sink(zstd-frames)")
    else:
        out.sink_to(_sink(cfg, cfg.out_topic, "UTF-8", {"compression.type": "zstd"}, "logunify-siem")) \
            .name("siem-sink(kafka-zstd)")
    stats.sink_to(_sink(cfg, cfg.stats_topic, "UTF-8", {}, "logunify-stats")).name("dedup-stats-sink")


def configure_env(env: StreamExecutionEnvironment, cfg: JobConfig) -> None:
    env.set_parallelism(cfg.parallelism)
    use_this_interpreter(env)
    env.add_python_file(str(Path(__file__).resolve().parent))
    jars = [Path(cfg.kafka_jar), *(Path(p) for p in cfg.extra_jars.split(",") if p.strip())]
    if cfg.compression == "kafka" and not any("zstd-jni" in j.name for j in jars):
        jars += sorted((Path(cfg.kafka_jar).parent).glob("zstd-jni-*.jar"))[:1]
        if not any("zstd-jni" in j.name for j in jars):
            raise SystemExit("--compression kafka needs the zstd-jni jar (Kafka's zstd codec); put it next to the "
                             "connector jar or pass --extra-jars")
    for jar in jars:
        if not jar.exists():
            raise SystemExit(f"jar not found: {jar}")
    env.add_jars(*(j.resolve().as_uri() for j in jars))
    if not cfg.bounded or cfg.delivery == "exactly_once":      # transactions only commit on checkpoints
        env.enable_checkpointing(cfg.checkpoint_ms)


def parse_args(argv=None) -> JobConfig:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    defaults = JobConfig()
    for f in fields(JobConfig):
        flag, default = "--" + f.name.replace("_", "-"), getattr(defaults, f.name)
        if isinstance(default, bool):
            ap.add_argument(flag, action=argparse.BooleanOptionalAction, default=default)
        else:
            ap.add_argument(flag, type=type(default), default=default)
    return JobConfig(**vars(ap.parse_args(argv)))


def main(argv=None) -> None:
    cfg = parse_args(argv)
    env = StreamExecutionEnvironment.get_execution_environment()
    configure_env(env, cfg)
    build_kafka_job(env, cfg)
    env.execute("logunify-siem-dedup")


if __name__ == "__main__":
    main()
