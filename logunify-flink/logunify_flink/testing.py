"""Harness for running the real pipeline on Flink's local mini-cluster with an in-memory, event-timed source.

Lives inside the package (not tests/) because Flink's Python workers must be able to import the functions.
"""
from pathlib import Path

from pyflink.common import Types, WatermarkStrategy
from pyflink.common.watermark_strategy import TimestampAssigner
from pyflink.datastream import MapFunction, StreamExecutionEnvironment

from .codec import from_wire, read_frame
from .config import JobConfig
from .job import build_pipeline
from .pyenv import use_this_interpreter

_PKG = Path(__file__).resolve().parent


class _Ts(TimestampAssigner):
    def extract_timestamp(self, value, record_timestamp):
        return value[0]


class _Raw(MapFunction):
    def map(self, value):
        return value[1]


class _Tag(MapFunction):
    def __init__(self, tag: str):
        self._tag = tag

    def map(self, value):
        return self._tag, value


def run_pipeline(events: list[tuple[int, str]], cfg: JobConfig) -> dict:
    """events: (event_time_ms, raw_log), ascending by time. Returns {'records', 'frames', 'summaries'}."""
    import json
    env = StreamExecutionEnvironment.get_execution_environment()
    env.set_parallelism(1)
    use_this_interpreter(env)
    env.add_python_file(str(_PKG))
    src = env.from_collection(events, type_info=Types.TUPLE([Types.LONG(), Types.STRING()]))
    stream = (src.assign_timestamps_and_watermarks(WatermarkStrategy.for_monotonous_timestamps()
                                                   .with_timestamp_assigner(_Ts()))
              .map(_Raw(), output_type=Types.STRING()))
    out, stats = build_pipeline(stream, cfg)
    pair = Types.TUPLE([Types.STRING(), Types.STRING()])
    merged = out.map(_Tag("O"), output_type=pair).union(stats.map(_Tag("S"), output_type=pair))

    records, frames, summaries = [], [], []
    for tag, payload in merged.execute_and_collect():
        if tag == "S":
            summaries.append(json.loads(payload))
        elif cfg.compression == "frame":
            frames.append(from_wire(payload))
            records.extend(read_frame(frames[-1]))
        else:
            records.append(json.loads(payload))
    return {"records": records, "frames": frames, "summaries": summaries}
