"""Runs the real operators on Flink's local mini-cluster (event-time, in-memory source)."""
import json

import pytest

from logunify_flink.config import JobConfig
from logunify_flink.testing import run_pipeline

T0 = 1_700_000_000_000
S = 1000


def ssh(ip="1.2.3.4", user="bob", pid=1, port=5000, ts="Oct 11 22:14:15"):
    return f"<38>{ts} web-01 sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"


def js(user="bob", rid="a", ts="2026-01-01T00:00:00Z"):
    return json.dumps({"timestamp": ts, "request_id": rid, "user": user, "action": "login"})


EVENTS = sorted([
    (T0 + 0 * S, ssh()),                                                   # 1 passes: window W1 opens
    (T0 + 5 * S, ssh("5.6.7.8")),                                          # 2 passes: different attacker
    (T0 + 10 * S, ssh(pid=2, port=6000, ts="Oct 11 22:14:25")),            # dup of 1 (only pid/port/ts differ)
    (T0 + 12 * S, "GET /healthz 200 1ms"),                                 # noise: chatter
    (T0 + 13 * S, "<15>Oct 11 22:14:28 h app: verbose internals"),          # noise: debug
    (T0 + 14 * S, ""),                                                     # noise: empty
    (T0 + 15 * S, "<15>Oct 11 22:14:29 h app: authentication failed for admin"),   # debug PRI but security: kept
    (T0 + 20 * S, js(rid="r1")),                                           # JSON passes
    (T0 + 30 * S, js(rid="r2", ts="2026-01-01T00:00:10Z")),                # dup of the JSON (volatile keys differ)
    (T0 + 200 * S, ssh(pid=3, port=7000)),                                 # dup of 1, still inside 300 s
    (T0 + 299 * S, ssh(pid=4)),                                            # dup of 1 (299 s < 300 s)
    (T0 + 301 * S, ssh(pid=5)),                                            # window W1 closed at 300 s: passes again
    (T0 + 302 * S, ssh(pid=6)),                                            # dup inside the new window
])


@pytest.fixture(scope="module")
def frame_run():
    return run_pipeline(EVENTS, JobConfig(window_seconds=300, batch_shards=1))


def test_dedup_noise_and_windows(frame_run):
    raws = [r["raw"] for r in frame_run["records"]]
    assert len(raws) == 5, raws
    fps = [r["fp"] for r in frame_run["records"]]
    ssh_bob = [r for r in frame_run["records"] if "from 1.2.3.4" in r["raw"]]
    assert [r["ts"] for r in ssh_bob] == [T0, T0 + 301 * S]               # passed at t=0 and again after the window
    assert sum("5.6.7.8" in x for x in raws) == 1
    assert sum(x.startswith('{"timestamp"') for x in raws) == 1
    assert any("authentication failed for admin" in x for x in raws)     # security guard beat the debug filter
    assert not any("healthz" in x or "verbose" in x or x == "" for x in raws)
    assert len(set(fps)) == 4                                            # 4 distinct events, 5 passes (bob passes twice)


def test_summaries_preserve_suppressed_volume(frame_run):
    by_sample = {s["sample"][:20]: s for s in frame_run["summaries"]}
    ssh_sum = next(s for s in frame_run["summaries"] if "from 1.2.3.4" in s["sample"])
    json_sum = next(s for s in frame_run["summaries"] if s["sample"].startswith("{"))
    assert ssh_sum["suppressed"] == 3 and ssh_sum["first_seen_ms"] == T0 and ssh_sum["window_ms"] == 300_000
    assert json_sum["suppressed"] == 1
    assert len(frame_run["summaries"]) == 3                               # W1 (3), JSON (1), W2 (1: the pid=6 dup)
    assert sorted(s["suppressed"] for s in frame_run["summaries"]) == [1, 1, 3]
    assert len(by_sample) >= 2


def test_frames_are_zstd(frame_run):
    assert frame_run["frames"] and all(f[:4] == b"\x28\xb5\x2f\xfd" for f in frame_run["frames"])


def test_size_limit_splits_frames_and_tail_is_flushed():
    r = run_pipeline(EVENTS, JobConfig(batch_shards=1, batch_max_records=2))
    assert len(r["records"]) == 5
    assert len(r["frames"]) == 3                                          # 2 + 2 + tail of 1 (flushed by final watermark)


def test_kafka_native_compression_mode_emits_plain_envelopes():
    r = run_pipeline(EVENTS, JobConfig(compression="kafka"))
    assert len(r["records"]) == 5 and r["frames"] == []
    assert {"ts", "fp", "raw"} <= set(r["records"][0])


def test_window_length_is_configurable():
    r = run_pipeline(EVENTS, JobConfig(window_seconds=60, batch_shards=1))
    ssh_bob = [x for x in r["records"] if "from 1.2.3.4" in x["raw"]]
    # 60 s windows: t=0 opens; t=10 dup; t=200 new window; t=299 new window; t=301/302 dups of the t=299 window
    assert [x["ts"] for x in ssh_bob] == [T0, T0 + 200 * S, T0 + 299 * S]
