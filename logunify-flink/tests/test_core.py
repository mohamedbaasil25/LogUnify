import json
import os

import pytest

from logunify_flink.codec import FrameWriter, ZSTD_MAGIC, envelope, from_wire, read_frame, to_wire
from logunify_flink.config import JobConfig
from logunify_flink.fingerprint import fingerprint, normalize
from logunify_flink.noise import NoiseFilter

SSH = "<38>Oct 11 22:14:15 web-01 sshd[123]: Failed password for bob from 1.2.3.4 port 5000 ssh2"


# ---------------------------------------------------------------- noise
@pytest.mark.parametrize("line,reason", [
    ("", "empty"), ("   \n", "empty"),
    ("GET /healthz 200 3ms", "chatter"),
    ("ELB-HealthChecker/2.0", "chatter"),
    ("app heartbeat ok seq=5", "chatter"),
    ("Oct 11 22:14:15 h CRON[1]: pam_unix(cron:session): session opened for user root", None),   # 'root' guard keeps it
    ("Oct 11 22:14:15 h CRON[1]: pam_unix(cron:session): session opened for user www", "chatter"),
    ("<15>Oct 11 22:14:15 h app: verbose internals", "debug"),                                  # PRI 15 -> severity 7
    ('{"level":"DEBUG","message":"cache miss"}', "debug"),
    ("2026-01-01 DEBUG: loading config", "debug"),
])
def test_noise_dropped(line, reason):
    assert NoiseFilter().reason(line) == reason


@pytest.mark.parametrize("line", [
    SSH,
    "<15>Oct 11 22:14:15 h app: authentication failed for admin",           # debug PRI but security signal: keep
    'CEF:0|Acme|NGFW|1|100|Port scan|5|src=1.2.3.4 dst=10.0.0.5',
    '{"level":"debug","message":"login denied for eve"}',
    "GET /healthz blocked by waf",
    "User bob logged in from 8.8.8.8",
])
def test_security_signal_never_dropped(line):
    assert NoiseFilter().reason(line) is None


def test_debug_dropping_is_optional():
    assert NoiseFilter(drop_debug=False).reason("<15>Oct 11 22:14:15 h app: verbose") is None


# ---------------------------------------------------------------- fingerprint
def test_volatile_fields_do_not_change_fingerprint():
    a = SSH
    b = "<38>Oct 11 22:19:59 web-01 sshd[99999]: Failed password for bob from 1.2.3.4 port 61234 ssh2"
    assert fingerprint(a) == fingerprint(b)


def test_meaningful_fields_change_fingerprint():
    base = fingerprint(SSH)
    assert fingerprint(SSH.replace("1.2.3.4", "5.6.7.8")) != base            # different attacker
    assert fingerprint(SSH.replace("bob", "alice")) != base                  # different user
    assert fingerprint(SSH.replace("web-01", "web-02")) != base              # different host
    assert fingerprint(SSH.replace("<38>", "<35>")) != base                  # different severity


def test_json_fingerprint_ignores_volatile_keys_and_order():
    a = '{"timestamp":"2026-01-01T00:00:00Z","request_id":"a1","user":"bob","action":"login","ts":1700000000}'
    b = '{"action":"login","user":"bob","request_id":"zz","@timestamp":"2026-01-01T00:05:00Z"}'
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a) != fingerprint(a.replace("bob", "eve"))


def test_cef_and_epoch_masking():
    a = "CEF:0|A|B|1|100|Scan|5|rt=1700000000123 src=1.2.3.4 spt=4444 dpt=22"
    b = "CEF:0|A|B|1|100|Scan|5|rt=1700000999999 src=1.2.3.4 spt=5555 dpt=22"
    assert fingerprint(a) == fingerprint(b) and fingerprint(a) != fingerprint(b.replace("dpt=22", "dpt=23"))


def test_fingerprint_is_stable_and_bounded():
    assert fingerprint("x") == fingerprint("x") and len(fingerprint("x")) == 32
    assert len(normalize("y" * 10_000_000)) <= 8192                       # bounded CPU per record
    assert normalize("{not json") == "{not json" and fingerprint("{not json")   # malformed JSON falls back to text


# ---------------------------------------------------------------- codec
def test_frame_roundtrip_and_ratio():
    lines = [envelope(1700000000000 + i, f"{i:032x}", f"<38>Oct 11 22:14:15 web-01 sshd[1]: Failed password for u{i % 5} from 10.0.0.{i % 200} port 22")
             for i in range(500)]
    frame = FrameWriter(3).compress(lines)
    assert frame[:4] == ZSTD_MAGIC
    recs = read_frame(frame)
    assert len(recs) == 500 and recs[7]["raw"].startswith("<38>") and recs[7]["ts"] == 1700000000007
    assert sum(len(x) for x in lines) / len(frame) > 4          # batch zstd on repetitive logs


def test_wire_string_is_lossless_for_all_bytes():
    blob = bytes(range(256)) * 50
    assert from_wire(to_wire(blob)) == blob
    assert to_wire(blob).encode("utf-8") != blob                # i.e. the latin-1 step is genuinely needed


def test_multiline_and_unicode_survive():
    raw = "Traceback (most recent call last):\n  File \"x.py\", line 1\nValueError: café ☃ \x00 end"
    recs = read_frame(FrameWriter().compress([envelope(1, "f" * 32, raw)]))
    assert recs[0]["raw"] == raw


def test_read_frame_rejects_garbage_and_bombs():
    with pytest.raises(ValueError):
        read_frame(b"not zstd at all")
    bomb = FrameWriter(19).compress([json.dumps({"raw": "A" * 5_000_000})])
    assert len(bomb) < 5000
    with pytest.raises(ValueError):
        read_frame(bomb, max_output=1_000_000)


# ---------------------------------------------------------------- config
def test_config_validation():
    assert JobConfig().window_ms == 300_000
    for bad in ({"compression": "gzip"}, {"delivery": "maybe"}, {"window_seconds": 0}, {"zstd_level": 30},
                {"batch_max_bytes": 10}, {"batch_shards": 0}):
        with pytest.raises(ValueError):
            JobConfig(**bad)
