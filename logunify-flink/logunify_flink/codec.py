"""Output wire format: zstd frames of NDJSON envelopes, carried through Flink as latin-1 strings.

Why latin-1: PyFlink's Kafka sink can only serialise strings, and Flink's byte[] serializers add a length
prefix that would corrupt the frame. Decoding the compressed bytes as ISO-8859-1 maps every byte to exactly
one char (0-255) and the sink encodes it back with ISO-8859-1, so the bytes on the wire are the zstd frame,
byte for byte.
"""
import json

import zstandard as zstd

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"       # every zstd frame starts with this; consumers can sniff it
WIRE_CHARSET = "ISO-8859-1"


def envelope(ts_ms: int, fp: str, raw: str) -> str:
    """One NDJSON line. json.dumps escapes newlines, so a multi-line log stays a single line."""
    return json.dumps({"ts": ts_ms, "fp": fp, "raw": raw}, separators=(",", ":"), ensure_ascii=False)


class FrameWriter:
    def __init__(self, level: int = 3):
        self._c = zstd.ZstdCompressor(level=level, write_content_size=True)

    def compress(self, lines: list[str]) -> bytes:
        return self._c.compress(("\n".join(lines) + "\n").encode("utf-8"))


def to_wire(frame: bytes) -> str:
    return frame.decode("latin-1")


def from_wire(s: str) -> bytes:
    return s.encode("latin-1")


def read_frame(frame: bytes, max_output: int = 64 * 1024 * 1024) -> list[dict]:
    """Consumer side: decompress a frame into envelope dicts, refusing decompression bombs."""
    if frame[:4] != ZSTD_MAGIC:
        raise ValueError("not a zstd frame")
    with zstd.ZstdDecompressor().stream_reader(frame) as r:
        data = r.read(max_output + 1)
    if len(data) > max_output:
        raise ValueError(f"frame expands beyond {max_output} bytes")
    return [json.loads(line) for line in data.decode("utf-8").splitlines() if line]
