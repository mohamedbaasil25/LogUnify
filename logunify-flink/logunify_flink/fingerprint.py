"""Deduplication fingerprint: identical events must hash identically even though their volatile envelope differs.

We mask only what carries no security meaning (timestamps, PIDs, ephemeral source ports, request/trace ids).
We deliberately do NOT mask IPs, users, hostnames or messages: two attempts from different attackers are
different events, and collapsing them would hide real signal.
"""
import hashlib
import json
import re

_MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
_TEXT_MASKS = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<ts>"),
    (re.compile(rf"\b(?:{_MONTHS})\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\b"), "<ts>"),
    (re.compile(r"(?<![\d.])1\d{9}(?:\.\d+)?(?![\d.])|(?<!\d)1\d{12}(?!\d)"), "<epoch>"),   # 10/13-digit epoch
    (re.compile(r"\[\d+\]"), "[]"),                                                        # sshd[1234]
    (re.compile(r"\b(port|spt)([ =])\d+", re.I), r"\1\2<p>"),                                # ephemeral ports
    (re.compile(r"\b(rt|start|end)=\d+"), r"\1=<ts>"),                                       # CEF times
]
VOLATILE_JSON_KEYS = frozenset({
    "timestamp", "@timestamp", "time", "ts", "datetime", "eventtime", "pid", "request_id", "requestid",
    "trace_id", "traceid", "span_id", "spanid", "latency_ms", "duration_ms", "elapsed_ms",
})
_MAX_CHARS = 8192          # fingerprint the head only: bounded CPU per record


def _strip_json(obj):
    if isinstance(obj, dict):
        return {k: _strip_json(v) for k, v in obj.items() if k.lower() not in VOLATILE_JSON_KEYS}
    if isinstance(obj, list):
        return [_strip_json(v) for v in obj]
    return obj


def normalize(raw: str) -> str:
    s = raw.strip()[:_MAX_CHARS]
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                s = json.dumps(_strip_json(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except ValueError:
            pass
    for rx, repl in _TEXT_MASKS:
        s = rx.sub(repl, s)
    return " ".join(s.split())          # syslog <PRI> is deliberately kept: severity is signal


def fingerprint(raw: str) -> str:
    return hashlib.blake2b(normalize(raw).encode("utf-8", "replace"), digest_size=16).hexdigest()
