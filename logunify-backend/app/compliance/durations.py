import re

_UNIT = {"d": 1.0, "h": 1 / 24, "m": 1 / 1440, "s": 1 / 86400, "ms": 1 / 86_400_000, "micros": 1e-6 / 86400,
         "nanos": 1e-9 / 86400}


def to_days(s: str) -> float:
    """Elasticsearch time value ('180d', '3.5h', '12.4d') -> days."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(d|h|ms|micros|nanos|m|s)\s*", str(s))
    if not m:
        raise ValueError(f"bad duration {s!r}")
    return float(m.group(1)) * _UNIT[m.group(2)]
