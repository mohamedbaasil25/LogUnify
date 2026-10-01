"""PII redaction applied to every log BEFORE template mining, enrichment, batching, alerting or forwarding.

Detectors are validated, not just pattern-matched, to keep false positives (and altered evidence) low:
  card     13-19 digits, plausible network prefix, Luhn checksum, contiguous or 4-4-4-4 grouping
  email    RFC-ish address with an alphabetic TLD (so 'user@10.0.0.5' is left alone)
  ssn      US SSN with the invalid area/group/serial ranges excluded
  aadhaar  12 digits starting 2-9, Verhoeff checksum (India, DPDP Act)
  pan      Indian PAN: 5 letters + 4 digits + letter, 4th letter one of the valid holder types
  phone    Indian mobile numbers (optional: 10-digit numbers are ambiguous in logs, so off by default)

Modes: 'mask' -> [PII:card]; 'hash' -> [PII:card:3fa9c1d2e0], a keyed HMAC pseudonym, so the same value stays
correlatable across logs without being recoverable. What is redacted is gone downstream (SIEM, lake, Merkle batches,
alert evidence); unredacted originals exist only at the source and in the raw Kafka topic, so protect and expire those.
Heuristic: no regex detector finds everything; treat this as risk reduction, not a guarantee.
"""
import hashlib
import hmac
import re
from collections import Counter

ALL_TYPES = ("card", "email", "ssn", "aadhaar", "pan", "phone")
DEFAULT_TYPES = ("card", "email", "ssn", "aadhaar", "pan")

# ---------------------------------------------------------------------------------------------- checksums
_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff(num: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(payload: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(payload)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            d -= 9 if d > 9 else 0
        total += d
    return total % 10 == 0


def _plausible_card(d: str) -> bool:
    if not 13 <= len(d) <= 19 or not luhn(d):
        return False
    p2, p4 = int(d[:2]), int(d[:4])
    return (d[0] == "4" or 51 <= p2 <= 55 or 2221 <= p4 <= 2720 or p2 in (34, 37, 36, 38, 35, 60, 65, 81, 82)
            or 300 <= int(d[:3]) <= 305 or 644 <= int(d[:3]) <= 649 or d.startswith("508"))


# ---------------------------------------------------------------------------------------------- detectors
_CARD = re.compile(r"(?<![\w.-])(?:\d{13,19}|\d{4}(?:[ -]\d{4}){2}[ -]\d{1,7})(?![\w-])")
_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}\b")
_SSN = re.compile(r"(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])")
_AADHAAR = re.compile(r"(?<![\d-])([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})(?![\d-])")
_PAN = re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b")
_PHONE = re.compile(r"(?<![\d-])(?:\+91[ -]?|0)?[6-9]\d{9}(?![\d-])")


# cheap gates: most log lines contain no long digit run, no '@' and no PAN-like token, so the expensive validated detectors
# (and their per-match checksum functions) are skipped entirely for them
_DIGIT_RUN = re.compile(r"\d{9,}|\d{3}-\d{2}-\d{4}|\d{4}[ -]\d{4}[ -]\d{4}")


def _valid_ssn(m: re.Match) -> bool:
    area, group, serial = m.groups()
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


class PiiRedactor:
    def __init__(self, types=DEFAULT_TYPES, mode: str = "mask", key: str | None = None):
        types = tuple(types)
        bad = set(types) - set(ALL_TYPES)
        if bad:
            raise ValueError(f"unknown PII type(s) {sorted(bad)}; choose from {ALL_TYPES}")
        if mode not in ("mask", "hash"):
            raise ValueError("pii mode must be 'mask' or 'hash'")
        if mode == "hash" and not key:
            raise ValueError("pii mode 'hash' needs pii_hash_key (a secret) so pseudonyms cannot be brute-forced")
        self.types, self.mode, self._key = types, mode, (key or "").encode()

    def _token(self, kind: str, value: str) -> str:
        if self.mode == "mask":
            return f"[PII:{kind}]"
        norm = re.sub(r"[\s-]", "", value).lower()
        return f"[PII:{kind}:{hmac.new(self._key, norm.encode(), hashlib.sha256).hexdigest()[:10]}]"

    def redact(self, text: str) -> tuple[str, Counter]:
        found: Counter = Counter()
        if not text:
            return text, found

        def sub(kind, rx, ok=lambda m: True, text_in=None):
            def repl(m):
                if ok(m):
                    found[kind] += 1
                    return self._token(kind, m.group(0))
                return m.group(0)
            return rx.sub(repl, text_in)

        out = text
        digits = _DIGIT_RUN.search(text) is not None
        for kind in ("card", "aadhaar", "ssn", "pan", "email", "phone"):        # order: long digit runs before short ones
            if kind not in self.types:
                continue
            if (kind in ("card", "aadhaar", "ssn", "phone") and not digits) or (kind == "email" and "@" not in text):
                continue
            if kind == "card":
                out = sub(kind, _CARD, lambda m: _plausible_card(re.sub(r"\D", "", m.group(0))), out)
            elif kind == "aadhaar":
                out = sub(kind, _AADHAAR, lambda m: verhoeff("".join(m.groups())), out)
            elif kind == "ssn":
                out = sub(kind, _SSN, _valid_ssn, out)
            elif kind == "pan":
                out = sub(kind, _PAN, text_in=out)
            elif kind == "email":
                out = sub(kind, _EMAIL, text_in=out)
            else:
                out = sub(kind, _PHONE, text_in=out)
        return out, found

    def redact_value(self, value):
        """Strings are redacted in place; numbers that ARE a card/Aadhaar/phone (e.g. a JSON int) become tokens."""
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, int) and not isinstance(value, bool):
            new, found = self.redact(str(value))
            return (new, found) if found else (value, found)
        return value, Counter()

    def redact_parsed(self, parsed) -> Counter:
        """Redact a ParsedLog in place (original, message and every field value). Returns counts by type."""
        total: Counter = Counter()
        for attr in ("original", "message"):
            v = getattr(parsed, attr, None)
            if isinstance(v, str):
                new, found = self.redact(v)
                setattr(parsed, attr, new)
                total += found
        for k, v in list(parsed.fields.items()):
            new, found = self.redact_value(v)
            if found:
                parsed.fields[k] = new
                total += found
        return total
