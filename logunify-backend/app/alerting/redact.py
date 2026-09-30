"""Redaction for log text that leaves the platform in notifications (email, webhook, chat).

Logs regularly contain credentials. CERT-In's FAQ (Q32) keeps confidentiality obligations unchanged, so alert text
carries a cleaned, truncated excerpt; the full record stays in the authenticated evidence endpoint.
Heuristic and incomplete by nature: it reduces exposure, it does not make a log safe to publish.
"""
import re

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_SECRET_KEYS = (r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
                r"auth(?:orization)?|cookie|session(?:id)?|credentials?)")
_PATTERNS = [
    # Scheme + credential first ("Authorization: Bearer <token>"): the generic key=value rule below would otherwise
    # consume only the word "Bearer" and leave the token itself in the text.
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    # password=hunter2 | "password": "hunter2" | token is abc123
    (re.compile(rf"(?i)\b({_SECRET_KEYS})\b([\"']?)(\s*[:=]\s*|\s+is\s+)(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)"),
     r"\1\2\3[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
     "[REDACTED-PRIVATE-KEY]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY-ID]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "[REDACTED-TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED-TOKEN]"),
]


def clean(text: str) -> str:
    """Strip control characters and collapse whitespace (safe for headers, logs and single-line fields)."""
    return " ".join(_CTRL.sub(" ", str(text)).split())


def redact(text: str | None, max_len: int = 400) -> str:
    if not text:
        return ""
    out = str(text)
    for rx, repl in _PATTERNS:
        out = rx.sub(repl, out)
    out = clean(out)
    return out if len(out) <= max_len else out[:max_len] + f"... [truncated {len(out) - max_len} chars]"
