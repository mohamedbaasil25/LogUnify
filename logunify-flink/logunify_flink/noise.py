"""Noise filter: decides whether a raw log is operational chatter that should never reach the SIEM.

Order matters: empty -> security-signal guard -> debug level -> chatter patterns. The guard runs before
everything else so an alert-worthy line is *never* dropped just because it also looks like chatter
(e.g. a debug-level line that says "authentication failed").
"""
import re

DEFAULT_DROP = [
    r"\bhealth[-_ ]?check(?:er|s)?\b",
    r"\bheartbeat\b",
    r"\bkeep[- ]?alive\b",
    r"ELB-HealthChecker",
    r"\bGET\s+/(?:health|healthz|ready|readyz|livez|ping|status)\b",
    r"pam_unix\(cron:session\)",                 # cron session open/close, no security value on its own
    r"\bntpd?\b.*\b(?:sync|adjust|offset)",
]
DEFAULT_KEEP = [
    r"fail(?:ed|ure)?", r"denied", r"unauthori[sz]ed", r"invalid", r"refused", r"forbidden", r"blocked",
    r"attack", r"exploit", r"malware", r"ransom", r"injection", r"privilege", r"violation", r"exfil",
    r"\bsudo\b", r"\broot\b", r"\bCEF:",
]

_PRI = re.compile(r"^<(\d{1,3})>")
_JSON_DEBUG = re.compile(r'"(?:level|severity|loglevel)"\s*:\s*"(?:debug|trace)"', re.I)
_TEXT_DEBUG = re.compile(r"(?:^|[\s\[])(?:DEBUG|TRACE)(?:[\]:\s])")


class NoiseFilter:
    def __init__(self, drop_debug: bool = True, extra_drop: tuple[str, ...] = (), extra_keep: tuple[str, ...] = ()):
        self.drop_debug = drop_debug
        self._drop = [re.compile(p, re.I) for p in (*DEFAULT_DROP, *extra_drop)]
        self._keep = re.compile("|".join(f"(?:{p})" for p in (*DEFAULT_KEEP, *extra_keep)), re.I)

    def reason(self, raw: str) -> str | None:
        """Why this log is noise, or None if it should be kept."""
        s = raw.strip()
        if not s:
            return "empty"
        if self._keep.search(s):
            return None
        if self.drop_debug:
            m = _PRI.match(s)
            if m and int(m.group(1)) & 7 == 7:          # syslog severity 7 = debug
                return "debug"
            if _JSON_DEBUG.search(s) or _TEXT_DEBUG.search(s[:200]):
                return "debug"
        for p in self._drop:
            if p.search(s):
                return "chatter"
        return None
