from .base import ParsedLog, ParseError
from .cef import parse_cef
from .json_parser import parse_json
from .syslog import parse_syslog
from .text import parse_text

PARSERS = {"json": parse_json, "cef": parse_cef, "syslog": parse_syslog, "text": parse_text}


def parse_auto(raw: str, hint: str | None = None) -> ParsedLog:
    """Detect Syslog / JSON / CEF by cheap prefix sniffing (an explicit hint wins)."""
    s = raw.lstrip()
    if not s:
        raise ParseError("empty log")
    if hint:
        if hint not in PARSERS:
            raise ParseError(f"unknown format hint '{hint}'")
        return PARSERS[hint](raw)
    if s[0] == "{":
        return parse_json(raw)
    if "CEF:" in s[:64]:
        return parse_cef(raw)
    if s[0] == "<":
        return parse_syslog(raw)
    return parse_text(raw)          # unstructured text: Drain3 handles it downstream
