from .base import ParsedLog, ParseError


def parse_text(raw: str) -> ParsedLog:
    """Unstructured free-text log: the whole line is the message; Drain3 extracts the rest downstream."""
    s = raw.strip()
    if not s:
        raise ParseError("empty log")
    return ParsedLog("text", s, None, s, {})
