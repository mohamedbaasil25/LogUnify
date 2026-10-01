"""Entry point kept for existing callers: parse one log with the default parser registry (see sdk.py)."""
from .base import ParsedLog
from .sdk import ParserRegistry, build_registry

_default: ParserRegistry | None = None


def default_registry() -> ParserRegistry:
    global _default
    if _default is None:
        _default = build_registry()
    return _default


def parse_auto(raw: str, hint: str | None = None) -> ParsedLog:
    """Detect the format (most confident parser wins) or use `hint` (a parser name), and parse. Raises ParseError."""
    return default_registry().parse(raw, hint)
