from dataclasses import dataclass, field
from typing import Any


class ParseError(ValueError):
    """Raised when a raw log cannot be interpreted by a parser."""


@dataclass
class ParsedLog:
    """Format-neutral intermediate representation produced by every parser."""
    format: str
    original: str
    timestamp: str | None = None
    message: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)  # dotted ECS field names
    parser: str = ""              # registry name + version of the parser that produced this (set by the registry)
    parser_version: str = ""
