"""Parser SDK: how a new log source is onboarded without touching the pipeline.

Three ways, from least to most code:
  1. DECLARATIVE: drop a YAML file in the parser directory (LOGUNIFY_PARSER_DIR) describing how to recognise the log and map it to
     ECS (regex with named groups, or JSON paths). No Python. See parsers/builtin/*.yaml for worked examples.
  2. PYTHON PLUGIN: a .py file in the same directory that defines `PARSERS = [MyParser(), ...]` (objects implementing `Parser`).
  3. PACKAGE: a pip-installable package exposing an entry point in the group `logunify.parsers` that returns a Parser (or a list).

A parser is: `name`, `version`, `sniff(text) -> float` (confidence 0..1 that the text is in its format; 0 = not mine) and
`parse(text) -> ParsedLog`. With no format hint the registry asks every parser to sniff and uses the most confident one (ties go to
the higher priority, then registration order); a hint selects a parser by name. The registry stamps `parser` + `parser_version` on
the result, and they end up on every normalized document (`logunify.parser.*`), so a record can always be traced to the exact
parser version that produced it.

TRUST BOUNDARY: parser files are code-equivalent configuration. Anyone who can write the parser directory can make the pipeline
run their regexes (ReDoS) or Python. Deploy them like code (reviewed, read-only mount); the API never accepts parser uploads.
Declarative regexes are linted for catastrophic-backtracking shapes and matched only against the first `max_line` characters.
"""
import importlib.metadata
import importlib.util
import ipaddress
import json
import logging
import re
import sys
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Protocol, runtime_checkable

import yaml

from .base import ParsedLog, ParseError

log = logging.getLogger("logunify.parsers")


@runtime_checkable
class Parser(Protocol):
    name: str
    version: str

    def sniff(self, text: str) -> float: ...
    def parse(self, text: str) -> ParsedLog: ...


class FunctionParser:
    """Adapter for a plain function + a sniff function: how the built-in syslog / JSON / CEF / text parsers are registered."""

    def __init__(self, name: str, version: str, fn: Callable[[str], ParsedLog], sniff: Callable[[str], float], description: str = ""):
        self.name, self.version, self._fn, self._sniff, self.description = name, version, fn, sniff, description

    def sniff(self, text: str) -> float:
        return self._sniff(text)

    def parse(self, text: str) -> ParsedLog:
        return self._fn(text)


class ParserRegistry:
    def __init__(self):
        self._parsers: dict[str, tuple[Parser, int, int]] = {}      # name -> (parser, priority, order)
        self._n = 0
        self.errors: list[str] = []                                  # files / entry points that failed to load

    def register(self, parser: Parser, *, priority: int = 0, replace: bool = False) -> None:
        if not isinstance(parser, Parser):
            raise TypeError(f"{parser!r} does not implement the Parser protocol (name, version, sniff(), parse())")
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,40}", parser.name):
            raise ValueError(f"parser name {parser.name!r} must match [a-z][a-z0-9_]{{1,40}}")
        if parser.name in self._parsers and not replace:
            raise ValueError(f"parser '{parser.name}' is already registered")
        self._n += 1
        self._parsers[parser.name] = (parser, priority, self._n)

    def get(self, name: str) -> Parser | None:
        e = self._parsers.get(name)
        return e[0] if e else None

    def names(self) -> list[str]:
        return sorted(self._parsers)

    def info(self) -> list[dict]:
        return [{"name": p.name, "version": p.version, "priority": pr, "description": getattr(p, "description", ""),
                 "kind": getattr(p, "kind", "python")} for p, pr, _ in sorted(self._parsers.values(), key=lambda e: e[2])]

    def detect(self, text: str) -> Parser | None:
        best, best_key = None, None
        for p, pr, order in self._parsers.values():
            try:
                c = float(p.sniff(text))
            except Exception:
                log.exception("parser %s: sniff() raised; ignoring it for this log", p.name)
                continue
            if c <= 0:
                continue
            key = (c, pr, -order)
            if best_key is None or key > best_key:
                best, best_key = p, key
        return best

    def parse(self, text: str, hint: str | None = None) -> ParsedLog:
        if not text.strip():
            raise ParseError("empty log")
        if hint:
            p = self.get(hint)
            if p is None:
                raise ParseError(f"unknown format hint '{hint}'")
        else:
            p = self.detect(text)
            if p is None:
                raise ParseError("no parser recognised this log")
        out = p.parse(text)
        out.parser, out.parser_version = p.name, p.version
        return out

    # ---- discovery ---------------------------------------------------------------------------------------------------
    def load_dir(self, directory: str | Path) -> list[str]:
        """Register every *.yaml / *.yml (declarative) and *.py (plugin) in `directory`. A bad file is skipped with an error log
        and reported in the return value's 'errors': it must not stop the others, or the service."""
        d, loaded = Path(directory), []
        if not d.is_dir():
            return loaded
        for f in sorted(d.iterdir()):
            try:
                if f.suffix in (".yaml", ".yml"):
                    p = DeclarativeParser.from_file(f)
                    self.register(p, priority=p.priority)
                    loaded.append(p.name)
                elif f.suffix == ".py" and not f.name.startswith("_"):
                    for p in _load_plugin(f):
                        self.register(p)
                        loaded.append(p.name)
            except Exception as e:
                log.error("parser file %s skipped: %s", f, e)
                self.errors.append(f"{f.name}: {e}")
        return loaded

    def load_entry_points(self) -> list[str]:
        loaded = []
        for ep in importlib.metadata.entry_points(group="logunify.parsers"):
            try:
                obj = ep.load()
                obj = obj() if callable(obj) and not isinstance(obj, Parser) else obj
                for p in (obj if isinstance(obj, (list, tuple)) else [obj]):
                    self.register(p)
                    loaded.append(p.name)
            except Exception as e:
                log.error("parser entry point %s failed: %s", ep.name, e)
                self.errors.append(f"entry point {ep.name}: {e}")
        return loaded


def _load_plugin(path: Path) -> list[Parser]:
    spec = importlib.util.spec_from_file_location(f"logunify_parser_plugin_{path.stem}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    parsers = getattr(mod, "PARSERS", None)
    if parsers is None:
        raise ValueError("plugin must define PARSERS = [<Parser>, ...]")
    return list(parsers)


# =============================================================================================================================
# Declarative parsers
# =============================================================================================================================
_REDOS = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]")      # (a+)+ , (a*)* , (.+)* ...: nested unbounded quantifiers


def _check_regex(rx: str, where: str) -> re.Pattern:
    if _REDOS.search(rx):
        raise ValueError(f"{where}: regex has nested unbounded quantifiers (catastrophic backtracking risk): {rx[:80]}")
    try:
        return re.compile(rx)
    except re.error as e:
        raise ValueError(f"{where}: invalid regex ({e})") from None


@lru_cache(maxsize=8)
def _loads(text: str):
    """JSON parse shared by every json-kind parser's sniff() and parse() for the same log line (one parse, not N)."""
    return json.loads(text)


def _dig(obj: Any, path: str) -> Any:
    for part in path.split("."):
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        elif isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
            obj = obj[int(part)]
        else:
            return None
    return obj


def _ts(value: Any, fmt: str | None) -> str | None:
    if value in (None, ""):
        return None
    if fmt == "epoch":
        return str(value)
    if fmt:
        try:
            return datetime.strptime(str(value), fmt).isoformat() if "%z" not in fmt else datetime.strptime(str(value), fmt).astimezone(
                timezone.utc).isoformat()
        except ValueError:
            return None                              # unparseable: the normalizer falls back to receive time and flags it
    return str(value)


_TRANSFORMS = {"lower": str.lower, "upper": str.upper, "strip": str.strip}


def _coerce(v: Any, spec: dict) -> Any:
    """Apply type / transform / drop_if / map from one field spec. Returns None to drop the field."""
    if v is None or v == "":
        return None
    if str(v) in [str(x) for x in spec.get("drop_if", [])]:
        return None
    t = spec.get("transform")
    if t:
        v = _TRANSFORMS[t](str(v))
    if "map" in spec:
        v = spec["map"].get(str(v), spec["map"].get("default", v))
    ty = spec.get("type")
    try:
        if ty == "int":
            return int(v)
        if ty == "float":
            return float(v)
        if ty == "ip":
            ipaddress.ip_address(str(v).strip())
            return str(v).strip()
        if ty == "bool":
            return str(v).strip().lower() in ("1", "true", "yes", "y")
        if ty == "list":
            return list(v) if isinstance(v, (list, tuple)) else [v]
    except (ValueError, TypeError):
        return None                                   # invalid ip / number: drop it rather than break the ES mapping
    return v if isinstance(v, (list, dict, int, float, bool)) else str(v)


def _predicate(cond: dict, getter: Callable[[str], Any]) -> bool:
    v = getter(cond["field"])
    if v is None:
        return False
    if "equals" in cond:
        return str(v) == str(cond["equals"])
    if "in" in cond:
        return str(v) in [str(x) for x in cond["in"]]
    if "regex" in cond:
        return re.search(cond["regex"], str(v)) is not None
    try:
        f = float(v)
    except ValueError:
        return False
    # every numeric operator that is present must hold (gte: 400 + lt: 500 is the range 400..499)
    ops = (("gte", lambda a, b: a >= b), ("gt", lambda a, b: a > b), ("lte", lambda a, b: a <= b), ("lt", lambda a, b: a < b))
    return all(fn(f, cond[k]) for k, fn in ops if k in cond)


class DeclarativeParser:
    """A parser defined entirely by a YAML document (kind: regex | json). Validated at load time, never at log time."""

    max_line = 8192                                    # declarative regexes are only run on the first N characters

    def __init__(self, spec: dict, source: str = "<memory>"):
        self.spec = spec
        self.name, self.version = str(spec["name"]), str(spec["version"])
        self.description = str(spec.get("description", ""))
        self.kind = spec.get("kind", "regex")
        self.priority = int(spec.get("priority", 10))
        if self.kind not in ("regex", "json"):
            raise ValueError("kind must be 'regex' or 'json'")
        sn = spec.get("sniff") or {}
        self._sniff_conf = float(sn.get("confidence", 0.85))
        self._sniff_contains = [str(x) for x in sn.get("contains", [])]
        self._sniff_rx = _check_regex(sn["regex"], f"{self.name}.sniff") if sn.get("regex") else None
        self._sniff_keys = [str(x) for x in sn.get("keys", [])]            # json: all of these paths must exist
        if not (self._sniff_contains or self._sniff_rx or self._sniff_keys):
            raise ValueError("sniff needs at least one of: contains, regex, keys")
        self._rx = _check_regex(spec["match"]["regex"], f"{self.name}.match") if self.kind == "regex" else None
        if self.kind == "regex" and not self._rx.groupindex:
            raise ValueError("match.regex needs named groups (?P<name>...)")
        self._fields: dict[str, dict] = {k: (v if isinstance(v, dict) else {"from": v}) for k, v in (spec.get("fields") or {}).items()}
        for k, v in self._fields.items():
            if "from" not in v and "path" not in v and "value" not in v and "first_of" not in v:
                raise ValueError(f"field {k}: needs 'from' (regex group), 'path' (json path), 'first_of' (list of json paths) or 'value'")
            if v.get("transform") and v["transform"] not in _TRANSFORMS:
                raise ValueError(f"field {k}: unknown transform {v['transform']}")
            if v.get("from") and self._rx is not None and v["from"] not in self._rx.groupindex:
                raise ValueError(f"field {k}: regex has no group named '{v['from']}'")
        self._static = spec.get("static") or {}
        self._rules = spec.get("rules") or []
        self._ts_spec = spec.get("timestamp") or {}
        self._msg = spec.get("message")
        self._msg_path = spec.get("message_path")
        self.source = source

    @classmethod
    def from_file(cls, path: Path) -> "DeclarativeParser":
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(spec, dict) or "name" not in spec or "version" not in spec:
            raise ValueError("a parser file needs at least `name` and `version`")
        return cls(spec, str(path))

    # ---- Parser protocol ---------------------------------------------------------------------------------------------
    def sniff(self, text: str) -> float:
        head = text[:self.max_line]
        if self.kind == "json":
            s = head.lstrip()
            if not s.startswith("{"):
                return 0.0
            try:
                obj = _loads(text)
            except ValueError:
                return 0.0
            return self._sniff_conf if all(_dig(obj, k) is not None for k in self._sniff_keys) and \
                all(c in text for c in self._sniff_contains) else 0.0
        if all(c in head for c in self._sniff_contains) and (self._sniff_rx is None or self._sniff_rx.search(head)):
            return self._sniff_conf
        return 0.0

    def parse(self, text: str) -> ParsedLog:
        raw = text.strip()
        if self.kind == "json":
            try:
                obj = _loads(raw)
            except ValueError as e:
                raise ParseError(f"{self.name}: invalid JSON") from e
            groups = None
        else:
            m = self._rx.match(raw[:self.max_line])
            if not m:
                raise ParseError(f"{self.name}: line does not match the expected format")
            groups, obj = m.groupdict(), None
        out: dict[str, Any] = {}
        for ecs, spec in self._fields.items():
            v = _coerce(self._value(spec, groups, obj), spec)
            if v is not None:
                out[ecs] = v
        raw_get = (lambda g: groups.get(g)) if groups is not None else (lambda p: _dig(obj, p))
        for rule in self._rules:                                           # rules read raw group values / json paths
            conds = rule.get("when") or []
            conds = [conds] if isinstance(conds, dict) else conds
            if all(_predicate(c, raw_get) for c in conds):
                out.update(rule.get("set", {}))
                for ecs, src in (rule.get("copy") or {}).items():          # re-point a field: {user.name: SubjectUserName} (the actor, not the target)
                    if (v := _coerce(raw_get(src), {})) is not None:
                        out[ecs] = v
        for k, v in self._static.items():
            out.setdefault(k, v)
        ts = self._timestamp(groups, obj)
        msg = self._message(groups, obj, raw)
        return ParsedLog(self.name, raw, ts, msg, out)

    # ---- helpers -----------------------------------------------------------------------------------------------------
    @staticmethod
    def _value(spec: dict, groups: dict | None, obj: Any) -> Any:
        if "value" in spec:
            return spec["value"]
        if "first_of" in spec:                                   # several possible JSON paths (different shippers name a field differently)
            for pth in spec["first_of"]:
                if obj is not None and (v := _dig(obj, pth)) not in (None, ""):
                    return v
            return None
        if "path" in spec:
            return _dig(obj, spec["path"]) if obj is not None else None
        return groups.get(spec["from"]) if groups is not None else None

    def _timestamp(self, groups, obj) -> str | None:
        t = self._ts_spec
        if not t:
            return None
        v = groups.get(t["field"]) if groups is not None else _dig(obj, t.get("path", t.get("field", "")))
        return _ts(v, t.get("format"))

    def _message(self, groups, obj, raw: str) -> str | None:
        if self._msg and groups is not None:
            try:
                return self._msg.format_map(_Safe({k: ("" if v is None else v) for k, v in groups.items()}))
            except Exception:
                return raw
        if self._msg_path and obj is not None:
            v = _dig(obj, self._msg_path)
            return None if v is None else str(v)
        return raw if groups is not None else None


class _Safe(dict):
    def __missing__(self, key):
        return ""


# =============================================================================================================================
# Default registry: built-ins + declarative built-ins + plugin directory + entry points
# =============================================================================================================================
def _builtin_registry() -> ParserRegistry:
    from .cef import parse_cef
    from .json_parser import parse_json
    from .syslog import parse_syslog
    from .text import parse_text
    r = ParserRegistry()
    pri = re.compile(r"^<\d{1,3}>")
    r.register(FunctionParser("json", "1.0.0", parse_json, lambda t: 0.95 if t.lstrip()[:1] == "{" else 0.0,
                              "Generic JSON object: well-known keys mapped to ECS, the rest under labels.*"), priority=0)
    r.register(FunctionParser("cef", "1.0.0", parse_cef, lambda t: 0.9 if "CEF:" in t.lstrip()[:64] else 0.0,
                              "ArcSight Common Event Format (plain or inside a syslog envelope)"), priority=0)
    r.register(FunctionParser("syslog", "1.0.0", parse_syslog, lambda t: 0.8 if pri.match(t.lstrip()) else 0.0,
                              "RFC 3164 / RFC 5424 syslog"), priority=0)
    r.register(FunctionParser("text", "1.0.0", parse_text, lambda t: 0.01, "Unstructured text (fallback; Drain3 mines templates)"),
               priority=-100)
    for p in (r.get(n) for n in r.names()):
        p.kind = "builtin"
    return r


def build_registry(parser_dir: str = "", entry_points: bool = True) -> ParserRegistry:
    r = _builtin_registry()
    r.load_dir(Path(__file__).parent / "builtin")                     # declarative parsers shipped with LogUnify
    if parser_dir:
        r.load_dir(parser_dir)
    if entry_points:
        r.load_entry_points()
    return r
