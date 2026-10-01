"""Golden-file test harness for parsers: the contract every parser (shipped, declarative, plugin) must keep.

Layout:   <fixtures>/<parser name>/<case>.log              one raw log line
          <fixtures>/<parser name>/<case>.expected.json    expected ECS fields (dotted names -> value), a SUBSET of the document

For every case it checks that
  1. the parser named by the directory parses the line (and the fields in .expected.json are present with those values);
  2. AUTO-DETECTION picks the same parser (a parser whose sniff() is too greedy or too shy breaks plug-and-play, so it is a failure);
  3. the resulting normalized document has ZERO ECS violations (validate.py);
  4. a `<case>.log` with no `.expected.json` is a failure, not a pass: write the expectation (`--update`) and review it.
Time-dependent fields are pinned (fixed receive time) so expectations are stable.
"""
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..ecs.normalizer import to_ecs
from ..ecs.taxonomy import categorize
from ..ecs.validate import flatten, validate
from .base import ParseError
from .sdk import ParserRegistry

FIXED = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
VOLATILE = {"event.ingested", "event.created"}


@dataclass
class CaseResult:
    parser: str
    case: str
    ok: bool
    problems: list[str] = field(default_factory=list)


def normalize(registry: ParserRegistry, line: str, hint: str | None = None, tz: str | None = None) -> dict:
    parsed = registry.parse(line, hint)
    categorize(parsed.fields, parsed.parser or parsed.format)
    parsed.fields["logunify.parser.name"] = parsed.parser
    return to_ecs(parsed, now=FIXED, tz=tz, received=FIXED)


def _flat(doc: dict) -> dict:
    return {k: v for k, v in flatten(doc) if k not in VOLATILE}


def run_case(registry: ParserRegistry, parser: str, log_file: Path) -> CaseResult:
    case = log_file.stem
    res = CaseResult(parser, case, True)
    line = log_file.read_text(encoding="utf-8").rstrip("\r\n")
    exp_file = log_file.with_suffix(".expected.json")
    try:
        doc = normalize(registry, line, parser)
    except ParseError as e:
        return CaseResult(parser, case, False, [f"parser '{parser}' rejected the line: {e}"])
    detected = registry.detect(line)
    if detected is None or detected.name != parser:
        res.problems.append(f"auto-detection chose '{detected.name if detected else None}', not '{parser}' (fix sniff() / priority)")
    for rule, fld, detail in validate(doc):
        res.problems.append(f"ECS {rule} {fld}: {detail}")
    if not exp_file.exists():
        res.problems.append(f"missing {exp_file.name} (run with --update, then review it)")
    else:
        got, want = _flat(doc), json.loads(exp_file.read_text(encoding="utf-8"))
        for k, v in want.items():
            if got.get(k) != v:
                res.problems.append(f"{k}: expected {v!r}, got {got.get(k)!r}")
    res.ok = not res.problems
    return res


def run_fixtures(registry: ParserRegistry, root: Path, only: str | None = None, update: bool = False) -> list[CaseResult]:
    results: list[CaseResult] = []
    for pdir in sorted(p for p in root.iterdir() if p.is_dir()) if root.is_dir() else []:
        if only and pdir.name != only:
            continue
        if registry.get(pdir.name) is None:
            results.append(CaseResult(pdir.name, "-", False, [f"fixtures exist but no parser named '{pdir.name}' is loaded"]))
            continue
        for lf in sorted(pdir.glob("*.log")):
            if update:
                try:
                    doc = normalize(registry, lf.read_text(encoding="utf-8").rstrip("\r\n"), pdir.name)
                    lf.with_suffix(".expected.json").write_text(
                        json.dumps(_flat(doc), indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
                except ParseError:
                    pass
            results.append(run_case(registry, pdir.name, lf))
    return results


def untested_parsers(registry: ParserRegistry, root: Path, ignore: set[str] = frozenset()) -> list[str]:
    """Parsers with no fixture directory: onboarding is not finished until there is at least one golden case."""
    have = {p.name for p in root.iterdir() if p.is_dir()} if root.is_dir() else set()
    return [n for n in registry.names() if n not in have and n not in ignore]
