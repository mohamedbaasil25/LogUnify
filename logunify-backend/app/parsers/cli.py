"""Parser developer CLI.

    python -m app.parsers.cli list [--parser-dir DIR]
    python -m app.parsers.cli try NAME "raw log line" [--parser-dir DIR]        # show the normalized ECS document
    python -m app.parsers.cli scaffold NAME [--dir DIR]                          # new declarative parser + first fixture
    python -m app.parsers.cli test [NAME] [--parser-dir DIR] [--fixtures DIR] [--update]

`test` exits 1 on any failure and is meant for CI. A parser with no fixtures is reported and fails `test --strict`.
"""
import argparse
import json
import sys
from pathlib import Path

from .fixtures import normalize, run_fixtures, untested_parsers
from .sdk import build_registry

DEFAULT_FIXTURES = Path(__file__).resolve().parents[2] / "parser_fixtures"

TEMPLATE = '''# Declarative parser for NAME. Edit, then:  python -m app.parsers.cli test NAME --parser-dir DIR --fixtures FIXDIR
name: NAME
version: "0.1.0"
kind: regex                  # regex = text lines with named groups | json = map JSON paths
description: describe the source and the log format here
priority: 10                 # ties between equally confident parsers go to the higher priority
sniff:                       # cheap test: "is this line in my format?"  (contains: [...] and/or regex: '...')
  contains: ["REPLACE_ME"]
  confidence: 0.9            # must beat the generic parsers: json 0.95, cef 0.9, syslog 0.8, text 0.01
match:
  regex: '^(?P<ts>\\S+) (?P<host>\\S+) (?P<msg>.*)$'
timestamp:
  field: ts
  # format: "%Y-%m-%dT%H:%M:%S%z"   # strptime format; omit for ISO-8601. No UTC offset? the source's timezone setting applies
message: "{msg}"
fields:                      # ECS field: {from: <regex group>, type: ip|int|float|bool, transform: lower|upper|strip, drop_if: [...]}
  host.name: {from: host}
static:                      # constants (taxonomy: use ECS allowed values)
  event.kind: event
  event.category: [host]
  event.type: [info]
  event.module: NAME
'''


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("list", "try", "test", "scaffold"):
        sp = sub.add_parser(name)
        sp.add_argument("--parser-dir", default="", help="extra parsers (*.yaml, *.py)")
        if name == "try":
            sp.add_argument("name")
            sp.add_argument("line")
        if name == "test":
            sp.add_argument("name", nargs="?")
            sp.add_argument("--fixtures", default=str(DEFAULT_FIXTURES))
            sp.add_argument("--update", action="store_true", help="(re)write .expected.json from current output: review the diff!")
            sp.add_argument("--strict", action="store_true", help="also fail for parsers that have no fixtures")
        if name == "scaffold":
            sp.add_argument("name")
            sp.add_argument("--dir", default="parsers.d")
            sp.add_argument("--fixtures", default=str(DEFAULT_FIXTURES))
    a = ap.parse_args(argv)
    reg = build_registry(a.parser_dir)

    if a.cmd == "list":
        for i in reg.info():
            print(f"{i['name']:20s} v{i['version']:8s} {i['kind']:10s} prio {i['priority']:<4d} {i['description']}")
        for e in reg.errors:
            print("LOAD ERROR:", e)
        return 1 if reg.errors else 0

    if a.cmd == "try":
        try:
            print(json.dumps(normalize(reg, a.line, a.name), indent=2, ensure_ascii=False))
        except Exception as e:
            print(f"parse failed: {e}")
            return 1
        return 0

    if a.cmd == "scaffold":
        if not a.name.replace("_", "").isalnum() or not a.name[0].isalpha() or a.name != a.name.lower():
            print("name must be lowercase letters, digits and underscores, starting with a letter")
            return 2
        d, fx = Path(a.dir), Path(a.fixtures) / a.name
        d.mkdir(parents=True, exist_ok=True)
        fx.mkdir(parents=True, exist_ok=True)
        target = d / f"{a.name}.yaml"
        if target.exists():
            print(f"{target} already exists; not overwriting")
            return 2
        target.write_text(TEMPLATE.replace("NAME", a.name).replace("DIR", str(d)).replace("FIXDIR", str(Path(a.fixtures))), encoding="utf-8")
        (fx / "001.log").write_text("2026-10-01T10:00:00Z web-01 REPLACE_ME example message\n", encoding="utf-8")
        print(f"created {target} and {fx / '001.log'}: put a real sample line in the .log, edit the parser, run `test {a.name} --update`")
        return 0

    root = Path(a.fixtures)
    results = run_fixtures(reg, root, a.name, a.update)
    bad = [r for r in results if not r.ok]
    for r in results:
        print(("PASS " if r.ok else "FAIL ") + f"{r.parser}/{r.case}")
        for p in r.problems:
            print("     -", p)
    missing = untested_parsers(reg, root)
    if missing:
        print("no fixtures for:", ", ".join(missing))
    print(f"\n{len(results) - len(bad)}/{len(results)} cases passed")
    return 1 if bad or reg.errors or (a.strict and missing) else 0


if __name__ == "__main__":
    sys.exit(main())
