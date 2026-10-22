"""Small mutation tester for the code whose bugs are silent: PII redaction and the parsers.

    python scripts/mutation_test.py --target app/privacy/pii.py --tests tests/test_pii.py --sample 40 --min-score 0.6

Line coverage says a line ran, not that a test would notice if it were wrong. This applies ONE small change at a time
(comparison/boolean/arithmetic operator swap, constant +1, True<->False, `not` removed) to a deterministic random sample of
mutation sites, runs the given tests, and counts a mutant "killed" when they fail. Survivors are printed: each is either a
missing test or an equivalent mutant (changes nothing observable).

The file is rewritten in place for each run and always restored (also on Ctrl-C); do not run two instances on one file.
No external dependency (mutmut does not support Windows). Not a replacement for a full tool: it is a sampled, first-order check.
"""
import argparse
import ast
import random
import subprocess
import sys
from pathlib import Path

CMP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.GtE, ast.LtE: ast.Gt, ast.Gt: ast.LtE, ast.GtE: ast.Lt, ast.In: ast.NotIn,
       ast.NotIn: ast.In, ast.Is: ast.IsNot, ast.IsNot: ast.Is}
BIN = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.FloorDiv}
BOOL = {ast.And: ast.Or, ast.Or: ast.And}


def sites(tree: ast.AST) -> list[tuple[str, ast.AST, int]]:
    """(kind, node, sub-index) for every place a mutation can be applied. Docstrings and annotations are skipped."""
    out: list[tuple[str, ast.AST, int]] = []
    skip: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)) and n.body and isinstance(n.body[0], ast.Expr) \
                and isinstance(getattr(n.body[0], "value", None), ast.Constant):
            skip.add(id(n.body[0].value))
        for a in ("returns", "annotation"):
            ann = getattr(n, a, None)
            if ann is not None:
                skip.update(id(x) for x in ast.walk(ann))
    for n in ast.walk(tree):                              # lookup tables (Verhoeff etc.): one wrong cell is real, but drowns the signal
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.List) and n.value.elts and all(isinstance(e, (ast.List, ast.Constant)) for e in n.value.elts):
            skip.update(id(x) for x in ast.walk(n.value))
    for n in ast.walk(tree):
        if isinstance(n, ast.Compare):
            out += [("cmp", n, i) for i, op in enumerate(n.ops) if type(op) in CMP]
        elif isinstance(n, ast.BinOp) and type(n.op) in BIN:
            out.append(("bin", n, 0))
        elif isinstance(n, ast.BoolOp):
            out.append(("bool", n, 0))
        elif isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            out.append(("not", n, 0))
        elif isinstance(n, ast.Constant) and id(n) not in skip:
            if isinstance(n.value, bool) or (isinstance(n.value, int) and not isinstance(n.value, bool)):
                out.append(("const", n, 0))
    return out


def apply(kind: str, n: ast.AST, i: int) -> tuple:
    """Mutate in place; returns an undo token."""
    if kind == "cmp":
        old = n.ops[i]; n.ops[i] = CMP[type(old)](); return ("cmp", n, i, old)
    if kind == "bin":
        old = n.op; n.op = BIN[type(old)](); return ("bin", n, 0, old)
    if kind == "bool":
        old = n.op; n.op = BOOL[type(old)](); return ("bool", n, 0, old)
    if kind == "not":
        old = (n.op, n.operand)
        n.op = ast.UAdd(); return ("not", n, 0, old)          # +x instead of not x: changes truthiness semantics for the test
    old = n.value
    n.value = (not old) if isinstance(old, bool) else old + 1
    return ("const", n, 0, old)


def undo(tok: tuple) -> None:
    kind, n, i, old = tok
    if kind == "cmp":
        n.ops[i] = old
    elif kind in ("bin", "bool"):
        n.op = old
    elif kind == "not":
        n.op = old[0]
    else:
        n.value = old


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--tests", nargs="+", required=True)
    ap.add_argument("--sample", type=int, default=40)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--min-score", type=float, default=0.0)
    ap.add_argument("--timeout", type=int, default=120)
    a = ap.parse_args()

    path = Path(a.target)
    raw = path.read_bytes()
    original = raw.decode("utf-8")
    base = subprocess.run([sys.executable, "-m", "pytest", *a.tests, "-q", "-x", "-p", "no:cacheprovider"], capture_output=True, text=True)
    if base.returncode != 0:
        print("tests fail on the unmutated code; fix that first\n" + base.stdout[-1500:])
        return 2

    tree = ast.parse(original)
    all_sites = sites(tree)
    random.Random(a.seed).shuffle(all_sites)
    chosen = all_sites[: a.sample]
    killed, survived = 0, []
    try:
        for kind, node, i in chosen:
            tok = apply(kind, node, i)
            line = getattr(node, "lineno", 0)
            try:
                path.write_text(ast.unparse(tree), encoding="utf-8")
                try:
                    r = subprocess.run([sys.executable, "-m", "pytest", *a.tests, "-q", "-x", "-p", "no:cacheprovider"], capture_output=True,
                                       text=True, timeout=a.timeout)
                    dead = r.returncode != 0
                except subprocess.TimeoutExpired:
                    dead = True                                # a mutant that hangs the tests is detected
            finally:
                undo(tok)
            if dead:
                killed += 1
            else:
                survived.append(f"{path}:{line}  {kind}")
    finally:
        path.write_bytes(raw)

    score = killed / len(chosen) if chosen else 1.0
    print(f"{a.target}: {killed}/{len(chosen)} mutants killed ({score:.0%}), {len(all_sites)} sites in total")
    for s in sorted(survived):
        print("  SURVIVED", s)
    return 0 if score >= a.min_score else 1


if __name__ == "__main__":
    sys.exit(main())
