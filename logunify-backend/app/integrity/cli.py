"""Compute Merkle roots for batches of ECS logs.

    python -m app.integrity.cli logs.ndjson                 # one root per 100-record batch
    python -m app.integrity.cli logs.ndjson --proof 42      # also print + check the proof for record #42
    python -m app.integrity.cli --mock 250                  # generate mock ECS logs instead of reading a file
"""
import argparse
import json
import sys

from .merkle import build_tree, hash_record, make_proof, verify_proof


def _mock_docs(n: int) -> list[dict]:
    from ..ecs.normalizer import to_ecs
    from ..mock.generators import gen_log
    from ..parsers.detect import parse_auto
    docs = []
    while len(docs) < n:
        line, fmt = gen_log(0.0)
        docs.append(to_ecs(parse_auto(line)))
    return docs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", help="NDJSON file of ECS documents ('-' for stdin)")
    ap.add_argument("--mock", type=int, metavar="N", help="generate N mock ECS documents")
    ap.add_argument("--batch-size", type=int, default=100)
    ap.add_argument("--proof", type=int, metavar="N", help="print and verify the proof for global record index N")
    a = ap.parse_args(argv)

    if a.mock:
        docs = _mock_docs(a.mock)
    elif a.file:
        src = sys.stdin if a.file == "-" else open(a.file, encoding="utf-8")
        docs = [json.loads(line) for line in src if line.strip()]
    else:
        ap.error("give a file or --mock N")
    if not docs:
        print("no records", file=sys.stderr)
        return 1

    for start in range(0, len(docs), a.batch_size):
        batch = docs[start:start + a.batch_size]
        levels = build_tree([hash_record(d) for d in batch])
        print(json.dumps({"batch": start // a.batch_size + 1, "records": len(batch),
                          "merkle_root": levels[-1][0].hex()}))
        if a.proof is not None and start <= a.proof < start + len(batch):
            i = a.proof - start
            proof = make_proof(levels, i)
            ok = verify_proof(batch[i], proof, levels[-1][0].hex())
            print(json.dumps({"proof_for_record": a.proof, "index_in_batch": i, "proof": proof, "verified": ok}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
