"""SHA-256 Merkle tree over canonicalised ECS records. Pure functions, no I/O.

Hardening choices:
* Canonical JSON (sorted keys, compact separators) so key order / whitespace never changes a hash.
* Domain separation: leaf = SHA256(0x00 || record), node = SHA256(0x01 || left || right). Without it an
  attacker can present an internal node as a "record" (second-preimage attack on the tree).
* An unpaired node is promoted unchanged instead of duplicated, so [a, b, c] and [a, b, c, c] differ.
"""
import hashlib
import hmac
import json

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

ProofStep = dict   # {"hash": <64 hex>, "position": "left" | "right"}  (where the sibling sits)


def canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hash_record(record: dict) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + canonical(record)).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def build_tree(leaves: list[bytes]) -> list[list[bytes]]:
    """Return all levels, leaves first, root level (one hash) last."""
    if not leaves:
        raise ValueError("cannot build a Merkle tree from zero leaves")
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur, nxt = levels[-1], []
        for i in range(0, len(cur), 2):
            nxt.append(_node(cur[i], cur[i + 1]) if i + 1 < len(cur) else cur[i])
        levels.append(nxt)
    return levels


def merkle_root(records: list[dict]) -> str:
    return build_tree([hash_record(r) for r in records])[-1][0].hex()


def make_proof(levels: list[list[bytes]], index: int) -> list[ProofStep]:
    if not 0 <= index < len(levels[0]):
        raise IndexError(f"leaf index {index} out of range (0..{len(levels[0]) - 1})")
    proof, i = [], index
    for level in levels[:-1]:
        sib = i ^ 1
        if sib < len(level):                       # promoted (unpaired) nodes have no sibling at this level
            proof.append({"hash": level[sib].hex(), "position": "left" if sib < i else "right"})
        i //= 2
    return proof


def compute_root(record: dict, proof: list[ProofStep]) -> tuple[str, str]:
    """Fold a proof over the record's leaf hash. Returns (leaf_hash_hex, computed_root_hex)."""
    leaf = hash_record(record)
    return leaf.hex(), fold_proof(leaf, proof)


def fold_proof(leaf: bytes, proof: list[ProofStep]) -> str:
    """Fold a Merkle proof over an already-computed SHA-256 leaf hash; returns the computed root (hex)."""
    h = leaf
    for step in proof:
        sib = bytes.fromhex(step["hash"])
        if step["position"] == "left":
            h = _node(sib, h)
        elif step["position"] == "right":
            h = _node(h, sib)
        else:
            raise ValueError(f"bad proof position {step['position']!r}")
    return h.hex()


def verify_proof(record: dict, proof: list[ProofStep], root_hex: str) -> bool:
    try:
        _, computed = compute_root(record, proof)
    except (ValueError, KeyError, TypeError):
        return False
    return hmac.compare_digest(computed, root_hex.lower())
