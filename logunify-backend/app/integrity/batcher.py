from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone

from .ledger import AnchorReceipt
from .merkle import build_tree, hash_record, make_proof


@dataclass
class Batch:
    id: str
    seq: int
    root: str
    count: int
    leaves: list[str]              # hex leaf hashes, in record order
    docs: list[dict]
    first_ts: str | None
    last_ts: str | None
    sealed_at: str
    anchor: AnchorReceipt | None = None

    def summary(self) -> dict:
        return {"id": self.id, "seq": self.seq, "merkle_root": self.root, "count": self.count,
                "first_timestamp": self.first_ts, "last_timestamp": self.last_ts,
                "sealed_at": self.sealed_at, "anchor": self.anchor.to_dict() if self.anchor else None}


class BatchBuilder:
    """Collects ECS documents and seals a Merkle batch every `size` records. Thread-safe."""

    def __init__(self, size: int = 100, max_batches: int = 50, prefix: str = "batch"):
        self.size, self.max_batches, self.prefix = size, max_batches, prefix
        self._pending: list[dict] = []
        self._batches: OrderedDict[str, Batch] = OrderedDict()
        self._seq = 0
        self._lock = threading.Lock()

    def add(self, doc: dict) -> Batch | None:
        with self._lock:
            self._pending.append(doc)
            return self._seal() if len(self._pending) >= self.size else None

    def seal_partial(self) -> Batch | None:
        with self._lock:
            return self._seal() if self._pending else None

    @property
    def pending(self) -> int:
        return len(self._pending)

    def _seal(self) -> Batch:
        docs, self._pending = self._pending, []
        leaves = [hash_record(d) for d in docs]
        self._seq += 1
        stamps = [d.get("@timestamp") for d in docs]
        b = Batch(id=f"{self.prefix}-{self._seq:06d}", seq=self._seq, root=build_tree(leaves)[-1][0].hex(),
                  count=len(docs), leaves=[x.hex() for x in leaves], docs=docs,
                  first_ts=min((s for s in stamps if s), default=None),
                  last_ts=max((s for s in stamps if s), default=None),
                  sealed_at=datetime.now(timezone.utc).isoformat())
        self._batches[b.id] = b
        while len(self._batches) > self.max_batches:
            self._batches.popitem(last=False)
        return b

    def get(self, batch_id: str) -> Batch | None:
        return self._batches.get(batch_id)

    def find_leaf(self, leaf_hex: str | None) -> dict | None:
        """Where (if anywhere) a record's SHA-256 leaf hash was sealed: batch, position, root and ledger anchor.

        None while the record is still in the open batch. Only the most recent batches are held in memory.
        """
        if not leaf_hex:
            return None
        with self._lock:
            for b in reversed(self._batches.values()):
                if leaf_hex in b.leaves:
                    i = b.leaves.index(leaf_hex)
                    return {"batch_id": b.id, "index": i, "merkle_root": b.root,
                            "anchor_tx_id": b.anchor.tx_id if b.anchor else None,
                            "anchored_at": b.anchor.timestamp if b.anchor else None,
                            "proof_endpoint": f"/api/v1/integrity/batches/{b.id}/proof/{i}"}
        return None

    def list(self) -> list[Batch]:
        return list(reversed(self._batches.values()))

    def proof(self, batch_id: str, index: int) -> dict | None:
        b = self.get(batch_id)
        if b is None:
            return None
        levels = build_tree([bytes.fromhex(x) for x in b.leaves])
        return {"batch_id": b.id, "index": index, "record": b.docs[index] if 0 <= index < b.count else None,
                "leaf_hash": b.leaves[index], "merkle_root": b.root, "proof": make_proof(levels, index)}

    # ---- persistence (app/state) ------------------------------------------------------------------------------
    def snapshot(self) -> tuple[int, list[dict], list[Batch]]:
        """(sequence counter, copy of the open batch's records, sealed batches oldest first). Batches are shared, not copied."""
        with self._lock:
            return self._seq, list(self._pending), list(self._batches.values())

    def restore(self, seq: int, pending: list[dict], batches: list[Batch]) -> None:
        """Reload after a restart. The sequence is restored so new batch ids never collide with anchored ones."""
        with self._lock:
            self._seq = max(seq, max((b.seq for b in batches), default=0))
            self._pending = list(pending)
            self._batches = OrderedDict((b.id, b) for b in sorted(batches, key=lambda b: b.seq)[-self.max_batches:])
