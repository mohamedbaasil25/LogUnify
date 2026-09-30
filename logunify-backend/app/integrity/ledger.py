"""MOCK Hyperledger Fabric ledger.

Simulates committing a Merkle-root anchor transaction. There is no endorsement, ordering service or
persistence: everything lives in memory and disappears on restart. A real integration would replace this
class with a Fabric Gateway client exposing the same two methods (submit_anchor / get_anchor).
"""
import hashlib
import secrets
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

CHANNEL = "logchannel"
CHAINCODE = "logintegrity"


@dataclass(frozen=True)
class AnchorReceipt:
    tx_id: str
    batch_id: str
    merkle_root: str
    timestamp: str
    block_number: int
    channel: str
    chaincode: str
    status: str
    mock: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


class MockFabricLedger:
    def __init__(self):
        self._lock = threading.Lock()
        self._by_tx: dict[str, AnchorReceipt] = {}
        self._by_batch: dict[str, AnchorReceipt] = {}
        self._block = 0

    def submit_anchor(self, batch_id: str, merkle_root: str) -> AnchorReceipt:
        """Commit (batch_id -> merkle_root). Idempotent: re-anchoring a batch returns the original receipt."""
        with self._lock:
            if (existing := self._by_batch.get(batch_id)):
                return existing
            ts = datetime.now(timezone.utc).isoformat()
            tx_id = hashlib.sha256(
                f"{CHANNEL}|{CHAINCODE}|{batch_id}|{merkle_root}|{ts}|{secrets.token_hex(8)}".encode()).hexdigest()
            self._block += 1
            r = AnchorReceipt(tx_id, batch_id, merkle_root, ts, self._block, CHANNEL, CHAINCODE, "VALID")
            self._by_tx[tx_id] = self._by_batch[batch_id] = r
            return r

    def get_anchor(self, tx_id: str) -> AnchorReceipt | None:
        return self._by_tx.get(tx_id)

    def get_anchor_for_batch(self, batch_id: str) -> AnchorReceipt | None:
        return self._by_batch.get(batch_id)

    # ---- persistence (app/state) ------------------------------------------------------------------------------
    def snapshot(self) -> list[AnchorReceipt]:
        with self._lock:
            return list(self._by_tx.values())

    def restore(self, receipts: list[AnchorReceipt]) -> None:
        with self._lock:
            for r in receipts:
                self._by_tx[r.tx_id] = self._by_batch[r.batch_id] = r
            self._block = max([self._block, *(r.block_number for r in receipts)])
