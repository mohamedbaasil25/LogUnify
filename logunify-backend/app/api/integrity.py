import hmac
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, model_validator

from ..integrity.merkle import build_tree, canonical, compute_root, fold_proof, hash_record
from ..pipeline.processor import Pipeline
from ..security.rbac import guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1/integrity", tags=["integrity"])

_HEX64 = r"^[0-9a-fA-F]{64}$"


class AnchorRequest(BaseModel):
    batch_id: str


class ProofStepModel(BaseModel):
    hash: str = Field(pattern=_HEX64)
    position: Literal["left", "right"]


class VerifyRequest(BaseModel):
    record: dict | None = Field(None, description="The ECS record; its SHA-256 leaf hash is recomputed")
    leaf_hash: str | None = Field(None, pattern=_HEX64, description="Alternative to `record`: the SHA-256 leaf hash")
    proof: list[ProofStepModel] = Field(max_length=64)
    merkle_root: str = Field(pattern=_HEX64)
    batch_id: str | None = Field(None, description="If given, the root is also checked against the ledger anchor")

    @model_validator(mode="after")
    def _one_of(self):
        if (self.record is None) == (self.leaf_hash is None):
            raise ValueError("provide exactly one of `record` or `leaf_hash`")
        return self


class HashRequest(BaseModel):
    record: dict


class BatchVerifyRequest(BaseModel):
    batch_id: str
    records: list[dict] = Field(min_length=1, max_length=5000, description="The batch's records, in original order")
    expected_root: str | None = Field(None, pattern=_HEX64, description="Optional root you obtained elsewhere")


def _batch_or_404(p: Pipeline, batch_id: str):
    b = p.batcher.get(batch_id)
    if b is None:
        raise HTTPException(404, f"unknown or expired batch '{batch_id}'")
    return b


@router.get("/batches", dependencies=[Depends(guard("viewer", "integrity.batches.list", sample_s=60))])
def list_batches(limit: int = Query(20, ge=1, le=100), p: Pipeline = Depends(get_pipeline)):
    return {"batch_size": p.batcher.size, "pending_records": p.batcher.pending,
            "items": [b.summary() for b in p.batcher.list()[:limit]]}


@router.get("/batches/{batch_id}", dependencies=[Depends(guard("viewer", "integrity.batch.view", sample_s=60))])
def get_batch(batch_id: str, p: Pipeline = Depends(get_pipeline)):
    return _batch_or_404(p, batch_id).summary()


@router.get("/batches/{batch_id}/proof/{index}", dependencies=[Depends(guard("analyst", "integrity.proof.download"))])
def get_proof(batch_id: str, index: int, p: Pipeline = Depends(get_pipeline)):
    """The record at `index`, its leaf hash, and the Merkle proof path to the batch root."""
    b = _batch_or_404(p, batch_id)
    if not 0 <= index < b.count:
        raise HTTPException(404, f"index must be 0..{b.count - 1}")
    return p.batcher.proof(batch_id, index)


@router.post("/seal", dependencies=[Depends(guard("admin", "integrity.seal"))])
def seal(p: Pipeline = Depends(get_pipeline)):
    """Seal the current partial batch now (normally batches seal at exactly `batch_size` records)."""
    b = p.seal_partial()
    if b is None:
        raise HTTPException(409, "no pending records to seal")
    return b.summary()


@router.post("/anchor", status_code=201, dependencies=[Depends(guard("admin", "integrity.anchor"))])
def anchor(req: AnchorRequest, p: Pipeline = Depends(get_pipeline)):
    """MOCK Hyperledger Fabric commit of the batch's Merkle root. Idempotent per batch."""
    return p.anchor_batch(_batch_or_404(p, req.batch_id)).to_dict()


@router.get("/anchors/{tx_id}", dependencies=[Depends(guard("viewer", "integrity.anchor.view", sample_s=60))])
def get_anchor(tx_id: str, p: Pipeline = Depends(get_pipeline)):
    r = p.ledger.get_anchor(tx_id)
    if r is None:
        raise HTTPException(404, "unknown transaction id")
    return r.to_dict()


def _cmp(a: str | None, b: str | None) -> bool:
    return a is not None and b is not None and hmac.compare_digest(a.lower(), b.lower())


@router.post("/hash", dependencies=[Depends(guard("viewer", "integrity.hash", sample_s=60))])
def hash_record_endpoint(req: HashRequest):
    """SHA-256 leaf hash of a record (canonical JSON, 0x00 domain prefix): lets you derive the value `verify` uses."""
    return {"leaf_hash": hash_record(req.record).hex(), "canonical_json": canonical(req.record).decode()}


@router.post("/verify-batch", dependencies=[Depends(guard("analyst", "integrity.verify_batch"))])
def verify_batch(req: BatchVerifyRequest, p: Pipeline = Depends(get_pipeline)):
    """Verify a whole batch: rehash every submitted record, rebuild the Merkle root, and compare it with the
    stored batch root, the ledger-anchored root, and optionally a root you supply. Pinpoints altered records."""
    b = _batch_or_404(p, req.batch_id)
    leaves = [hash_record(r).hex() for r in req.records]
    root = build_tree([bytes.fromhex(x) for x in leaves])[-1][0].hex()
    n, m = len(leaves), b.count
    tampered = [i for i in range(min(n, m)) if leaves[i] != b.leaves[i]]
    anchor = p.ledger.get_anchor_for_batch(b.id)
    checks = {"matches_batch_root": _cmp(root, b.root),
              "matches_ledger_anchor": _cmp(root, anchor.merkle_root) if anchor else None,
              "matches_expected_root": _cmp(root, req.expected_root) if req.expected_root else None}
    return {"batch_id": b.id, "valid": all(v for v in checks.values() if v is not None),
            "computed_root": root, "stored_root": b.root, "anchored": anchor is not None,
            "tx_id": anchor.tx_id if anchor else None, "checks": checks,
            "records_submitted": n, "records_expected": m,
            "tampered_indexes": tampered[:100], "tampered_count": len(tampered),
            "missing_indexes": list(range(n, m))[:100], "extra_indexes": list(range(m, n))[:100]}


@router.get("/batches/{batch_id}/audit", dependencies=[Depends(guard("analyst", "integrity.batch_audit"))])
def audit_batch(batch_id: str, p: Pipeline = Depends(get_pipeline)):
    """Self-audit: rehash the records this server holds and compare with the sealed leaves and the ledger anchor."""
    b = _batch_or_404(p, batch_id)
    leaves = [hash_record(d).hex() for d in b.docs]
    root = build_tree([bytes.fromhex(x) for x in leaves])[-1][0].hex()
    anchor = p.ledger.get_anchor_for_batch(b.id)
    mismatched = [i for i, (x, y) in enumerate(zip(leaves, b.leaves)) if x != y]
    return {"batch_id": b.id, "records": b.count, "recomputed_root": root, "sealed_root": b.root,
            "sealed_root_intact": _cmp(root, b.root) and not mismatched, "altered_indexes": mismatched[:100],
            "anchored": anchor is not None, "ledger_root_matches": _cmp(root, anchor.merkle_root) if anchor else None}


@router.post("/verify", dependencies=[Depends(guard("viewer", "integrity.verify", sample_s=60))])
def verify(req: VerifyRequest, p: Pipeline = Depends(get_pipeline)):
    """Check that `record` is a member of the tree with `merkle_root` (and, with batch_id, of the anchored batch)."""
    steps = [s.model_dump() for s in req.proof]
    if req.record is not None:
        leaf, computed = compute_root(req.record, steps)
    else:
        leaf = req.leaf_hash.lower()
        computed = fold_proof(bytes.fromhex(leaf), steps)
    proof_valid = hmac.compare_digest(computed, req.merkle_root.lower())
    out = {"valid": proof_valid, "proof_valid": proof_valid, "leaf_hash": leaf, "computed_root": computed,
           "anchored": False, "anchor_root_matches": None, "tx_id": None}
    if req.batch_id:
        _batch_or_404(p, req.batch_id)
        if (a := p.ledger.get_anchor_for_batch(req.batch_id)):
            match = hmac.compare_digest(a.merkle_root, req.merkle_root.lower())
            out.update(anchored=True, anchor_root_matches=match, tx_id=a.tx_id, valid=proof_valid and match)
    return out
