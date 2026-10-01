"""Traceability API: from an event.id to the raw bytes, the normalized document, its Merkle batch and ledger anchor.

Everything an auditor needs to prove "this normalized record came from exactly these received bytes, and nobody changed it":
  checks.raw_hash_matches_event_hash   SHA-256 of the archived raw == event.hash stamped on the document at the door
  checks.archive_intact                the archive's own record verified against the hash it indexed at write time
  checks.doc_matches_archive_index     the document we hold hashes to what was archived alongside the raw bytes
  batch / anchor                       where the document was sealed in a Merkle batch and anchored (MOCK ledger today)
Raw bytes are only returned to admins (`include_raw=true`), and that access is written to the audit log.
"""
import base64

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..archive.raw_store import ArchiveError
from ..integrity.merkle import hash_record
from ..pipeline.processor import Pipeline
from ..security.rbac import Principal, guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1", tags=["trace"])


def _find_doc(p: Pipeline, event_id: str) -> dict | None:
    for d in reversed(p.recent):
        if (d.get("event") or {}).get("id") == event_id:
            return d
    for b in reversed(p.batcher.list()):
        for d in b.docs:
            if (d.get("event") or {}).get("id") == event_id:
                return d
    return None


@router.get("/trace/{event_id}")
def trace(event_id: str, request: Request, include_raw: bool = Query(False), p: Pipeline = Depends(get_pipeline),
          principal: Principal = Depends(guard("analyst", "trace.view"))):
    if include_raw and not principal.allows("admin"):
        request.app.state.audit.append(principal.sub, principal.role, principal.auth, "trace.raw", request.url.path,
                                       "denied:403", request.client.host if request.client else None, {"needs": "admin"})
        raise HTTPException(403, "Raw (unredacted) log content requires role 'admin'")
    doc = _find_doc(p, event_id)
    arch = None
    if p.archive:
        p.archive.flush(2.0)
        try:
            arch = p.archive.get(event_id)
        except ArchiveError as e:
            raise HTTPException(409, f"raw archive cannot produce this record: {e}") from None
    if doc is None and arch is None:
        raise HTTPException(404, "unknown event.id (not in the recent window, the sealed batches, or the raw archive)")

    checks: dict = {"raw_hash_matches_event_hash": None, "archive_intact": None, "doc_matches_archive_index": None}
    out: dict = {"event_id": event_id, "normalized": doc, "raw_archived": arch is not None}
    if doc is not None:
        leaf = hash_record(doc).hex()
        out["record_sha256"] = leaf
        out["integrity_reference"] = p.batcher.find_leaf(leaf)          # None while the record is still in the open batch
        ev = doc.get("event") or {}
        out["envelope"] = {"hash": ev.get("hash"), "created": ev.get("created"), "ingested": ev.get("ingested"),
                           "parser": (doc.get("logunify") or {}).get("parser"), "origin": (doc.get("logunify") or {}).get("origin"),
                           "source": (doc.get("logunify") or {}).get("source"), "transport": (doc.get("logunify") or {}).get("transport"),
                           "raw_redacted_in_document": bool(((doc.get("logunify") or {}).get("raw") or {}).get("redacted"))}
    if arch is not None:
        checks["archive_intact"] = arch["intact"]
        out["raw"] = {"sha256": arch["sha256"], "size": len(arch["raw"]), "stored_at": arch["stored_at"]}
        if doc is not None:
            checks["raw_hash_matches_event_hash"] = arch["sha256"] == (doc.get("event") or {}).get("hash")
            checks["doc_matches_archive_index"] = arch["doc_sha256"] == out["record_sha256"]
        if include_raw:
            request.app.state.audit.append(principal.sub, principal.role, principal.auth, "trace.raw", request.url.path, "allowed",
                                           request.client.host if request.client else None, {"event_id": event_id})
            out["raw"]["text"] = arch["raw"].decode("utf-8", "replace")
            out["raw"]["base64"] = base64.b64encode(arch["raw"]).decode()
    out["checks"] = checks
    out["verdict"] = ("verified" if arch is not None and all(v for v in checks.values() if v is not None) else
                      "mismatch" if arch is not None else "raw_not_archived")
    return out


@router.get("/archive", dependencies=[Depends(guard("admin", "archive.status", sample_s=60))])
def archive_status(p: Pipeline = Depends(get_pipeline)):
    """Raw archive counters (encrypted?, records, segments, queue, dropped)."""
    if p.archive is None:
        raise HTTPException(409, "raw archive is disabled (LOGUNIFY_RAW_ARCHIVE_ENABLED=false)")
    return p.archive.stats()
