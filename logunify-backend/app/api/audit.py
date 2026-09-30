"""Audit-log API (admin only). Reading the audit log is itself audited."""
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from ..pipeline.processor import Pipeline
from ..security.audit import AuditLog
from ..security.rbac import guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


def get_audit(request: Request) -> AuditLog:
    return request.app.state.audit


class Head(BaseModel):
    seq: int = Field(ge=0)
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class VerifyBody(BaseModel):
    expected_head: Head | None = Field(None, description="A head you witnessed earlier; detects tail truncation")


@router.get("", dependencies=[Depends(guard("admin", "audit.list", sample_s=30))])
def list_audit(limit: int = Query(100, ge=1, le=1000), actor: str | None = None, action: str | None = None,
               before_seq: int | None = Query(None, ge=1), a: AuditLog = Depends(get_audit)):
    """Newest first. Each row carries prev_hash and hash so an auditor can re-verify offline."""
    return {"keyed": a.keyed, "items": a.list(limit, actor, action, before_seq)}


@router.get("/head", dependencies=[Depends(guard("admin", "audit.head", sample_s=30))])
def head(a: AuditLog = Depends(get_audit)):
    """Current chain head: store it somewhere the log's operators cannot edit (or use /anchor)."""
    return a.head()


@router.post("/verify", dependencies=[Depends(guard("admin", "audit.verify"))])
def verify(body: VerifyBody | None = None, a: AuditLog = Depends(get_audit)):
    return a.verify(body.expected_head.model_dump() if body and body.expected_head else None)


@router.post("/anchor", status_code=201, dependencies=[Depends(guard("admin", "audit.anchor"))])
def anchor(a: AuditLog = Depends(get_audit), p: Pipeline = Depends(get_pipeline)):
    """Commit the chain head to the ledger (MOCK Fabric today) as an external witness of the audit log."""
    h = a.head()
    rec = p.ledger.submit_anchor(f"audit-{h['seq']}", h["hash"])
    return {"head": h, "anchor": rec.to_dict(), "mock_ledger": True}
