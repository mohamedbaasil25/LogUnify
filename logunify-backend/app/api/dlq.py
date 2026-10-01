"""Dead-letter store API (admin): inspect and replay logs that could not be normalized."""
from fastapi import APIRouter, Depends, Query

from ..pipeline.processor import Pipeline
from ..security.rbac import guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1/dlq", tags=["dead-letter"])


@router.get("", dependencies=[Depends(guard("admin", "dlq.view", sample_s=30))])
def view(limit: int = Query(20, ge=1, le=200), p: Pipeline = Depends(get_pipeline)):
    """Counters + a preview of the oldest dead-lettered records (raw payload truncated). Alert on `lost_*` > 0."""
    return {"stats": p.dlq.stats(), "by_reason": dict(p.metrics.dead_lettered), "preview": p.dlq.peek(limit)}


@router.post("/replay", dependencies=[Depends(guard("admin", "dlq.replay"))])
async def replay(limit: int = Query(1000, ge=1, le=100_000), p: Pipeline = Depends(get_pipeline)):
    """Re-submit the oldest records (original event.id kept, so downstream writes stay idempotent). Records that are refused
    again go back to the file."""
    return await p.replay_dlq(limit)
