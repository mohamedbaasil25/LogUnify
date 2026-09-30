"""Elasticsearch forwarder status and dead-letter replay (admin)."""
from fastapi import APIRouter, Depends, HTTPException

from ..pipeline.processor import Pipeline
from ..security.rbac import guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1/forwarding", tags=["forwarding"])


def _fw(p: Pipeline):
    if p.forwarder is None:
        raise HTTPException(409, "Elasticsearch forwarding is disabled (LOGUNIFY_ES_FORWARD_ENABLED=false)")
    return p.forwarder


@router.get("/elasticsearch", dependencies=[Depends(guard("admin", "forwarding.status", sample_s=30))])
def status(p: Pipeline = Depends(get_pipeline)):
    """Health, queue depth, retries, dead-lettered / lost counters. Alert on `lost_*` > 0 and `healthy` = false."""
    return _fw(p).stats()


@router.post("/elasticsearch/replay", dependencies=[Depends(guard("admin", "forwarding.replay"))])
async def replay(include_rejected: bool = False, p: Pipeline = Depends(get_pipeline)):
    """Re-queue dead-lettered documents (records Elasticsearch rejected as invalid are skipped unless include_rejected)."""
    return await _fw(p).replay_dlq(include_rejected)
