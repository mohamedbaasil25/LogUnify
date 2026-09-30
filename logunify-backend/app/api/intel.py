from fastapi import APIRouter, Depends, HTTPException, Query

from ..pipeline.processor import Pipeline
from ..security.rbac import guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1", tags=["intel"])


def _intel(p: Pipeline):
    if not p.intel:
        raise HTTPException(503, "intel engine disabled (LOGUNIFY_INTEL_ENABLED=false)")
    return p.intel


@router.get("/anomalies", dependencies=[Depends(guard("analyst", "logs.anomalies.view", sample_s=60))])
def anomalies(limit: int = Query(50, ge=1, le=200), p: Pipeline = Depends(get_pipeline)):
    """Newest-first logs scoring above the threshold, each carrying threat.technique.* (placeholder MITRE tag)."""
    i = _intel(p)
    items = list(reversed(p.anomalies))[:limit]
    return {"threshold": i.threshold, "model_ready": i.scorer.ready, "total": i.anomalies, "items": items}


@router.get("/templates", dependencies=[Depends(guard("analyst", "logs.templates.view", sample_s=60))])
def templates(limit: int = Query(20, ge=1, le=200), p: Pipeline = Depends(get_pipeline)):
    """Most frequent Drain3 log templates."""
    i = _intel(p)
    return {"cluster_count": i.miner.cluster_count, "items": i.miner.top_templates(limit)}
