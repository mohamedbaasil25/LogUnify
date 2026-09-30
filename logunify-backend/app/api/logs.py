from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from ..pipeline.processor import Pipeline
from ..security.rbac import guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1", tags=["logs"])


class IngestRequest(BaseModel):
    logs: list[str] = Field(min_length=1, max_length=5000, description="Raw log lines")
    format: Literal["syslog", "json", "cef", "text"] | None = Field(None, description="Skip auto-detection")


class ParseRequest(BaseModel):
    log: str
    format: Literal["syslog", "json", "cef", "text"] | None = None


@router.post("/ingest", status_code=202, dependencies=[Depends(guard("analyst", "logs.ingest"))])
async def ingest(req: IngestRequest, p: Pipeline = Depends(get_pipeline)):
    """Publish raw logs to the ingestion topic; parsing happens asynchronously in the pipeline."""
    accepted = 0
    for line in req.logs:
        accepted += await p.submit(line.encode(), req.format)
    return {"submitted": len(req.logs), "accepted": accepted, "rejected": len(req.logs) - accepted}


@router.post("/parse", dependencies=[Depends(guard("analyst", "logs.parse"))])
def parse_preview(req: ParseRequest, p: Pipeline = Depends(get_pipeline)):
    """Dry-run: parse one log into ECS synchronously. Counts toward metrics like any other log."""
    p.metrics.record_received(len(req.log.encode()))
    doc = p.process(req.log.encode(), req.format)
    return {"ok": doc is not None, "ecs": doc}


@router.get("/logs/recent", dependencies=[Depends(guard("analyst", "logs.view", sample_s=60))])
def recent(limit: int = Query(50, ge=1, le=1000), format: Literal["syslog", "json", "cef", "text"] | None = None,
           p: Pipeline = Depends(get_pipeline)):
    """Newest-first ECS events from the in-memory ring buffer."""
    items = [d for d in reversed(p.recent) if format is None or d["logunify"]["source_format"] == format]
    return {"count": min(limit, len(items)), "items": items[:limit]}
