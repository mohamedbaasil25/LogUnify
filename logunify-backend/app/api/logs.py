from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..pipeline.processor import Pipeline
from ..security.rbac import guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1", tags=["logs"])


class IngestRequest(BaseModel):
    logs: list[str] = Field(min_length=1, max_length=5000, description="Raw log lines")
    format: str | None = Field(None, pattern=r"^[a-z][a-z0-9_]{1,40}$", description="Parser name (see /api/v1/parsers); skips auto-detection")


class ParseRequest(BaseModel):
    log: str
    format: str | None = Field(None, pattern=r"^[a-z][a-z0-9_]{1,40}$")


def _known_format(p: Pipeline, fmt: str | None) -> None:
    if fmt and p.parsers.get(fmt) is None:
        raise HTTPException(422, f"unknown parser '{fmt}'; available: {', '.join(p.parsers.names())}")


@router.post("/ingest", status_code=202, dependencies=[Depends(guard("analyst", "logs.ingest"))])
async def ingest(req: IngestRequest, request: Request, p: Pipeline = Depends(get_pipeline)):
    """Publish raw logs to the ingestion topic; parsing happens asynchronously in the pipeline."""
    _known_format(p, req.format)
    peer = request.client.host if request.client else None
    accepted = await p.submit_many([line.encode() for line in req.logs], req.format, transport="http", peer=peer)
    return {"submitted": len(req.logs), "accepted": accepted, "rejected": len(req.logs) - accepted}


@router.post("/parse", dependencies=[Depends(guard("analyst", "logs.parse"))])
def parse_preview(req: ParseRequest, p: Pipeline = Depends(get_pipeline)):
    """Dry-run: parse one log into ECS synchronously. Counts toward metrics like any other log."""
    _known_format(p, req.format)
    p.metrics.record_received(len(req.log.encode()))
    doc = p.process(req.log.encode(), req.format)
    return {"ok": doc is not None, "ecs": doc}


@router.get("/logs/recent", dependencies=[Depends(guard("analyst", "logs.view", sample_s=60))])
def recent(limit: int = Query(50, ge=1, le=1000), format: str | None = Query(None, pattern=r"^[a-z][a-z0-9_]{1,40}$"),
           p: Pipeline = Depends(get_pipeline)):
    """Newest-first ECS events from the in-memory ring buffer."""
    items = [d for d in reversed(p.recent) if format is None or d["logunify"]["source_format"] == format]
    return {"count": min(limit, len(items)), "items": items[:limit]}
