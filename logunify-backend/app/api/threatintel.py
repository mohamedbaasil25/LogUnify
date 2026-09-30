from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..pipeline.processor import Pipeline
from ..threatintel.service import ThreatIntel
from ..security.rbac import guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1/threatintel", tags=["threat-intel"])


def get_ti(p: Pipeline = Depends(get_pipeline)) -> ThreatIntel:
    if not p.ti:
        raise HTTPException(503, "threat intel disabled (LOGUNIFY_TI_ENABLED=false)")
    return p.ti


class IocIn(BaseModel):
    type: Literal["ip", "domain", "md5", "sha1", "sha256"]
    value: str = Field(min_length=1, max_length=253)
    category: str = Field("", max_length=100)
    threat_level: int | None = Field(None, ge=1, le=4, description="MISP scale: 1 high, 2 medium, 3 low, 4 undefined")
    description: str = Field("", max_length=200)


class IocImport(BaseModel):
    iocs: list[IocIn] = Field(min_length=1, max_length=10000)


def _ioc(i) -> dict:
    return {"type": i.type, "value": i.value, "feed": i.feed, "category": i.category, "confidence": i.confidence,
            "threat_level": i.threat_level, "event_id": i.event_id, "description": i.description, "tags": list(i.tags)}


@router.get("/status", dependencies=[Depends(guard("viewer", "ti.status", sample_s=60))])
def status(ti: ThreatIntel = Depends(get_ti)):
    """Feed health and indicator counts. The MISP API key is never included."""
    return {"feeds": list(ti.status.values()), "indicators": ti.store.counts(), "matches": ti.matches,
            "sync_interval_minutes": ti.s.misp_sync_minutes,
            "using_mock_feed": "mock-misp" in ti.status}


@router.post("/sync", dependencies=[Depends(guard("admin", "ti.sync"))])
async def sync(ti: ThreatIntel = Depends(get_ti)):
    """Pull the MISP feed now (no-op when MISP isn't configured)."""
    await ti.sync()
    return {"feeds": list(ti.status.values()), "indicators": ti.store.counts()}


@router.get("/matches", dependencies=[Depends(guard("analyst", "ti.matches.view", sample_s=60))])
def matches(limit: int = Query(50, ge=1, le=200), ti: ThreatIntel = Depends(get_ti)):
    """Newest-first logs that matched an indicator."""
    return {"total": ti.matches, "items": list(reversed(ti.recent))[:limit]}


@router.get("/lookup", dependencies=[Depends(guard("analyst", "ti.lookup"))])
def lookup(value: str = Query(min_length=1, max_length=253), ti: ThreatIntel = Depends(get_ti)):
    """Is this IP / domain / file hash a known indicator?"""
    hit = ti.lookup(value)
    return {"value": value, "malicious": hit is not None, "indicator": _ioc(hit) if hit else None}


@router.post("/iocs", dependencies=[Depends(guard("admin", "ti.iocs.import"))])
def import_iocs(body: IocImport, ti: ThreatIntel = Depends(get_ti)):
    """Add analyst-supplied indicators (feed 'manual'). Invalid values and catch-all CIDRs are rejected."""
    return ti.import_manual([i.model_dump() for i in body.iocs])
