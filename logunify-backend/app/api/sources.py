import hmac
import ipaddress
from typing import Literal
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from ..pipeline.processor import Pipeline
from ..sources import SourceRegistry
from ..security.rbac import guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1/sources", tags=["sources"])


def get_registry(request: Request) -> SourceRegistry:
    return request.app.state.sources


class SourceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=64, pattern=r"^[\w .\-]+$")
    type: Literal["syslog", "http", "api"]
    format: Literal["auto", "syslog", "json", "cef", "text"] = "auto"
    tags: list[str] = Field(default_factory=list, max_length=10)
    # syslog listener
    protocol: Literal["udp", "tcp"] = "udp"
    port: int | None = Field(None, ge=1, le=65535)
    # api poller
    url: str | None = Field(None, max_length=512)
    poll_interval_s: int = Field(60, ge=10, le=86400)

    @field_validator("tags")
    @classmethod
    def _tags(cls, v):
        return [t.strip()[:32] for t in v if t.strip()]


class IngestBody(BaseModel):
    logs: list[str] = Field(min_length=1, max_length=5000)


def _validate_url(url: str | None) -> str:
    """API feeds must be https and must not point at loopback/link-local/private literals (SSRF guard)."""
    u = urlparse(url or "")
    if u.scheme != "https" or not u.hostname:
        raise HTTPException(422, "API feeds require a full https:// URL")
    try:
        ip = ipaddress.ip_address(u.hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise HTTPException(422, "API feed URL must not target a private or loopback address")
    except ValueError:
        if u.hostname.lower() in {"localhost"} or u.hostname.lower().endswith((".local", ".internal")):
            raise HTTPException(422, "API feed URL must not target an internal host")
    return url


@router.get("/listeners", dependencies=[Depends(guard("analyst", "sources.listeners", 60))])
def listener_stats(request: Request):
    """Live syslog listener counters: received, dropped (queue full / oversize), framing errors, queue depth."""
    return {"items": request.app.state.listeners.stats()}


@router.get("", dependencies=[Depends(guard("analyst", "sources.list", sample_s=60))])
def list_sources(reg: SourceRegistry = Depends(get_registry)):
    return {"items": [s.public() for s in reg.list()]}


@router.post("", status_code=201, dependencies=[Depends(guard("admin", "sources.create"))])
async def create_source(req: SourceCreate, request: Request, reg: SourceRegistry = Depends(get_registry)):
    """Register a feed. The HTTP token is returned only in this response."""
    if req.type == "syslog":
        if req.port is None:
            raise HTTPException(422, "syslog feeds need a port")
        cfg = {"protocol": req.protocol, "port": req.port}
    elif req.type == "api":
        cfg = {"url": _validate_url(req.url), "poll_interval_s": req.poll_interval_s}
    else:
        cfg = {}
    try:
        src = reg.add(req.name.strip(), req.type, req.format, cfg, req.tags)
    except ValueError as e:
        raise HTTPException(409, str(e))
    if src.type == "syslog":
        try:
            await request.app.state.listeners.start_source(src)
            src.status = "active"
        except OSError as e:                     # keep the registration; report why nothing is listening
            src.error = f"could not bind {request.app.state.settings.syslog_bind}:{cfg['port']}/{cfg['protocol']}: {e.strerror or e}"
    out = src.public(reveal_token=True)
    if src.type == "http":
        out["config"]["ingest_path"] = f"/api/v1/sources/{src.id}/ingest"
    return out


@router.delete("/{sid}", status_code=204, dependencies=[Depends(guard("admin", "sources.delete"))])
async def delete_source(sid: str, request: Request, reg: SourceRegistry = Depends(get_registry)):
    await request.app.state.listeners.stop_source(sid)
    if not reg.delete(sid):
        raise HTTPException(404, "unknown source")


@router.post("/{sid}/ingest", status_code=202)
async def ingest(sid: str, body: IngestBody, x_source_token: str = Header(""),
                 reg: SourceRegistry = Depends(get_registry), p: Pipeline = Depends(get_pipeline)):
    """Push logs into the pipeline through an HTTP feed. Auth: `X-Source-Token` header."""
    src = reg.get(sid)
    if src is None or src.type != "http" or not src.check_token(x_source_token):
        raise HTTPException(401, "invalid source or token")     # same answer for unknown id / bad token
    hint = None if src.format == "auto" else src.format
    accepted = 0
    for line in body.logs:
        accepted += await p.submit(line.encode(), hint)
    src.received += accepted
    return {"submitted": len(body.logs), "accepted": accepted}
