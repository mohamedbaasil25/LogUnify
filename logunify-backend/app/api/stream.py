"""Live log stream (Server-Sent Events). Replaces dashboard polling: the server pushes each normalized document as it is produced.

Auth is the normal Authorization header (analyst+), so clients use fetch() streaming, not the browser EventSource (which cannot
send headers). Events: `log` (data = ECS JSON), `lagged` (data = {"dropped": n}: this client was too slow and missed events),
comments `: ping` every 15 s keep proxies from closing an idle connection.
"""
import asyncio
import json

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from ..pipeline.processor import Pipeline
from ..security.rbac import guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1/stream", tags=["stream"])


@router.get("/logs", dependencies=[Depends(guard("analyst", "stream.logs"))])
async def stream_logs(request: Request, format: str | None = Query(None, pattern=r"^[a-z][a-z0-9_]{1,40}$"),
                      anomalies_only: bool = False, p: Pipeline = Depends(get_pipeline)):
    sub = p.stream.subscribe()

    async def gen():
        last_ping, reported = 0.0, 0
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    doc = await asyncio.wait_for(sub.q.get(), 1.0)
                except asyncio.TimeoutError:
                    doc = None
                if await request.is_disconnected():
                    return
                now = asyncio.get_running_loop().time()
                if doc is None:
                    if now - last_ping > 15:
                        last_ping = now
                        yield ": ping\n\n"
                    continue
                if sub.dropped > reported:
                    reported = sub.dropped
                    yield f"event: lagged\ndata: {json.dumps({'dropped': reported})}\n\n"
                if format and (doc.get("logunify") or {}).get("source_format") != format:
                    continue
                if anomalies_only and "technique" not in (doc.get("threat") or {}):
                    continue
                yield f"event: log\ndata: {json.dumps(doc, separators=(',', ':'), default=str)}\n\n"
        finally:
            p.stream.unsubscribe(sub)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/status", dependencies=[Depends(guard("viewer", "stream.status", sample_s=60))])
def stream_status(p: Pipeline = Depends(get_pipeline)):
    return {"subscribers": p.stream.subscribers, "published": p.stream.published}
