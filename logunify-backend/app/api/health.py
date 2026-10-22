from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=["health"])


@router.get("/health")
def health():
    """Liveness: the process is up. Public and deliberately minimal (no version, no configuration)."""
    return {"status": "ok"}


@router.get("/ready")
def ready(request: Request):
    """Readiness: something is actually consuming and nothing is silently losing data. Public, boolean only: details are in
    GET /api/v1/system (authenticated)."""
    ok = not _problems(request)
    return JSONResponse({"ready": ok}, status_code=200 if ok else 503)


def _problems(request) -> list[str]:
    s, p = request.app.state.settings, request.app.state.pipeline
    problems = []
    if not p.consumer_alive:
        problems.append("consumer loop is not running")
    d = p.dlq.stats()
    if d["lost_full"] or d["lost_io"] or d["lost_queue"]:
        problems.append("dead-letter store is losing records")
    if s.state_enabled and not request.app.state.state.enabled:
        problems.append("durable state is enabled but failed to start")
    return problems
