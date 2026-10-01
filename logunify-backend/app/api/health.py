from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=["health"])


@router.get("/health")
def health(request: Request):
    """Liveness: the process is up. Cheap, unauthenticated, safe for load balancers and container healthchecks."""
    s = request.app.state.settings
    return {"status": "ok", "version": s.version, "bus": "kafka" if s.kafka_enabled else "memory", "mock": s.mock_enabled}


@router.get("/ready")
def ready(request: Request):
    """Readiness: something is actually consuming. 503 if the consumer loop is not running, the dead-letter store is losing
    records, or durable state failed to start when it was requested."""
    s, p = request.app.state.settings, request.app.state.pipeline
    problems = []
    if not p.consumer_alive:
        problems.append("consumer loop is not running")
    if p.dlq.stats()["lost_full"] or p.dlq.stats()["lost_io"] or p.dlq.stats()["lost_queue"]:
        problems.append("dead-letter store is losing records")
    if s.state_enabled and not request.app.state.state.enabled:
        problems.append("durable state is enabled but failed to start")
    body = {"ready": not problems, "problems": problems, "consumer_restarts": p.metrics.consumer_restarts, "version": s.version}
    return JSONResponse(body, status_code=200 if not problems else 503)
