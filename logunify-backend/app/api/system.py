"""System information for operators (viewer+). The public /health and /ready say only up / ready."""
from fastapi import APIRouter, Depends, Request

from ..security.rbac import guard
from .health import _problems

router = APIRouter(prefix="/api/v1", tags=["system"])


@router.get("/system", dependencies=[Depends(guard("viewer", "system.info", sample_s=60))])
def system(request: Request):
    s, p = request.app.state.settings, request.app.state.pipeline
    return {"version": s.version, "bus": "kafka" if s.kafka_enabled else "memory", "mock_generator": s.mock_enabled,
            "auth_mode": s.auth_mode, "worker_id": s.worker_id or None, "consumer_alive": p.consumer_alive,
            "consumer_restarts": p.metrics.consumer_restarts, "ready": not _problems(request), "problems": _problems(request),
            "taxonomy_mode": s.taxonomy_mode, "raw_archive": bool(p.archive), "docs_enabled": s.docs_enabled}
