from fastapi import APIRouter, Request

router = APIRouter(tags=["health"])


@router.get("/health")
def health(request: Request):
    s = request.app.state.settings
    return {"status": "ok", "bus": "kafka" if s.kafka_enabled else "memory", "mock": s.mock_enabled}
