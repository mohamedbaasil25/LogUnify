"""Persistence status (admin). Reading it is audited."""
from fastapi import APIRouter, Depends, HTTPException, Request

from ..security.rbac import guard

router = APIRouter(prefix="/api/v1/state", tags=["state"])


@router.get("", dependencies=[Depends(guard("admin", "state.status", sample_s=60))])
def status(request: Request):
    """Whether durable state is on, what was restored at startup, and the last flush's timing / error."""
    return request.app.state.state.stats()


@router.post("/flush", dependencies=[Depends(guard("admin", "state.flush"))])
async def flush(request: Request):
    """Write pending changes now (they are otherwise flushed every LOGUNIFY_STATE_FLUSH_INTERVAL_S seconds)."""
    st = request.app.state.state
    if not st.enabled:
        raise HTTPException(409, "state persistence is disabled or failed to start")
    return await st.flush()
