"""Log search with a time range, and saved searches (private, or shared with every analyst)."""
import secrets
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from ..pipeline.processor import Pipeline
from ..search import SearchError, parse_query, parse_time, search_logs
from ..security.rbac import Principal, guard
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1", tags=["search"])
MAX_PER_OWNER = 200
LOG_KEYS = {"q", "from", "to", "format", "min_score", "limit"}
ALERT_KEYS = {"status", "assignee", "limit"}
_STATUSES = {"active", "open", "acknowledged", "reported", "closed"}


class SearchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["logs", "alerts"] = "logs"
    query: dict = Field(default_factory=dict)
    shared: bool = False


def _validate(kind: str, query: dict) -> dict:
    allowed = LOG_KEYS if kind == "logs" else ALERT_KEYS
    extra = set(query) - allowed
    if extra:
        raise HTTPException(422, f"unknown query keys for {kind}: {sorted(extra)}; allowed: {sorted(allowed)}")
    q = {k: v for k, v in query.items() if v not in (None, "")}
    try:
        if kind == "logs":
            parse_query(q.get("q"))
            parse_time(q.get("from")), parse_time(q.get("to"))
            if "min_score" in q and not 0 <= float(q["min_score"]) <= 1:
                raise ValueError("min_score must be between 0 and 1")
        elif q.get("status") and q["status"] not in _STATUSES:
            raise ValueError(f"status must be one of {sorted(_STATUSES)}")
        if "limit" in q and not 1 <= int(q["limit"]) <= 500:
            raise ValueError("limit must be 1-500")
    except (SearchError, ValueError, TypeError) as e:
        raise HTTPException(422, str(e)) from None
    for k in ("q", "from", "to", "format", "status", "assignee"):
        if k in q and (not isinstance(q[k], str) or len(q[k]) > 500):
            raise HTTPException(422, f"{k} must be text of at most 500 characters")
    return q


def _store(p: Pipeline):
    if p.alerts is None:
        raise HTTPException(503, "saved searches are stored with the alert store: alerting is disabled (LOGUNIFY_ALERTING_ENABLED=false)")
    return p.alerts.store


def _run_logs(p: Pipeline, q: dict, extra: dict | None = None) -> dict:
    q = {**q, **(extra or {})}
    try:
        return search_logs(p.recent, q=q.get("q"), t_from=q.get("from"), t_to=q.get("to"), fmt=q.get("format"),
                           min_score=float(q["min_score"]) if q.get("min_score") is not None else None,
                           limit=int(q.get("limit", 100)), offset=int(q.get("offset", 0)))
    except SearchError as e:
        raise HTTPException(422, str(e)) from None


@router.get("/logs/search", dependencies=[Depends(guard("analyst", "logs.search", sample_s=60))])
def search(q: str | None = Query(None, max_length=500, description="see app/search.py for the syntax"),
           from_: str | None = Query(None, alias="from", max_length=40), to: str | None = Query(None, max_length=40),
           format: str | None = Query(None, pattern=r"^[a-z][a-z0-9_]{1,40}$"), min_score: float | None = Query(None, ge=0, le=1),
           limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=100_000), p: Pipeline = Depends(get_pipeline)):
    """Search the events this instance still holds, newest first, with a time range. `coverage` shows the window searched."""
    return _run_logs(p, {"q": q, "from": from_, "to": to, "format": format, "min_score": min_score, "limit": limit, "offset": offset})


@router.get("/searches")
def list_searches(p: Pipeline = Depends(get_pipeline), who: Principal = Depends(guard("analyst", "searches.list", sample_s=60))):
    return {"items": _store(p).list_searches(who.sub)}


@router.post("/searches", status_code=201)
def create_search(body: SearchBody, p: Pipeline = Depends(get_pipeline), who: Principal = Depends(guard("analyst", "searches.create"))):
    st = _store(p)
    if st.count_searches(who.sub) >= MAX_PER_OWNER:
        raise HTTPException(409, f"at most {MAX_PER_OWNER} saved searches per user")
    now = time.time()
    rec = {"id": "SRC-" + secrets.token_hex(5), "owner": who.sub, "name": body.name.strip(), "kind": body.kind,
           "shared": body.shared, "query": _validate(body.kind, body.query), "created_at": now, "updated_at": now}
    st.put_search(rec)
    return rec


def _owned(st, search_id: str, who: Principal, write: bool) -> dict:
    rec = st.get_search(search_id)
    if rec is None or (rec["owner"] != who.sub and not rec["shared"]):
        raise HTTPException(404, "unknown search")                     # a private search is indistinguishable from a missing one
    if write and rec["owner"] != who.sub and not who.allows("admin"):
        raise HTTPException(403, "only the owner (or an admin) can change a shared search")
    return rec


@router.put("/searches/{search_id}")
def update_search(search_id: str, body: SearchBody, p: Pipeline = Depends(get_pipeline),
                  who: Principal = Depends(guard("analyst", "searches.update"))):
    st = _store(p)
    rec = _owned(st, search_id, who, write=True)
    if body.kind != rec["kind"]:
        raise HTTPException(422, "a search's kind cannot change; create a new one")
    rec.update(name=body.name.strip(), shared=body.shared, query=_validate(rec["kind"], body.query), updated_at=time.time())
    st.put_search(rec)
    return rec


@router.delete("/searches/{search_id}", status_code=204)
def delete_search(search_id: str, p: Pipeline = Depends(get_pipeline), who: Principal = Depends(guard("analyst", "searches.delete"))):
    st = _store(p)
    _owned(st, search_id, who, write=True)
    st.delete_search(search_id)


@router.post("/searches/{search_id}/run")
def run_search(search_id: str, request: Request, p: Pipeline = Depends(get_pipeline),
               who: Principal = Depends(guard("analyst", "searches.run", sample_s=60))):
    """Run a saved search now. Relative times (`-6h`) are evaluated at run time, so "last 6 hours" stays the last 6 hours."""
    rec = _owned(_store(p), search_id, who, write=False)
    q = rec["query"]
    if rec["kind"] == "logs":
        return {"search": rec, "result": _run_logs(p, q)}
    items = p.alerts.list_alerts(None if q.get("status") in (None, "") else q["status"], int(q.get("limit", 100)),
                                 (who.sub if q.get("assignee") == "me" else q.get("assignee")))
    return {"search": rec, "result": {"total": len(items), "items": items}}
