"""Alert workflow API. Every endpoint requires X-API-Key (LOGUNIFY_ALERT_API_KEY): alerts hold incident evidence and
these calls write compliance records (who acknowledged, who reported to CERT-In, why something was closed)."""
import hmac
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

from ..alerting import cert_in
from ..alerting.manager import AlertManager
from ..alerting.models import AlertNotFound, InvalidTransition
from ..pipeline.processor import Pipeline
from ..security.rbac import guard
from .deps import get_pipeline


def require_key(request: Request, x_api_key: str = Header(default="")) -> None:
    """Legacy credential (auth_mode=off): a shared X-API-Key. With auth_mode=jwt, an analyst bearer token works instead."""
    s = request.app.state.settings
    if s.auth_mode == "jwt" and not x_api_key:
        return
    key = s.alert_api_key
    if key is None:
        raise HTTPException(503, "Alert API is disabled: set LOGUNIFY_ALERT_API_KEY to enable it")
    if not hmac.compare_digest(x_api_key.encode("utf-8"), key.get_secret_value().encode("utf-8")):
        raise HTTPException(401, "Invalid or missing X-API-Key", headers={"WWW-Authenticate": "ApiKey"})


def get_manager(p: Pipeline = Depends(get_pipeline)) -> AlertManager:
    if p.alerts is None:
        raise HTTPException(503, "Alerting is disabled (LOGUNIFY_ALERTING_ENABLED=false)")
    return p.alerts


router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"], dependencies=[
    Depends(require_key),
    Depends(guard("analyst", sample_s={"list_alerts": 60, "get_alert": 60, "events": 60, "config": 60}, allow_api_key=True))])


class Actor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    by: str = Field(min_length=2, max_length=100, description="Who is doing this (recorded in the audit trail)")


class AckBody(Actor):
    note: str = Field("", max_length=1000)


class ReportedBody(Actor):
    via: Literal["email", "phone", "fax", "portal", "other"] = "email"
    reference: str = Field("", max_length=200, description="CERT-In acknowledgement / ticket reference, if you have one")
    note: str = Field("", max_length=1000)
    reported_at: datetime | None = Field(None, description="When it was actually sent to CERT-In (default: now)")


class CloseBody(Actor):
    resolution: Literal["false_positive", "not_reportable", "resolved"]
    note: str = Field("", max_length=2000)


class DetailsBody(Actor):
    """Information only a human can supply (the CERT-In form fields the platform cannot know). Null clears a field."""
    i_am: Literal["the affected entity", "reporting incident affecting other entity"] | None = None
    affected_entity: str | None = None
    incident_type_ids: list[str] | None = None
    incident_type_other: str | None = None
    critical: bool | None = None
    critical_details: str | None = None
    domain_url: str | None = None
    ip_address: str | None = None
    operating_system: str | None = None
    make_model_cloud: str | None = None
    affected_application: str | None = None
    location: str | None = None
    network_isp: str | None = None
    description_addendum: str | None = None
    impact: str | None = None
    actions_taken: str | None = None
    ongoing: bool | None = None


def _client(request: Request) -> str | None:
    return request.client.host if request.client else None


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except AlertNotFound:
        raise HTTPException(404, "unknown alert id") from None
    except InvalidTransition as e:
        raise HTTPException(409, str(e)) from None
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


@router.get("/config")
def config(m: AlertManager = Depends(get_manager)):
    """Effective alerting configuration (no secrets)."""
    return m.config_view()


@router.post("/test")
async def test_channels(m: AlertManager = Depends(get_manager)):
    """Send one clearly-labelled TEST message through every channel. Not an incident; no CERT-In clock."""
    if not m.notifiers:
        raise HTTPException(409, "no notification channel is configured")
    return {"channels": await m.send_test()}


@router.get("")
def list_alerts(status: Literal["active", "open", "acknowledged", "reported", "closed"] | None = None,
                limit: int = Query(50, ge=1, le=500), m: AlertManager = Depends(get_manager)):
    """Newest first. `active` = open + acknowledged = the CERT-In clock is running and nothing has been reported."""
    return {"items": m.list_alerts(status, limit)}


@router.get("/{alert_id}")
def get_alert(alert_id: str, m: AlertManager = Depends(get_manager)):
    return _call(m.view, alert_id)


@router.get("/{alert_id}/cert-in-report")
def cert_in_report(alert_id: str, format: Literal["json", "text"] = "json", m: AlertManager = Depends(get_manager)):
    """Form-aligned DRAFT CERT-In incident report (json, or plain text ready to paste into the email to CERT-In)."""
    report = _call(m.report_for, alert_id)
    if format == "text":
        kind = "incident.overdue" if report["deadline"]["overdue"] else "incident.detected"
        return PlainTextResponse(cert_in.render_text(report, kind), media_type="text/plain; charset=utf-8")
    return report


@router.get("/{alert_id}/evidence")
def evidence(alert_id: str, m: AlertManager = Depends(get_manager)):
    """The full, unredacted ECS record plus its SHA-256 and Merkle-batch reference (logs accompany the CERT-In report)."""
    return _call(m.evidence_for, alert_id)


@router.get("/{alert_id}/events")
def events(alert_id: str, m: AlertManager = Depends(get_manager)):
    """Append-only audit trail: creation, each notification attempt, reminders, acknowledgement, report, closure."""
    return {"items": _call(m.events_for, alert_id)}


@router.post("/{alert_id}/ack")
def acknowledge(alert_id: str, body: AckBody, request: Request, m: AlertManager = Depends(get_manager)):
    _call(m.acknowledge, alert_id, body.by, body.note, _client(request))
    return m.view(alert_id)


@router.patch("/{alert_id}/details")
def update_details(alert_id: str, body: DetailsBody, request: Request, m: AlertManager = Depends(get_manager)):
    fields = {k: getattr(body, k) for k in body.model_fields_set if k != "by"}
    if not fields:
        raise HTTPException(422, "no fields to update")
    _call(m.update_details, alert_id, body.by, fields, _client(request))
    return m.report_for(alert_id)["completeness"]


@router.post("/{alert_id}/report")
def mark_reported(alert_id: str, body: ReportedBody, request: Request, m: AlertManager = Depends(get_manager)):
    """Record that the incident WAS reported to CERT-In (this system never files on your behalf)."""
    at = body.reported_at.astimezone(timezone.utc).timestamp() if body.reported_at else None
    _call(m.mark_reported, alert_id, body.by, via=body.via, reference=body.reference, note=body.note,
          reported_at=at, client=_client(request))
    return m.view(alert_id)


@router.post("/{alert_id}/close")
def close(alert_id: str, body: CloseBody, request: Request, m: AlertManager = Depends(get_manager)):
    _call(m.close, alert_id, body.by, body.resolution, body.note, _client(request))
    return m.view(alert_id)
