"""Alert calibration API: replay the rules over the events held, show analyst feedback, manage suppression rules.

Replay = what the rules WOULD do; feedback = what analysts DECIDED about alerts that did fire. See alerting/calibration.py.
Nothing here changes the alert threshold or the critical set: those are configuration (LOGUNIFY_ALERT_*), changed deliberately and restarted.
Suppression rules are the only runtime tuning, they are admin-only, time-limited, reasoned and permanent history.
"""
import time

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from ..alerting import calibration as cal
from ..alerting.manager import AlertManager
from ..alerting.models import AlertNotFound, InvalidTransition
from ..alerting.rules import AlertRules
from ..alerting.validation import AlertConfigError
from ..pipeline.processor import Pipeline
from ..search import SearchError, parse_time
from ..security.rbac import Principal, guard
from .alerts import get_manager
from .deps import get_pipeline

router = APIRouter(prefix="/api/v1", tags=["calibration"])
PREVIEW_MAX = 50


class SuppressionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique: str = Field(min_length=1, max_length=12, description="MITRE id (T1070 covers T1070.001) or *")
    asset: str = Field(min_length=1, max_length=100, description="host name / IP pattern, * and ? wildcards")
    reason: str = Field(min_length=10, max_length=500)
    days: int = Field(30, ge=1, le=90)


@router.get("/alerts-calibration")
def calibration(
    threshold: float | None = Query(None, ge=0, lt=1, description="candidate threshold to preview (default: the configured one)"),
    critical: str | None = Query(None, max_length=300, description="candidate critical techniques, CSV (default: the configured set)"),
    format: str | None = Query(None, pattern=r"^[a-z][a-z0-9_]{1,40}$", description="replay one parser / source only"),
    from_: str | None = Query(None, alias="from", max_length=40, description="replay window start: ISO-8601 or -6h / -7d"),
    feedback_days: int = Query(30, ge=1, le=365),
    capacity_per_day: float = Query(20, gt=0, le=10_000, description="alerts/day your analysts can triage inside the 6-hour window"),
    p: Pipeline = Depends(get_pipeline), m: AlertManager = Depends(get_manager),
    _who: Principal = Depends(guard("analyst", "alerts.calibration", sample_s=60)),
):
    now = time.time()
    try:
        lo = parse_time(from_)
    except SearchError as e:
        raise HTTPException(422, str(e)) from None
    cur = m.rules
    try:
        cand = AlertRules(cur.threshold if threshold is None else threshold, critical if critical else cur.critical, cur.require_rule_basis)
    except (ValueError, AlertConfigError) as e:
        raise HTTPException(422, str(e)) from None
    docs = list(p.recent)                                           # one consistent copy; the ring keeps moving
    if format:
        docs = [d for d in docs if (d.get("logunify") or {}).get("source_format") == format]
    if lo:
        docs = [d for d in docs if (t := cal._ts(d)) is None or t >= lo.timestamp()]
    stamps = [t for d in docs if (t := cal._ts(d)) is not None]
    window_s = (max(stamps) - min(stamps)) if len(stamps) > 1 else 0.0
    scores = [s for d in docs if isinstance((s := (((d.get("logunify") or {}).get("anomaly")) or {}).get("score")), (int, float))
              and ((d.get("logunify") or {}).get("anomaly") or {}).get("model_ready") is not False]
    sup = m.active_suppressions()
    thresholds = sorted({*cal.SWEEP, round(cur.threshold, 4), round(cand.threshold, 4)})
    rows = cal.sweep(docs, cand, m.dedup_s, thresholds, sup, now)
    rec = cal.recommend(rows, window_s, capacity_per_day, cur.threshold)
    preview = cal.group_alerts(docs, cand, m.dedup_s, sup, now)
    since = now - feedback_days * 86400
    alerts = m.store.alerts_since(since)
    return {
        "configured": {"threshold": cur.threshold, "critical_techniques": sorted(cur.critical), "require_rule_basis": cur.require_rule_basis,
                       "dedup_minutes": m.dedup_s // 60, "tagging_threshold": p.intel.threshold if p.intel else None},
        "candidate": {"threshold": cand.threshold, "critical_techniques": sorted(cand.critical)},
        "scope": {"format": format, "from": from_, "feedback_days": feedback_days},
        "replay": {
            "coverage": {"events_held": len(p.recent), "events_in_scope": len(docs), "buffer": p.recent.maxlen,
                         "oldest": min(stamps) if stamps else None, "newest": max(stamps) if stamps else None,
                         "note": "replay covers only the events this instance still holds (LOGUNIFY_RECENT_BUFFER); raise it for a longer sample"},
            "confidence": cal.confidence(len(docs), window_s),
            "model_ready_events": len(scores),
            "histogram": cal.histogram(scores), "percentiles": cal.percentiles(scores),
            "funnel": cal.funnel(docs, cand, sup, now),
            "sweep": rows, "recommendation": rec,
            "preview": {"alerts": len(preview["alerts"]), "events": preview["events"], "suppressed": preview["suppressed"],
                        "items": preview["alerts"][:PREVIEW_MAX], "truncated": len(preview["alerts"]) > PREVIEW_MAX},
            "note": "A replay counts alerts; it cannot say which are false positives. Review the preview rows, then close real alerts with a resolution: that is the feedback below.",
        },
        "feedback": {**cal.feedback(alerts, now), "since_days": feedback_days, "per_day": cal.per_day(alerts)},
        "suppressions": m.list_suppressions(),
    }


@router.get("/suppressions")
def list_suppressions(m: AlertManager = Depends(get_manager), _who: Principal = Depends(guard("analyst", "suppressions.list", sample_s=60))):
    return {"items": m.list_suppressions()}


@router.post("/suppressions", status_code=201)
def create_suppression(body: SuppressionBody, m: AlertManager = Depends(get_manager),
                       who: Principal = Depends(guard("admin", "suppressions.create"))):
    try:
        return m.add_suppression(who.sub, body.technique, body.asset, body.reason, body.days)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


@router.delete("/suppressions/{sup_id}")
def revoke_suppression(sup_id: str, m: AlertManager = Depends(get_manager), who: Principal = Depends(guard("admin", "suppressions.revoke"))):
    try:
        return m.revoke_suppression(sup_id, who.sub)
    except AlertNotFound:
        raise HTTPException(404, "unknown suppression") from None
    except InvalidTransition as e:
        raise HTTPException(409, str(e)) from None
