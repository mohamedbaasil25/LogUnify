from fastapi import APIRouter, Depends, Query

from ..pipeline.metrics import MetricsRegistry
from ..pipeline.processor import Pipeline
from ..security.rbac import guard
from .deps import get_metrics, get_pipeline

router = APIRouter(prefix="/api/v1/metrics", tags=["metrics"],
                   dependencies=[Depends(guard("viewer", "metrics.view", sample_s=300))])


@router.get("")
def summary(m: MetricsRegistry = Depends(get_metrics), p: Pipeline = Depends(get_pipeline)):
    """Headline pipeline numbers: throughput, compression ratio, dropped logs, noise reduction."""
    out = m.summary()
    # Noise reduction: share of events an analyst no longer reads individually because they collapse into a
    # known Drain3 template (1 - distinct templates / processed events).
    clusters = p.intel.miner.cluster_count if p.intel else 0
    out["threat_intel"] = {"enabled": bool(p.ti), "iocs": p.ti.store.counts()["total"] if p.ti else 0,
                           "matches": p.ti.matches if p.ti else 0}
    out["alerting"] = p.alerts.stats() if p.alerts else {"enabled": False}
    out["templates"] = clusters
    out["noise_reduced_pct"] = round(100 * (1 - clusters / m.processed), 2) if m.processed and clusters else 0.0
    return out


@router.get("/throughput")
def throughput(window: int = Query(60, ge=1, le=900), m: MetricsRegistry = Depends(get_metrics)):
    """Per-second processed-event counts for the last `window` seconds (chart-ready)."""
    return {"window_seconds": window, "eps_avg": m.rate(window), "series": m.series(window)}


@router.get("/dropped")
def dropped(m: MetricsRegistry = Depends(get_metrics)):
    """Logs REFUSED at the door (oversize, queue full): the sender was told. Not to be confused with dead-lettered logs."""
    total = sum(m.dropped.values())
    return {"total": total, "by_reason": dict(m.dropped)}


@router.get("/dead-lettered")
def dead_lettered(m: MetricsRegistry = Depends(get_metrics)):
    """Logs accepted but not normalized (parse errors, internal errors, unpublishable): kept, replayable, never lost."""
    return {"total": sum(m.dead_lettered.values()), "by_reason": dict(m.dead_lettered), "reconciliation": m.reconciliation()}


@router.get("/compression")
def compression(m: MetricsRegistry = Depends(get_metrics)):
    return {"bytes_in": m.bytes_in, "bytes_out": m.bytes_out, "ratio": m.compression_ratio,
            "saved_pct": round(100 * (1 - m.bytes_out / m.bytes_in), 2) if m.bytes_in else 0.0}


@router.get("/formats")
def formats(m: MetricsRegistry = Depends(get_metrics)):
    return dict(m.by_format)
