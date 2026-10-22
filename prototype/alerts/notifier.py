"""Webhook alerting: score strictly above the threshold AND a critical technique. Redis (if reachable) de-duplicates repeats."""
import json
import logging
import os

import aiohttp

log = logging.getLogger("logunify.alerts")


def threshold() -> float:
    try:
        return float(os.getenv("LOGUNIFY_ALERT_SCORE_THRESHOLD", "0.80"))
    except ValueError:
        return 0.80


def critical_techniques() -> set[str]:
    return {t.strip() for t in os.getenv("LOGUNIFY_CRITICAL_TECHNIQUES", "T1059,T1059.001,T1003,T1136,T1070").split(",") if t.strip()}


def should_alert(ev: dict) -> bool:
    return ev.get("event.risk_score_norm", 0.0) > threshold() and bool(critical_techniques() & set(ev.get("threat.technique.id", [])))


def _payload(ev: dict) -> dict:
    ids = ", ".join(ev.get("threat.technique.id", []))
    text = (f"LogUnify alert: score {ev['event.risk_score_norm']:.2f} (> {threshold():.2f}) [{ids}] on {ev.get('host.name', '?')} "
            f"user={ev.get('user.name', '?')} src={ev.get('source.ip', '-')} at {ev['@timestamp']}")
    return {"text": text, "event": {k: ev.get(k) for k in ("@timestamp", "host.name", "user.name", "source.ip", "event.code", "event.risk_score_norm",
                                                           "threat.technique.id", "process.command_line", "event.original")}}


async def notify(ev: dict, session: aiohttp.ClientSession, redis=None) -> bool:
    """True if a webhook POST succeeded. Never raises: an alerting failure must not stop the pipeline."""
    if not should_alert(ev):
        return False
    url = os.getenv("LOGUNIFY_WEBHOOK_URL", "")
    if not url:
        log.warning("alert condition met but LOGUNIFY_WEBHOOK_URL is not set")
        return False
    key = f"logunify:dedup:{ev.get('host.name')}:{ev.get('user.name')}:{','.join(ev.get('threat.technique.id', []))}"
    try:
        if redis is not None and not await redis.set(key, "1", nx=True, ex=int(os.getenv("LOGUNIFY_ALERT_DEDUP_SECONDS", "1800"))):
            log.info("alert suppressed (duplicate within dedup window): %s", key)
            return False
    except Exception as e:                                       # Redis down: alert anyway rather than lose it
        log.error("dedup unavailable (%s); sending without dedup", e)
    try:
        async with session.post(url, data=json.dumps(_payload(ev)), headers={"content-type": "application/json"}, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status >= 300:
                raise RuntimeError(f"webhook returned HTTP {r.status}")
        log.warning("ALERT sent: %s", ev["host.name"] if "host.name" in ev else "?")
        return True
    except Exception as e:
        log.error("webhook delivery failed: %s", e)
        try:
            if redis is not None:
                await redis.delete(key)                          # let the next occurrence retry
        except Exception:
            pass
        return False
