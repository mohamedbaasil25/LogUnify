"""Alert calibration: what the alert rules WOULD have done on the events held, and what analysts decided about the alerts that fired.

Two independent evidence sources, kept separate so nobody mistakes one for the other:
  * REPLAY   the rules re-run over the events this instance still holds (the recent-events ring, `LOGUNIFY_RECENT_BUFFER`). It answers "how
             many alerts would threshold X / technique set Y have produced?". It cannot tell a false positive from a true one.
  * FEEDBACK the closed alerts in the alert store (`false_positive`, `not_reportable`, `resolved`). It answers "how often were we wrong,
             and where?". It only exists for alerts that actually fired at the thresholds in force at the time.

Everything is computed with the production rules (`AlertRules`) and the production grouping (technique + asset, one alert per quiet
period), so the counts are what an analyst would have received. Pure functions: no I/O, easy to test.
"""
import fnmatch
from collections import Counter, defaultdict
from datetime import datetime, timezone

from . import cert_in
from .rules import AlertRules, get

SWEEP = (0.70, 0.75, 0.80, 0.85, 0.90, 0.95)


def _ts(doc: dict) -> float | None:
    try:
        t = datetime.fromisoformat(str(doc.get("@timestamp", "")).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).timestamp()


def histogram(scores: list[float], bins: int = 20) -> list[dict]:
    counts = [0] * bins
    for s in scores:
        counts[min(bins - 1, max(0, int(s * bins)))] += 1
    return [{"from": round(i / bins, 4), "to": round((i + 1) / bins, 4), "count": c} for i, c in enumerate(counts)]


def percentiles(scores: list[float]) -> dict:
    if not scores:
        return {}
    s = sorted(scores)
    at = lambda q: round(s[min(len(s) - 1, int(len(s) * q))], 4)   # noqa: E731
    return {"p50": at(.5), "p90": at(.9), "p99": at(.99), "p999": at(.999), "max": round(s[-1], 4)}


def is_suppressed(sup: list[dict], technique_id: str, doc: dict, now: float) -> dict | None:
    """First active suppression covering this technique + asset (the same match `AlertManager.on_event` applies)."""
    tid = technique_id.upper()
    parent = tid.split(".")[0]
    asset = cert_in.asset_key(doc).lower()
    for s in sup:
        if s.get("revoked_at") or s["expires_at"] <= now:
            continue
        if s["technique"] != "*" and s["technique"].upper() not in (tid, parent):
            continue
        if fnmatch.fnmatchcase(asset, s["asset"].lower()):
            return s
    return None


def group_alerts(docs: list[dict], rules: AlertRules, dedup_s: float, suppressions: list[dict] | None = None, now: float = 0.0) -> dict:
    """Run the rules over `docs` (oldest first) and group like production: one alert per (technique family, asset), repeats inside
    `dedup_s` of the previous hit are absorbed. Returns {alerts: [...], events: n, suppressed: n}."""
    last: dict[tuple, float] = {}
    alerts: list[dict] = []
    open_alert: dict[tuple, dict] = {}
    events = suppressed = 0
    ordered = sorted(enumerate(docs), key=lambda p: (_ts(p[1]) or 0.0, p[0]))
    for _, d in ordered:
        trig = rules.evaluate(d)
        if trig is None:
            continue
        if suppressions and is_suppressed(suppressions, trig.technique_id, d, now or (_ts(d) or 0.0)):
            suppressed += 1
            continue
        events += 1
        key = (trig.technique_id.split(".")[0], cert_in.asset_key(d))
        t = _ts(d) or 0.0
        if key in open_alert and t - last[key] <= dedup_s:
            open_alert[key]["occurrences"] += 1
        else:
            a = cert_in.affected_asset(d)
            open_alert[key] = {"technique": trig.technique_id, "technique_name": trig.technique_name, "asset": key[1],
                               "host": a["host"], "score": round(trig.score, 4), "at": d.get("@timestamp"), "occurrences": 1,
                               "basis": trig.basis, "event_id": (d.get("event") or {}).get("id"),
                               "message": str(d.get("message") or (d.get("event") or {}).get("original") or "")[:300]}
            alerts.append(open_alert[key])
        last[key] = t
    return {"alerts": alerts, "events": events, "suppressed": suppressed}


def funnel(docs: list[dict], rules: AlertRules, suppressions: list[dict] | None = None, now: float = 0.0) -> list[dict]:
    """Why alerts do or do not fire: how many events survive each condition, in order. The step where the count collapses is the
    thing to fix (a warming model, a threshold nothing reaches, placeholder tags, a technique outside the critical set)."""
    n = len(docs)
    ready = [d for d in docs if get(d, "logunify", "anomaly", "model_ready") is not False
             and isinstance(get(d, "logunify", "anomaly", "score"), (int, float))]
    over = [d for d in ready if get(d, "logunify", "anomaly", "score") > rules.threshold]
    tagged = [d for d in over if isinstance(get(d, "threat", "technique", "id"), str)]
    based = [d for d in tagged if not rules.require_rule_basis or str(get(d, "logunify", "mitre", "basis") or "").startswith("rule:")]

    def crit(d):
        tid = get(d, "threat", "technique", "id").strip().upper()
        return tid in rules.critical or tid.split(".")[0] in rules.critical
    critical = [d for d in based if crit(d)]
    kept = [d for d in critical if not (suppressions and is_suppressed(suppressions, get(d, "threat", "technique", "id"), d, now or (_ts(d) or 0.0)))]
    return [
        {"step": "events held", "count": n, "why": "the window being replayed"},
        {"step": "model warmed up", "count": len(ready), "why": "a score from a model still warming up is not evidence, so it never alerts"},
        {"step": f"score above {rules.threshold:g}", "count": len(over), "why": "the alert threshold (strictly greater than)"},
        {"step": "carries a MITRE technique", "count": len(tagged), "why": "techniques are only tagged above the tagging threshold (LOGUNIFY_ANOMALY_THRESHOLD)"},
        {"step": "technique chosen by a rule", "count": len(based), "why": "the placeholder T1078 fallback tag is ignored (LOGUNIFY_ALERT_REQUIRE_RULE_BASIS)"},
        {"step": "technique is in the critical set", "count": len(critical), "why": "LOGUNIFY_ALERT_CRITICAL_TECHNIQUES"},
        {"step": "not suppressed", "count": len(kept), "why": "active suppression rules"},
    ]


def sweep(docs: list[dict], rules: AlertRules, dedup_s: float, thresholds=SWEEP, suppressions=None, now: float = 0.0) -> list[dict]:
    out = []
    for thr in sorted({round(t, 4) for t in thresholds}):
        r = AlertRules(thr, rules.critical, rules.require_rule_basis)
        g = group_alerts(docs, r, dedup_s, suppressions, now)
        techs = Counter(a["technique"] for a in g["alerts"])
        out.append({"threshold": thr, "events": g["events"], "alerts": len(g["alerts"]), "suppressed": g["suppressed"],
                    "techniques": dict(techs.most_common(8))})
    return out


def feedback(alerts: list, now: float, top: int = 10) -> dict:
    """What analysts decided. `alerts` are Alert objects (any status) created in the period of interest."""
    closed = [a for a in alerts if a.status == "closed" and a.closed]
    res = Counter(a.closed["resolution"] for a in closed)
    by_tech: dict[str, Counter] = defaultdict(Counter)
    by_asset: dict[tuple, Counter] = defaultdict(Counter)
    for a in closed:
        fam = a.trigger["technique_id"].split(".")[0]
        asset = cert_in.asset_key(a.doc)
        for c in (by_tech[fam], by_asset[(fam, asset)]):
            c["closed"] += 1
            c[a.closed["resolution"]] += 1
    rate = lambda c: round(c["false_positive"] / c["closed"], 3) if c["closed"] else None   # noqa: E731
    techniques = sorted(({"technique": t, "closed": c["closed"], "false_positive": c["false_positive"],
                          "not_reportable": c["not_reportable"], "resolved": c["resolved"], "fp_rate": rate(c)}
                         for t, c in by_tech.items()), key=lambda r: (-r["false_positive"], r["technique"]))
    noisy = sorted(({"technique": t, "asset": asset, "closed": c["closed"], "false_positive": c["false_positive"],
                     "not_reportable": c["not_reportable"], "resolved": c["resolved"],
                     "candidate": c["false_positive"] >= 3 and c["resolved"] == 0}
                    for (t, asset), c in by_asset.items() if c["false_positive"]), key=lambda r: -r["false_positive"])[:top]
    reported = [a for a in alerts if a.reported]
    on_time = sum(1 for a in reported if a.reported.get("on_time"))
    active = [a for a in alerts if a.status in ("open", "acknowledged")]
    return {"alerts_total": len(alerts), "closed": len(closed), "resolutions": dict(res),
            "false_positive_rate": round(res["false_positive"] / len(closed), 3) if closed else None,
            "techniques": techniques, "noisiest_assets": noisy,
            "cert_in": {"reported": len(reported), "on_time": on_time,
                        "on_time_rate": round(on_time / len(reported), 3) if reported else None,
                        "overdue_now": sum(1 for a in active if a.due_at <= now), "active_now": len(active)}}


def per_day(alerts: list, days: int = 14) -> list[dict]:
    c = Counter(datetime.fromtimestamp(a.created_at, cert_in.IST).strftime("%Y-%m-%d") for a in alerts)
    return [{"day": d, "alerts": n} for d, n in sorted(c.items())][-days:]


def confidence(n_events: int, window_s: float) -> dict:
    """How far to trust a replay. Alert volume extrapolated from a short window is a guess, not a measurement."""
    h = window_s / 3600
    level = "high" if (h >= 72 and n_events >= 5000) else "medium" if (h >= 24 and n_events >= 1000) else "low"
    why = f"{n_events:,} events over {h:.1f} h"
    if level == "low":
        why += ": too little to extrapolate daily volume (aim for 3+ days including a weekend and a busy period)"
    return {"level": level, "window_hours": round(h, 2), "events": n_events, "why": why}


def recommend(rows: list[dict], window_s: float, capacity_per_day: float, current: float) -> dict:
    """The LOWEST threshold whose projected volume fits the analysts' capacity (lower = more detection). Advice, never applied automatically."""
    days = max(window_s / 86400, 1e-9)
    for r in rows:
        r["alerts_per_day"] = round(r["alerts"] / days, 2) if window_s >= 3600 else None
    fits = [r for r in rows if r["alerts_per_day"] is not None and r["alerts_per_day"] <= capacity_per_day]
    if window_s < 3600:
        return {"threshold": None, "text": "The window is under an hour: not enough data to project daily volume."}
    if not fits:
        return {"threshold": None, "text": f"No threshold in the sweep fits {capacity_per_day:g} alerts/day. Narrow the critical-technique set, "
                                            "suppress confirmed noise, or add capacity; do not raise the threshold just to hide volume."}
    pick = fits[0]
    same = abs(pick["threshold"] - current) < 1e-9
    return {"threshold": pick["threshold"],
            "text": (f"Current threshold {current:g} already is the lowest that fits {capacity_per_day:g} alerts/day." if same else
                     f"Lowest threshold fitting {capacity_per_day:g} alerts/day: {pick['threshold']:g} (about {pick['alerts_per_day']:g}/day). "
                     f"Set LOGUNIFY_ALERT_SCORE_THRESHOLD={pick['threshold']:g} and restart; it is not changed from here.")}
