"""Is the Windows Security feed healthy? Checks a RUNNING LogUnify and prints PASS / WARN / FAIL per check. Exit 1 if anything FAILed.

    python scripts/verify_windows_onboarding.py --url https://logunify.example.internal --token "$ANALYST_TOKEN"
    python scripts/verify_windows_onboarding.py --url http://127.0.0.1:8000 --api-key "$KEY"      # auth_mode=off + alert API key

Run it ~10 minutes after the first host connects, and again after a day. It reads (analyst role): sources, listener stats, metrics, recent
windows_security events, calibration coverage. It never writes. What it can tell you:
  * the source is bound, the host connected, events arrive, nothing is dropped / dead-lettered;
  * the parser filled the fields the rules need (host, event code, user, source IP, outcome);
  * the TIME ZONE is right (event time vs ingest time: an offset of whole hours means the source timezone is wrong);
  * which event IDs dominate (volume you may want to filter at NXLog) and how long the buffer will hold at this rate.
"""
import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone

WANTED = {1102, 104, 4624, 4625, 4634, 4647, 4648, 4672, 4688, 4697, 4719, 4720, 4726, 4728, 4732, 4740, 4756, 7045}
NEED_USER = {4624, 4625, 4634, 4647, 4648, 4720, 4726, 4728, 4732, 4756, 4672, 4688, 4719}
LOGON_WITH_SOURCE = {4624, 4625}
RESULTS: list[tuple[str, str, str]] = []


def record(level: str, name: str, detail: str) -> None:
    RESULTS.append((level, name, detail))
    print(f"[{level:4}] {name}: {detail}")


class Api:
    def __init__(self, url: str, token: str, key: str):
        self.url, self.h = url.rstrip("/"), {}
        if token:
            self.h["Authorization"] = f"Bearer {token}"
        if key:
            self.h["X-API-Key"] = key

    def get(self, path: str):
        req = urllib.request.Request(self.url + path, headers=self.h)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            raise SystemExit(f"{path}: HTTP {e.code} {e.reason} ({'token/role missing: analyst needed' if e.code in (401, 403) else 'server error'})") from None
        except urllib.error.URLError as e:
            raise SystemExit(f"{path}: cannot reach {self.url} ({e.reason})") from None


def parse_ts(s: str | None) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def get_in(d: dict, path: str):
    for p in path.split("."):
        if not isinstance(d, dict) or p not in d:
            return None
        d = d[p]
    return d


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True)
    ap.add_argument("--token", default="", help="bearer token (analyst or higher)")
    ap.add_argument("--api-key", default="", help="X-API-Key (auth_mode=off)")
    ap.add_argument("--sample", type=int, default=500, help="how many of the newest events to inspect")
    ap.add_argument("--host", default="", help="a host name that must have been seen (substring, case-insensitive)")
    a = ap.parse_args()
    api = Api(a.url, a.token, a.api_key)

    # ---- 1. service
    try:
        urllib.request.urlopen(a.url.rstrip("/") + "/ready", timeout=10).read()
        record("PASS", "service ready", "/ready answered")
    except Exception as e:                                                                  # noqa: BLE001
        record("FAIL", "service ready", f"/ready failed: {e}")
        return 1

    # ---- 2. source + listener
    srcs = [s for s in api.get("/api/v1/sources")["items"] if s["type"] == "syslog" and s["format"] == "windows_security"]
    if not srcs:
        record("FAIL", "source", "no syslog source with format=windows_security (create it: docs/WINDOWS_SECURITY.md step 4)")
    for s in srcs:
        if s["status"] != "active" or s.get("error"):
            record("FAIL", f"source {s['name']}", f"status={s['status']} error={s.get('error')}")
        else:
            record("PASS", f"source {s['name']}", f"active, {s['config'].get('protocol')}/{s['config'].get('port')}, timezone={s['config'].get('timezone') or 'UTC (default)'}")
        if not s["config"].get("timezone"):
            record("WARN", f"source {s['name']} timezone", "no timezone set: NXLog EventTime is LOCAL time, so this is only right if the host runs UTC")
    ids = {s["id"] for s in srcs}
    listeners = [li for li in api.get("/api/v1/sources/listeners")["items"] if li["source_id"] in ids]
    for li in listeners:
        if li.get("connections_total", 0) == 0:
            record("FAIL", "host connected", f"listener {li['ports']} has had no connection yet: check NXLog log, firewall / TLS terminator, host name")
        elif li.get("tcp_received", 0) == 0:
            record("FAIL", "events received", "a client connected but sent nothing (NXLog query matched no events, or auditing is off)")
        else:
            record("PASS", "events received", f"{li.get('tcp_received', 0):,} lines over {li.get('connections_total', 0)} connection(s), {li.get('tcp_connections', 0)} open now, queue {li.get('queue_depth', 0)}/{li.get('queue_max', 0)}")
        if li.get("queue_depth", 0) > li.get("queue_max", 1) * 0.8:
            record("WARN", "listener queue", "more than 80% full: the pipeline is not keeping up")

    # ---- 3. losses
    m = api.get("/api/v1/metrics")
    bad = {k: m.get(k) for k in ("dropped", "dead_lettered") if m.get(k)}
    record("FAIL" if bad else "PASS", "no loss", f"dropped/dead-lettered: {bad}  (see /api/v1/dlq (admin) for the lines; oversize = raise LOGUNIFY_SYSLOG_MAX_MESSAGE_BYTES)" if bad else f"received {m.get('received', 0):,}, processed {m.get('processed', 0):,}, dropped 0, dead-lettered 0")

    # ---- 4. events
    res = api.get(f"/api/v1/logs/search?format=windows_security&limit={min(500, a.sample)}")
    docs, cov = res["items"], res["coverage"]
    if not docs:
        record("FAIL", "windows events", "no windows_security events held yet")
        return 1 if any(r[0] == "FAIL" for r in RESULTS) else 0
    record("PASS", "windows events", f"{res['total']:,} held; inspecting the newest {len(docs)}")
    if a.host:
        seen = {str(get_in(d, "host.name") or "").lower() for d in docs}
        ok = any(a.host.lower() in h for h in seen)
        record("PASS" if ok else "FAIL", f"host {a.host}", "seen" if ok else f"not among the newest events; hosts seen: {sorted(seen)[:8]}")

    # field completeness
    miss = Counter()
    for d in docs:
        code = get_in(d, "event.code")
        for f in ("host.name", "event.code", "@timestamp"):
            if d.get(f) is None and get_in(d, f) is None:
                miss[f] += 1
        if code in NEED_USER and not get_in(d, "user.name"):
            miss["user.name"] += 1
        if code in LOGON_WITH_SOURCE and get_in(d, "labels.logon_type") in (3, 10, "3", "10") and not get_in(d, "source.ip"):
            miss["source.ip (network logon)"] += 1
        if code in LOGON_WITH_SOURCE and not get_in(d, "event.outcome"):
            miss["event.outcome"] += 1
    if miss:
        worst = max(miss.values()) / len(docs)
        record("FAIL" if worst > 0.2 else "WARN", "parsed fields", f"missing in the sample: {dict(miss)}: NXLog may name them differently; adjust app/parsers/builtin/windows_security.yaml")
    else:
        record("PASS", "parsed fields", "host, event code, user, source IP, outcome present where expected")
    fallback = sum(1 for d in docs if get_in(d, "logunify.timestamp.source") == "received")
    if fallback:
        record("WARN", "event time", f"{fallback}/{len(docs)} events fell back to receive time (EventTime unreadable)")

    # time zone: event time vs ingest time
    skews = []
    for d in docs:
        t, i = parse_ts(d.get("@timestamp")), parse_ts(get_in(d, "event.ingested"))
        if t and i and get_in(d, "logunify.timestamp.source") != "received":
            skews.append((i - t).total_seconds())
    spread = (sorted(skews)[int(len(skews) * 0.9)] - sorted(skews)[int(len(skews) * 0.1)]) if len(skews) >= 10 else 0
    if skews and spread > 900:
        record("WARN", "time zone", f"cannot judge yet: event-to-ingest delay varies by {spread / 60:.0f} min across the sample, i.e. a backlog is being delivered (NXLog catching up, or a replay). Re-run once the feed is live")
    elif skews:
        med = statistics.median(skews)
        zone_like = abs(med) >= 1800 and abs(med - round(med / 900) * 900) <= 180        # real UTC offsets are multiples of 15 min; delays are not
        if abs(med) <= 300:
            record("PASS", "time zone", f"event time is within {abs(med):.0f}s of ingest time (median)")
        elif zone_like:
            record("FAIL", "time zone", f"event time differs from ingest time by {med:+.0f}s (= {round(med / 900) / 4:+g} h, a whole UTC offset): the source timezone is probably wrong "
                                        f"(events look like they are {'in the past' if med > 0 else 'in the FUTURE'}). Confirm the host's zone and fix the source; every search and replay window is shifted until you do")
        else:
            record("WARN", "time zone", f"event time trails ingest time by {med:+.0f}s ({med / 60:+.0f} min), not a whole-offset pattern: clock drift on the host, or NXLog delivering a backlog")

    # event-ID mix
    codes = Counter(get_in(d, "event.code") for d in docs)
    top = ", ".join(f"{c}×{n}" for c, n in codes.most_common(6))
    unexpected = {c: n for c, n in codes.items() if c not in WANTED}
    share = sum(unexpected.values()) / len(docs)
    if unexpected and share > 0.05:
        record("WARN", "event mix", f"{share:.0%} of events are IDs the rules do not use ({dict(unexpected)}): filter them in the NXLog query to save buffer. Top: {top}")
    else:
        record("PASS", "event mix", f"top: {top}")

    # volume / buffer horizon
    t0, t1 = parse_ts(cov.get("oldest")), parse_ts(cov.get("newest"))
    try:
        buf = api.get("/api/v1/alerts-calibration?format=windows_security")["replay"]["coverage"]["buffer"]
    except SystemExit:
        buf = None
    if t0 and t1 and (t1 - t0).total_seconds() >= 600 and buf:
        rate_h = cov["events_held"] / ((t1 - t0).total_seconds() / 3600)
        hours = buf / rate_h
        record("PASS" if hours >= 72 else "WARN", "buffer horizon",
               f"~{rate_h:,.0f} events/h (all sources held); the {buf:,}-event buffer covers ~{hours:,.1f} h ({hours / 24:.1f} days) at this rate"
               + ("" if hours >= 72 else ": calibration confidence stays 'low/medium' below 72 h; filter event IDs, raise LOGUNIFY_RECENT_BUFFER (~8 KB/event), or calibrate on a quieter host"))
    else:
        record("WARN", "buffer horizon", "not enough data yet to estimate the event rate (need 10+ minutes of events); run again later")

    fails = [r for r in RESULTS if r[0] == "FAIL"]
    print(f"\n{len(RESULTS) - len(fails) - sum(r[0] == 'WARN' for r in RESULTS)} passed, {sum(r[0] == 'WARN' for r in RESULTS)} warning(s), {len(fails)} failed  ({datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC)")
    return 1 if fails else 0


if __name__ == "__main__":
    t_start = time.time()
    sys.exit(main())
