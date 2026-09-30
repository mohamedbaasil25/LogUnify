"""AlertManager: turns qualifying ECS events into alerts, notifies, and tracks the CERT-In 6-hour clock.

Flow:  Pipeline.process -> on_event (sync, thread-safe, cheap) -> alert row + audit event -> queue ->
       worker delivers to each channel with retries -> maintenance loop sends deadline reminders / overdue notices,
       retries failed channels, and summarises alert storms.

Guarantees worth knowing:
  * An alert is recorded (and the clock starts) BEFORE any notification is attempted; a dead channel never loses it.
  * Failed channels are retried with backoff until someone reports or closes the alert.
  * One alert per (technique, asset) while activity continues (quiet period = dedup window); repeats only count.
  * A hard cap on first-notifications per hour protects the channels; overflow alerts stay recorded and are
    announced in one summary message, and their deadline reminders still go out.
  * Nothing is ever sent to CERT-In automatically: a human verifies and submits, then records it via mark_reported.
"""
import asyncio
import copy
import hashlib
import logging
import secrets
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime

from ..integrity.merkle import hash_record
from . import cert_in
from .messages import Message, alert_summary, build_message, build_storm_message, build_test_message
from .models import (ACTIVE, NOT_CLOSED, REPORT_CHANNELS, RESOLUTIONS, Alert, AlertNotFound, InvalidTransition)
from .notifiers import DeliveryError, build_notifiers
from .rules import AlertRules, Trigger
from .store import AlertStore
from .validation import parse_minutes

log = logging.getLogger("logunify.alerting")
_MAX_TEXT = 2000


@dataclass
class Job:
    kind: str
    alert_id: str | None
    label: str = ""


def _label(minutes: int) -> str:
    return f"{minutes // 60}h left" if minutes % 60 == 0 else f"{minutes} min left"


def _clean_details(details: dict) -> dict:
    """Validate analyst-supplied fields. None (or empty text) clears a field."""
    out: dict = {}
    for k, v in details.items():
        if k not in cert_in.ANALYST_FIELDS:
            raise ValueError(f"unknown field {k!r}")
        if v is None or (isinstance(v, str) and not v.strip()):
            out[k] = None
        elif k in ("critical", "ongoing"):
            if not isinstance(v, bool):
                raise ValueError(f"{k} must be true or false")
            out[k] = v
        elif k == "incident_type_ids":
            if not isinstance(v, list) or any(i not in cert_in.ANNEXURE_I for i in v):
                raise ValueError(f"incident_type_ids must be a list of Annexure I ids ({', '.join(cert_in.ANNEXURE_I)})")
            out[k] = list(dict.fromkeys(v))
        elif k == "i_am":
            if v not in cert_in.I_AM_CHOICES:
                raise ValueError(f"i_am must be one of {cert_in.I_AM_CHOICES}")
            out[k] = v
        else:
            if not isinstance(v, str) or len(v) > _MAX_TEXT:
                raise ValueError(f"{k} must be text of at most {_MAX_TEXT} characters")
            out[k] = v.strip()
    return out


class AlertManager:
    def __init__(self, settings, *, notifiers=None, store: AlertStore | None = None, clock=time.time,
                 sleep=asyncio.sleep, evidence_locator=None):
        s = settings
        self.rules = AlertRules(s.alert_score_threshold, s.alert_critical_techniques, s.alert_require_rule_basis)
        if s.alert_score_threshold < s.anomaly_threshold:
            log.warning("alert threshold %.2f is below the MITRE tagging threshold %.2f: only logs scoring above %.2f carry a "
                        "technique, so the effective alert threshold is %.2f", s.alert_score_threshold, s.anomaly_threshold,
                        s.anomaly_threshold, s.anomaly_threshold)
        self.dedup_s = s.alert_dedup_minutes * 60
        self.max_per_hour = s.alert_max_notifications_per_hour
        self.reminders = parse_minutes(s.alert_reminder_minutes)
        self.overdue_repeat_s = s.alert_overdue_repeat_minutes * 60
        self.maintenance_s = s.alert_maintenance_seconds
        self.retry_attempts, self.retry_base = max(1, s.alert_retry_attempts), s.alert_retry_base_s
        self.org = cert_in.OrgProfile(
            name=s.org_name, address=s.org_address, location=s.org_location, isp=s.org_isp,
            poc_name=s.poc_name, poc_designation=s.poc_designation, poc_email=s.poc_email, poc_mobile=s.poc_mobile,
            poc_phone=s.poc_phone, poc_fax=s.poc_fax,
            critical_assets=tuple(x.strip() for x in s.org_critical_assets.split(",") if x.strip()))
        self.notifiers = notifiers if notifiers is not None else build_notifiers(s)
        self.store = store or AlertStore(s.alert_db_path)
        self._clock, self._sleep, self._locator = clock, sleep, evidence_locator
        self._lock = threading.RLock()
        self._alerts: dict[str, Alert] = {}         # every non-closed alert (closed ones live only in the store)
        self._by_key: dict[str, str] = {}           # dedup key -> alert id currently absorbing repeats
        self._dirty: set[str] = set()               # alerts whose occurrence counters need flushing
        self._sent: deque[float] = deque()          # first-notification timestamps (hourly cap)
        self._storm: list[str] = []
        self._storm_last = 0.0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queue: asyncio.Queue | None = None
        self._tasks: list[asyncio.Task] = []
        self.counters: Counter = Counter()

    # ---------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        self._loop, self._queue = asyncio.get_running_loop(), asyncio.Queue()
        with self._lock:
            for a in self.store.load(NOT_CLOSED):                 # restore: the 6-hour clocks survive a restart
                self._alerts[a.id] = a
                self._by_key[a.dedup_key] = a.id
            pending = [a.id for a in self._alerts.values() if a.notification["status"] == "pending"]
        if self._alerts:
            log.info("restored %d open alert(s) from %s", len(self._alerts), self.store.path)
        if not self.notifiers:
            log.warning("alerting is enabled but NO notification channel is configured: alerts are recorded only "
                        "(set LOGUNIFY_ALERT_WEBHOOK_URL and/or LOGUNIFY_ALERT_SMTP_HOST)")
        self._tasks = [asyncio.create_task(self._worker(), name="alert-worker"),
                       asyncio.create_task(self._maintenance_loop(), name="alert-maintenance")]
        for aid in pending:
            self._enqueue(Job("incident.detected", aid))

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass
        self._tasks = []
        with self._lock:
            self._flush_dirty()
        self.store.close()

    async def drain(self) -> None:
        """Wait until queued notification jobs have been processed (tests, graceful shutdown)."""
        if self._queue is not None:
            await asyncio.sleep(0)            # let enqueues scheduled with call_soon_threadsafe land before joining
            await self._queue.join()

    # ---------------------------------------------------------------- ingest hook (called from Pipeline.process)
    def on_event(self, doc: dict) -> str | None:
        """Evaluate one ECS document. Returns the id of a NEW alert, or None (no match / absorbed as a repeat)."""
        trig = self.rules.evaluate(doc)
        if trig is None:
            return None
        now = self._clock()
        key = hashlib.sha256(f"{trig.technique_id.split('.')[0]}|{cert_in.asset_key(doc)}".encode()).hexdigest()[:16]
        with self._lock:
            current = self._alerts.get(self._by_key.get(key, ""))
            if current is not None and now - current.last_seen_at <= self.dedup_s:
                current.occurrences += 1
                current.last_seen_at = now
                self._dirty.add(current.id)
                self.counters["suppressed"] += 1
                return None
            ist_day = datetime.fromtimestamp(now, cert_in.IST).strftime("%Y%m%d")
            alert = Alert(
                id=f"ALR-{ist_day}-{secrets.token_hex(4)}", dedup_key=key, status="open", created_at=now,
                due_at=now + cert_in.DEADLINE_HOURS * 3600, last_seen_at=now, occurrences=1, trigger=trig.as_dict(), doc=doc,
                evidence={"record_sha256": hash_record(doc).hex(), "event_id": (doc.get("event") or {}).get("id")})
            self._alerts[alert.id], self._by_key[key] = alert, alert.id
            self.store.save(alert, ("created", "system", {"technique": trig.technique_id, "score": trig.score,
                                                          "basis": trig.basis, "due_at": alert.due_at, "dedup_key": key}, now))
            self.counters["triggered"] += 1
        log.warning("CRITICAL ALERT %s: %s %s score %.2f; CERT-In report due %s IST", alert.id, trig.technique_id,
                    trig.technique_name, trig.score, cert_in.ts_pair(alert.due_at)["ist"])
        self._enqueue(Job("incident.detected", alert.id))
        return alert.id

    def _enqueue(self, job: Job) -> bool:
        loop, q = self._loop, self._queue
        if loop is None or q is None:
            return False                              # not started yet: start() picks up pending alerts
        try:
            loop.call_soon_threadsafe(q.put_nowait, job)
            return True
        except RuntimeError:
            return False                              # loop closed during shutdown: the alert stays 'pending' in the store

    # ---------------------------------------------------------------- delivery
    async def _worker(self) -> None:
        assert self._queue is not None
        while True:
            job = await self._queue.get()
            try:
                await self._handle(job)
            except Exception:
                log.exception("alert job failed: %s %s", job.kind, job.alert_id)
            finally:
                self._queue.task_done()

    def _report(self, alert: Alert, now: float) -> dict:
        ref = self._locate(alert)
        return cert_in.build_report(alert, self.org, now=now, evidence_ref=ref)

    def _locate(self, alert: Alert) -> dict | None:
        if alert.evidence.get("integrity_reference"):
            return alert.evidence["integrity_reference"]
        if not self._locator:
            return None
        try:
            ref = self._locator(alert.evidence.get("record_sha256"))
        except Exception:
            log.exception("evidence lookup failed")
            return None
        if ref:                                        # cache: sealed batches are only kept in memory for a while
            with self._lock:
                alert.evidence["integrity_reference"] = ref
                self._dirty.add(alert.id)
        return ref

    def _allow_first(self, now: float) -> bool:
        while self._sent and now - self._sent[0] > 3600:
            self._sent.popleft()
        if self.max_per_hour and len(self._sent) >= self.max_per_hour:
            return False
        self._sent.append(now)
        return True

    async def _send_with_retry(self, notifier, msg: Message) -> tuple[bool, int, str | None]:
        attempts, err = 0, None
        for i in range(self.retry_attempts):
            attempts += 1
            try:
                await notifier.send(msg)
                return True, attempts, None
            except DeliveryError as e:
                err = str(e)[:300]
                if not e.retryable or i == self.retry_attempts - 1:
                    break
                await self._sleep(min(self.retry_base * (2 ** i), 60.0))
            except Exception as e:                      # a bug in a notifier must not kill the worker
                err = f"{type(e).__name__}"
                log.exception("unexpected notifier failure (%s)", notifier.name)
                break
        return False, attempts, err

    async def _handle(self, job: Job) -> None:
        if job.kind == "incident.storm":
            await self._send_storm()
            return
        with self._lock:
            alert = self._alerts.get(job.alert_id or "") or self.store.get(job.alert_id or "")
        if alert is None:
            return
        now = self._clock()
        first = job.kind == "incident.detected"
        if alert.status not in (NOT_CLOSED if first else ACTIVE):
            return                                        # reminders only matter while the clock is running
        if not self.notifiers:
            if first:
                self._record_notification(alert, now, [], "no_channels")
            return
        if first and not alert.notification.get("counted"):
            with self._lock:
                allowed = self._allow_first(now)
                alert.notification["counted"] = allowed
            if not allowed:
                with self._lock:
                    first_time = alert.notification["status"] != "rate_limited"
                    alert.notification["status"], alert.notification["last_attempt_at"] = "rate_limited", now
                    if alert.id not in self._storm:
                        self._storm.append(alert.id)              # announced once in the next storm summary
                    if first_time:                                # retries of a still-limited alert are not re-counted
                        self.counters["rate_limited"] += 1
                        self.store.save(alert, ("notification_rate_limited", "system", {"cap_per_hour": self.max_per_hour}, now))
                        log.warning("alert %s recorded but its notification was rate-limited (%d/hour cap)", alert.id, self.max_per_hour)
                return
        targets = [n for n in self.notifiers
                   if not first or not alert.notification["channels"].get(n.name, {}).get("ok")]
        msg = build_message(job.kind, alert, self._report(alert, now), label=job.label, now=now)
        results = await asyncio.gather(*(self._send_with_retry(n, msg) for n in targets))
        outcomes = [(n.name, *r) for n, r in zip(targets, results)]
        if first:
            self._record_notification(alert, now, outcomes, None)
        else:
            with self._lock:
                self.store.add_event(alert.id, job.kind, "system",
                                     {"label": job.label, "channels": {n: {"ok": ok, "attempts": a, "error": e} for n, ok, a, e in outcomes}}, now)
            self.counters["reminders_sent"] += 1

    def _record_notification(self, alert: Alert, now: float, outcomes: list, forced_status: str | None) -> None:
        with self._lock:
            n = alert.notification
            for name, ok, attempts, err in outcomes:
                prev = n["channels"].get(name, {"attempts": 0})
                n["channels"][name] = {"ok": ok, "attempts": prev["attempts"] + attempts, "last_error": None if ok else err, "last_at": now}
                self.counters["notify_ok" if ok else "notify_fail"] += 1
            n["last_attempt_at"] = now
            if forced_status:
                n["status"] = forced_status
            else:
                oks = [n["channels"].get(x.name, {}).get("ok", False) for x in self.notifiers]
                n["status"] = "sent" if all(oks) else ("partial" if any(oks) else "failed")
                if any(oks) and n["sent_at"] is None:
                    n["sent_at"] = now
                if n["status"] != "sent":
                    n["cycles"] += 1
            events = [("notified" if ok else "notify_failed", "system", {"channel": name, "attempts": attempts, "error": err}, now)
                      for name, ok, attempts, err in outcomes] or [("notification_status", "system", {"status": n["status"]}, now)]
            self.store.save(alert, events[0])
            for kind, actor, data, at in events[1:]:
                self.store.add_event(alert.id, kind, actor, data, at)
        if n["status"] in ("failed", "partial"):
            log.error("alert %s: notification %s (will keep retrying): %s", alert.id, n["status"],
                      {k: v.get("last_error") for k, v in n["channels"].items() if not v.get("ok")})

    async def _send_storm(self) -> None:
        with self._lock:
            ids, self._storm = self._storm, []
            alerts = [self._alerts[i] for i in ids if i in self._alerts and self._alerts[i].status in ACTIVE]
            self._storm_last = self._clock()
        if not alerts or not self.notifiers:
            return
        msg = build_storm_message(alerts, self._clock())
        await asyncio.gather(*(self._send_with_retry(n, msg) for n in self.notifiers))

    # ---------------------------------------------------------------- maintenance: reminders, retries, storm summary
    def _retry_delay(self, cycles: int) -> float:
        return min(60.0 * (2 ** cycles), 900.0)

    async def _maintenance_loop(self) -> None:
        while True:
            await asyncio.sleep(self.maintenance_s)
            try:
                await self.run_maintenance_once()
            except Exception:
                log.exception("alert maintenance failed")

    async def run_maintenance_once(self) -> None:
        now = self._clock()
        jobs: list[Job] = []
        with self._lock:
            self._flush_dirty()
            for a in list(self._alerts.values()):
                n = a.notification
                stale = now - (n["last_attempt_at"] or a.created_at)
                if n["status"] in ("failed", "partial", "rate_limited") and stale >= self._retry_delay(n["cycles"]):
                    n["last_attempt_at"] = now
                    jobs.append(Job("incident.detected", a.id))
                elif n["status"] == "pending" and now - a.created_at > 120:
                    jobs.append(Job("incident.detected", a.id))           # job lost (e.g. created before start): re-queue
                if a.status not in ACTIVE:
                    continue
                remaining = a.due_at - now
                if remaining <= 0:
                    if a.overdue_last_at is None or now - a.overdue_last_at >= self.overdue_repeat_s:
                        a.overdue_last_at = now
                        jobs.append(Job("incident.overdue", a.id))
                        self.store.save(a)
                else:
                    crossed = [m for m in self.reminders if remaining <= m * 60 and m not in a.reminders_sent]
                    if crossed:
                        a.reminders_sent.extend(crossed)                  # one message even if several thresholds were crossed
                        jobs.append(Job("incident.reminder", a.id, _label(min(crossed))))
                        self.store.save(a)
            if self._storm and now - self._storm_last >= 3600:
                jobs.append(Job("incident.storm", None))
        for j in jobs:
            self._enqueue(j)

    def _flush_dirty(self) -> None:
        for aid in list(self._dirty):
            a = self._alerts.get(aid)
            if a is not None:
                self.store.save(a)
        self._dirty.clear()

    # ---------------------------------------------------------------- human workflow (each step is an audit event)
    def _get(self, alert_id: str) -> Alert:
        with self._lock:
            a = self._alerts.get(alert_id) or self.store.get(alert_id)
        if a is None:
            raise AlertNotFound(alert_id)
        return a

    def acknowledge(self, alert_id: str, by: str, note: str = "", client: str | None = None) -> Alert:
        with self._lock:
            a, now = self._get(alert_id), self._clock()
            if a.status != "open":
                raise InvalidTransition(f"cannot acknowledge an alert that is {a.status}")
            a.status, a.ack = "acknowledged", {"by": by, "at": now, "note": note}
            self.store.save(a, ("acknowledged", by, {"note": note, "client": client}, now))
            return a

    def update_details(self, alert_id: str, by: str, details: dict, client: str | None = None) -> Alert:
        clean = _clean_details(details)
        with self._lock:
            a, now = self._get(alert_id), self._clock()
            if a.status == "closed":
                raise InvalidTransition("alert is closed")
            for k, v in clean.items():
                if v is None:
                    a.analyst.pop(k, None)
                else:
                    a.analyst[k] = v
            self.store.save(a, ("details_updated", by, {"fields": clean, "client": client}, now))
            return a

    def mark_reported(self, alert_id: str, by: str, *, via: str = "email", reference: str = "", note: str = "",
                      reported_at: float | None = None, client: str | None = None) -> Alert:
        if via not in REPORT_CHANNELS:
            raise ValueError(f"via must be one of {REPORT_CHANNELS}")
        with self._lock:
            a, now = self._get(alert_id), self._clock()
            if a.status not in ACTIVE:
                raise InvalidTransition(f"cannot record a report for an alert that is {a.status}")
            at = now if reported_at is None else reported_at
            if at > now + 60:
                raise ValueError("reported_at is in the future")
            if at < a.created_at:
                raise ValueError("reported_at is before the incident was noticed")
            on_time = at <= a.due_at
            a.status = "reported"
            a.reported = {"by": by, "at": at, "via": via, "reference": reference, "note": note, "on_time": on_time,
                          "late_by_seconds": None if on_time else int(at - a.due_at)}
            self.store.save(a, ("reported_to_cert_in", by, {**a.reported, "client": client}, now))
            log.info("alert %s recorded as reported to CERT-In (%s, on time: %s)", a.id, via, on_time)
            return a

    def close(self, alert_id: str, by: str, resolution: str, note: str, client: str | None = None) -> Alert:
        if resolution not in RESOLUTIONS:
            raise ValueError(f"resolution must be one of {RESOLUTIONS}")
        if resolution != "resolved" and len((note or "").strip()) < 10:
            raise ValueError(f"closing as {resolution} needs a reason of at least 10 characters (it is a compliance decision)")
        with self._lock:
            a, now = self._get(alert_id), self._clock()
            if a.status == "closed":
                raise InvalidTransition("alert is already closed")
            if resolution == "resolved" and a.status != "reported":
                raise InvalidTransition("an incident can only be closed as 'resolved' after it was reported to CERT-In; "
                                        "otherwise close it as false_positive or not_reportable with a reason")
            if resolution != "resolved" and a.status == "reported":
                raise InvalidTransition("a reported incident can only be closed as 'resolved'")
            a.status, a.closed = "closed", {"by": by, "at": now, "resolution": resolution, "note": note}
            self._alerts.pop(a.id, None)
            if self._by_key.get(a.dedup_key) == a.id:
                self._by_key.pop(a.dedup_key, None)
            self._dirty.discard(a.id)
            self.store.save(a, ("closed", by, {"resolution": resolution, "note": note, "client": client}, now))
            return a

    # ---------------------------------------------------------------- queries
    def list_alerts(self, status: str | None = None, limit: int = 50) -> list[dict]:
        now = self._clock()
        with self._lock:
            if status == "active":
                items = [a for a in self._alerts.values() if a.status in ACTIVE]
            elif status in ("open", "acknowledged", "reported"):
                items = [a for a in self._alerts.values() if a.status == status]
            elif status == "closed":
                items = self.store.list_alerts("closed", limit)
            else:
                items = list(self._alerts.values()) + self.store.list_alerts("closed", limit)
            items = sorted(items, key=lambda a: a.created_at, reverse=True)[:limit]
            return [alert_summary(a, now) for a in items]

    def view(self, alert_id: str) -> dict:
        """Snapshot of an alert. Deep-copied under the lock: callers (the API) serialise it while the worker and
        other threads keep mutating the live alert."""
        with self._lock:
            a, now = self._get(alert_id), self._clock()
            return copy.deepcopy({"summary": alert_summary(a, now), "trigger": a.trigger, "notification": a.notification,
                                  "analyst": a.analyst, "ack": a.ack, "reported": a.reported, "closed": a.closed,
                                  "evidence": a.evidence, "last_seen_at": a.last_seen_at})

    def report_for(self, alert_id: str) -> dict:
        a = self._get(alert_id)
        return self._report(a, self._clock())

    def evidence_for(self, alert_id: str) -> dict:
        a = self._get(alert_id)
        return {"alert_id": a.id, "record_sha256": a.evidence.get("record_sha256"), "integrity_reference": self._locate(a),
                "note": "Unredacted record as processed. Directions para (iv): provide logs to CERT-In with the report.",
                "record": a.doc}

    def events_for(self, alert_id: str) -> list[dict]:
        self._get(alert_id)
        return self.store.events(alert_id)

    def stats(self) -> dict:
        now = self._clock()
        with self._lock:
            active = [a for a in self._alerts.values() if a.status in ACTIVE]
            return {"enabled": True, "channels": [n.name for n in self.notifiers], "triggered": self.counters["triggered"],
                    "suppressed": self.counters["suppressed"], "open": len(active),
                    "overdue": sum(1 for a in active if a.due_at <= now),
                    "notifications_ok": self.counters["notify_ok"], "notifications_failed": self.counters["notify_fail"],
                    "rate_limited": self.counters["rate_limited"]}

    def config_view(self) -> dict:
        return {"score_threshold": self.rules.threshold, "critical_techniques": sorted(self.rules.critical),
                "require_rule_basis": self.rules.require_rule_basis, "dedup_minutes": self.dedup_s // 60,
                "max_notifications_per_hour": self.max_per_hour, "reminder_minutes_before_due": list(self.reminders),
                "deadline_hours": cert_in.DEADLINE_HOURS,
                "channels": [{"name": n.name, "target": getattr(n, "label", None)} for n in self.notifiers],
                "webhook_signed": any(n.name == "webhook" and getattr(n, "_secret", None) for n in self.notifiers),
                "organization_configured": bool(self.org.name and self.org.poc_name and self.org.poc_email)}

    async def send_test(self) -> dict:
        """One clearly-labelled TEST message through every channel (no alert, no clock, single attempt each)."""
        msg = build_test_message(self.org, self._clock())
        out = {}
        for n in self.notifiers:
            try:
                await n.send(msg)
                out[n.name] = {"ok": True}
            except DeliveryError as e:
                out[n.name] = {"ok": False, "error": str(e)[:300], "retryable": e.retryable}
        return out
