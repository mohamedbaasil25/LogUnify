"""Control mapping: what LogUnify does (and does not do) against CERT-In, PCI-DSS v4.0, HIPAA Security Rule and ISO 27001:2022.

Statuses, deliberately conservative:
  met      an automated check in THIS run supports the control's log-management aspect
  partial  LogUnify contributes, but part of the control lies outside it, or the evidence is a mock / heuristic
  gap      the current configuration does not satisfy it (the evidence says why)
  manual   organisational, not machine-checkable (procedures, NTP, contracts); a human must attest

The control descriptions are short paraphrases for orientation, not the standards' wording. A green report is
evidence for an assessor, not a certification, and covers LogUnify only, not the systems that produce the logs.
"""
from dataclasses import dataclass


@dataclass
class Ctx:
    settings: object
    retention: dict            # retention.static_proof()
    live: dict                 # retention.live_elasticsearch()
    audit: dict                # AuditLog.verify()
    metrics: dict              # MetricsRegistry.summary()
    alerting_enabled: bool
    ledger_mock: bool = True


def _min_days(c: Ctx) -> float | None:
    ls = c.retention.get("layers") or []
    return min((x["days"] for x in ls), default=None)


def _rbac(c: Ctx) -> bool:
    return c.settings.auth_mode == "jwt"


def _pii(c: Ctx) -> tuple[bool, str]:
    s = c.settings
    on = s.pii_enabled
    fails = c.metrics.get("pii", {}).get("failures", 0)
    return on, (f"PII redaction {'on' if on else 'OFF'} (types: {s.pii_types}; mode: {s.pii_mode}); "
                f"{sum(c.metrics.get('pii', {}).get('redactions', {}).values())} values masked since start; {fails} redaction failures")


def _retention_eval(c: Ctx, need_days: int, what: str):
    d = _min_days(c)
    if d is None:
        return "manual", f"{what}: policy files not available to this run; cannot evidence retention"
    live = c.live.get("checked")
    basis = f"static policy files (shortest layer {d:g} d)" + ("; live Elasticsearch checks " + ("passed" if c.live.get("passed") else "FAILED") if live else "; no live cluster check")
    if d < need_days:
        return "gap", f"{what} needs {need_days} d; configured retention is {d:g} d ({basis}). Raise the ILM/ISM/Splunk delete ages and re-run policy_lint"
    if live and not c.live.get("passed"):
        return "partial", f"{what}: policy files satisfy {need_days} d but the live cluster check failed ({basis})"
    return ("met" if live else "partial"), f"{what}: {basis}"


def evaluate(c: Ctx) -> list[dict]:
    s, out = c.settings, []

    def add(fw, cid, title, need, status, ev):
        out.append({"framework": fw, "id": cid, "title": title, "requirement": need, "status": status, "evidence": ev})

    pii_on, pii_ev = _pii(c)
    audit_ok = c.audit.get("valid")
    audit_ev = (f"hash-chained audit log: {c.audit.get('records', 0)} records, chain {'VALID' if audit_ok else 'BROKEN'}"
                f"{' (keyed HMAC)' if c.audit.get('keyed') else ' (unkeyed: detects accidents, not a DB-level attacker)'}")
    rb_ev = f"auth_mode={s.auth_mode}" + ("; roles viewer/analyst/admin enforced" if _rbac(c) else "; ALL callers are admin, enable LOGUNIFY_AUTH_MODE=jwt")
    integ = c.metrics.get("integrity", {})
    integ_ev = (f"{integ.get('batches_sealed', 0)} Merkle batches sealed, {integ.get('batches_anchored', 0)} anchored on a "
                f"{'MOCK ledger (not a real Fabric network)' if c.ledger_mock else 'ledger'}")
    integ_status = "partial" if c.ledger_mock else "met"
    org_ok = bool(s.org_name and s.poc_name and s.poc_email)
    alert_ev = f"alerting {'on' if c.alerting_enabled else 'OFF'}; threshold {s.alert_score_threshold}"
    ntp = "Time synchronisation is a host/infrastructure control; attest separately (NTP to NIC/NPL for CERT-In)"
    audit_st = "met" if audit_ok else "gap"
    rb_st = "met" if _rbac(c) else "gap"
    pii_st = "partial" if pii_on else "gap"
    pii_note = pii_ev + ". Heuristic detectors; the raw Kafka topic still holds unredacted originals until it expires"

    # ---- CERT-In -------------------------------------------------------------------------------------------------
    st, ev = _retention_eval(c, 180, "180-day log retention")
    region = [f for f in c.retention.get("findings", []) if " E8 " in f and f.startswith("WARN")]
    if region and st == "met":
        st, ev = "partial", ev + ". Snapshot region is outside India: allowed only if producible to CERT-In (FAQ Q35)"
    add("CERT-In", "Dir.(iv)", "Retain logs 180 days, Indian jurisdiction", "Maintain ICT system logs for a rolling 180 days within Indian jurisdiction", st, ev)
    add("CERT-In", "Dir.(ii)", "Report incidents within 6 hours",
        "Report Annexure I incidents to CERT-In within 6 hours of noticing",
        "partial" if c.alerting_enabled else "gap",
        alert_ev + "; deadline clock, reminders and a form-aligned draft report. LogUnify never files for you")
    add("CERT-In", "Dir.(iii)", "Designate a Point of Contact", "Provide and keep current a PoC for CERT-In",
        "met" if org_ok else "gap", "organisation + PoC details " + ("configured" if org_ok else "MISSING (LOGUNIFY_ORG_*, LOGUNIFY_POC_*)"))
    add("CERT-In", "Dir.(v)", "Synchronise clocks to NIC/NPL NTP", "System clocks synchronised to NIC or NPL time sources", "manual", ntp)

    # ---- PCI-DSS v4.0 --------------------------------------------------------------------------------------------
    st, ev = _retention_eval(c, 365, "12-month audit-log history")
    add("PCI-DSS 4.0", "10.5.1", "Retain audit-log history 12 months", "Keep audit logs 12 months, the last 3 months immediately available", st, ev)
    add("PCI-DSS 4.0", "10.3.4", "Detect changes to stored logs", "Change-detection / file-integrity mechanism on audit logs",
        integ_status, integ_ev)
    add("PCI-DSS 4.0", "10.3.1", "Restrict read access to logs", "Read access to audit logs limited to those with a job-related need", rb_st, rb_ev)
    add("PCI-DSS 4.0", "10.2.1.2", "Log administrative actions", "Audit logs capture all actions by administrative-access individuals", audit_st, audit_ev)
    add("PCI-DSS 4.0", "3.5.1", "PAN unreadable where stored", "Primary account numbers rendered unreadable anywhere they are stored", pii_st, pii_note)
    add("PCI-DSS 4.0", "7.2", "Least-privilege access", "Access assigned by job function, least privilege", rb_st, rb_ev)
    add("PCI-DSS 4.0", "10.4.1.1", "Automated log review", "Audit-log reviews performed with automated mechanisms",
        "partial" if c.alerting_enabled else "gap", alert_ev + "; Isolation Forest scoring + MITRE tagging (heuristic, not validated detection content)")
    add("PCI-DSS 4.0", "10.6.1", "Synchronised system clocks", "System clocks synchronised using time-synchronisation technology", "manual", ntp)

    # ---- HIPAA Security Rule -------------------------------------------------------------------------------------
    add("HIPAA", "164.312(b)", "Audit controls", "Record and examine activity in systems containing ePHI", "partial",
        "LogUnify normalises and scores the logs it receives and keeps its own action audit; recording at the source systems is outside it. " + audit_ev)
    add("HIPAA", "164.312(c)(1)", "Integrity", "Protect ePHI from improper alteration or destruction", integ_status, integ_ev)
    add("HIPAA", "164.312(a)(1)", "Access control", "Access only for authorised persons/software", rb_st, rb_ev)
    add("HIPAA", "164.312(a)(2)(i)", "Unique user identification", "Assign a unique name/number to each user", rb_st,
        "the audit log records the token subject (sub) per action" if _rbac(c) else rb_ev)
    add("HIPAA", "164.312(d)", "Person or entity authentication", "Verify that a person seeking access is who they claim", rb_st,
        rb_ev + "; HS256 shared-secret tokens only. Federating a real IdP (RS256/JWKS) is not implemented")
    add("HIPAA", "164.312(e)(1)", "Transmission security", "Guard against unauthorised access to ePHI in transit", "gap",
        "no mTLS between backend, Kafka, Flink and Vector; TLS terminates outside LogUnify (not implemented)")
    st, ev = _retention_eval(c, 6 * 365, "6-year documentation retention")
    add("HIPAA", "164.316(b)(2)(i)", "Retain required documentation 6 years",
        "Retain security documentation six years (whether logs count is a legal call)", st if st != "met" else "partial", ev)
    add("HIPAA", "164.308(a)(6)", "Security incident procedures", "Identify, respond to and document security incidents",
        "partial" if c.alerting_enabled else "gap", alert_ev + "; workflow ack, details, report, close with append-only history")
    add("HIPAA", "PHI coverage", "PHI-specific redaction", "Minimum-necessary handling of ePHI in logs", "gap",
        "detectors cover cards, e-mail, SSN, Aadhaar, PAN (phone optional); names, MRNs, dates of birth and free-text PHI are NOT detected")

    # ---- ISO/IEC 27001:2022 Annex A ------------------------------------------------------------------------------
    st, ev = _retention_eval(c, 180, "log retention")
    add("ISO 27001:2022", "A.8.15", "Logging", "Produce, store, protect and analyse logs", "partial" if st != "gap" else "gap",
        ev + "; " + integ_ev)
    add("ISO 27001:2022", "A.8.16", "Monitoring activities", "Monitor systems for anomalous behaviour", "partial" if c.alerting_enabled else "gap", alert_ev)
    add("ISO 27001:2022", "A.8.17", "Clock synchronisation", "Synchronise clocks to approved sources", "manual", ntp)
    add("ISO 27001:2022", "A.5.15", "Access control", "Rules for physical and logical access", rb_st, rb_ev)
    add("ISO 27001:2022", "A.8.3", "Information access restriction", "Restrict access to information per policy", rb_st, rb_ev)
    add("ISO 27001:2022", "A.8.5", "Secure authentication", "Authenticate users securely", rb_st, rb_ev)
    add("ISO 27001:2022", "A.8.11", "Data masking", "Mask data per access-control and business requirements", pii_st, pii_note)
    add("ISO 27001:2022", "A.5.34", "Privacy and PII protection", "Protect PII per law and contract (GDPR, DPDP Act)", pii_st, pii_note)
    arch_ev = ("raw archive ON (" + ("AES-256-GCM encrypted" if s.raw_archive_key else "NOT ENCRYPTED") + f", retention {s.raw_archive_retention_days or 'unlimited'} d): "
               "/api/v1/trace/{event.id} proves raw bytes -> normalized record -> Merkle batch" if s.raw_archive_enabled else
               "raw archive OFF: event.hash is stamped on every record but the original bytes are not retained, so a record cannot be proven against what was received")
    add("ISO 27001:2022", "A.5.28", "Collection of evidence", "Procedures to identify, collect and preserve evidence", integ_status,
        integ_ev + "; evidence endpoint returns record + SHA-256 + batch reference; " + arch_ev + "; " + audit_ev)
    add("ISO 27001:2022", "A.5.24-26", "Incident management", "Plan, assess and respond to incidents",
        "partial" if c.alerting_enabled else "gap", alert_ev + "; CERT-In 6-hour workflow")
    return out


def summarise(controls: list[dict]) -> dict:
    fw: dict[str, dict[str, int]] = {}
    for x in controls:
        fw.setdefault(x["framework"], {"met": 0, "partial": 0, "gap": 0, "manual": 0})[x["status"]] += 1
    return fw
