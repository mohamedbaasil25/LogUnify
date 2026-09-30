"""Compliance report: retention proof + control mapping, as JSON and as an auditor-facing PDF.

The report carries a SHA-256 over its canonical JSON body (`report_sha256`, printed in the PDF footer). Anchor or archive
that hash to show a report was not edited afterwards. It states what was checked, at what evidence level, and what was not.
"""
import hashlib
import json
import time

from .controls import Ctx, evaluate, summarise
from .pdf import Pdf
from .retention import live_elasticsearch, static_proof

_COLOR = {"met": (0.05, 0.5, 0.2), "partial": (0.75, 0.5, 0.0), "gap": (0.8, 0.1, 0.1), "manual": (0.3, 0.3, 0.6)}
_LABEL = {"met": "MET", "partial": "PARTIAL", "gap": "GAP", "manual": "MANUAL"}

SCOPE = ("Scope: this report covers the LogUnify pre-processing platform only, not the systems that produce the logs nor the "
         "organisation's procedures. It is evidence for an assessor, not a certification. Statuses: MET = automated evidence "
         "in this run; PARTIAL = LogUnify contributes but part lies elsewhere or rests on a mock/heuristic; GAP = current "
         "configuration does not satisfy it; MANUAL = needs human attestation.")


def build(settings, pipeline, audit, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    retention = static_proof(settings.forwarder_root)
    live = live_elasticsearch(settings.es_url, settings.es_api_key.get_secret_value() if settings.es_api_key else None,
                              settings.es_verify_ssl)
    ctx = Ctx(settings, retention, live, audit.verify(), pipeline.metrics.summary(), pipeline.alerts is not None)
    controls = evaluate(ctx)
    body = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "scope": SCOPE,
        "system": {"auth_mode": settings.auth_mode, "pii_enabled": settings.pii_enabled,
                   "ledger": "MOCK Hyperledger Fabric (simulated)", "geoip": "MOCK", "mitre_rules": "heuristic, not validated"},
        "retention": {"required_days": 180, "static": retention, "live": live},
        "audit_log": ctx.audit,
        "summary": summarise(controls),
        "controls": controls,
    }
    body["report_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return body


def render_pdf(rep: dict) -> bytes:
    pdf = Pdf("LogUnify compliance report", f"LogUnify | generated {rep['generated_at']} | sha256 {rep['report_sha256'][:16]}")
    pdf.text("LogUnify Compliance & Retention Report", 18, bold=True, gap=2)
    pdf.text(f"Generated {rep['generated_at']}   |   report SHA-256 {rep['report_sha256']}", 8, color=(0.4, 0.4, 0.4), gap=6)
    pdf.text(rep["scope"], 9, gap=6)
    sysinfo = rep["system"]
    pdf.text("Known limitations of this deployment", 11, bold=True)
    pdf.text(f"Ledger: {sysinfo['ledger']}.  GeoIP: {sysinfo['geoip']}.  MITRE tagging: {sysinfo['mitre_rules']}.  "
             f"Authentication: {sysinfo['auth_mode']}.", 9, gap=8)

    pdf.text("Summary by framework", 12, bold=True)
    for fw, c in rep["summary"].items():
        pdf.text(f"{fw}:  {c['met']} met, {c['partial']} partial, {c['gap']} gap, {c['manual']} manual", 10, indent=8)
    pdf.space(8)

    r = rep["retention"]
    pdf.text("180-day retention proof", 12, bold=True)
    st = r["static"]
    if not st["available"]:
        pdf.text("Static policy evidence: " + st["reason"], 9, color=_COLOR["gap"])
    else:
        verdict = "PASS" if st["passed"] else "FAIL"
        pdf.text(f"Static policy evidence: {verdict}  ({st['lint_errors']} lint errors). Basis: {st['basis']}.", 9,
                 color=_COLOR["met"] if st["passed"] else _COLOR["gap"])
        for x in st["layers"]:
            pdf.text(f"[{'OK' if x['ok'] else 'SHORT'}] {x['layer']}: {x['setting']} = {x['days']:g} d (required {x['required_days']} d)",
                     9, indent=8)
        for f in st["findings"]:
            pdf.text(f, 8, indent=8, color=(0.4, 0.4, 0.4))
    lv = r["live"]
    if not lv["checked"]:
        pdf.text("Live cluster evidence: NOT CHECKED (" + lv["reason"] + "). Static evidence proves intended policy only.", 9,
                 color=_COLOR["manual"])
    else:
        pdf.text(f"Live Elasticsearch evidence ({lv['url']}): {'PASS' if lv['passed'] else 'FAIL'}; oldest index age "
                 f"{lv.get('oldest_index_age')}", 9, color=_COLOR["met"] if lv["passed"] else _COLOR["gap"])
        for c in lv["checks"]:
            pdf.text(f"[{'OK' if c['ok'] else 'FAIL'}] {c['name']}: {c['detail']}", 9, indent=8)
    pdf.text("Not proven by this report: that no deletion occurred early, or that a snapshot restores. Splunk and Wazuh have "
             "no live probe (static only).", 8, color=(0.4, 0.4, 0.4), gap=6)

    a = rep["audit_log"]
    pdf.text("Audit-log integrity", 12, bold=True)
    pdf.text(f"{a['records']} records; hash chain {'VALID' if a['valid'] else 'BROKEN at seq ' + str(a.get('broken_at'))}"
             f"{'; keyed (HMAC)' if a.get('keyed') else '; unkeyed'}", 9,
             color=_COLOR["met"] if a["valid"] else _COLOR["gap"], gap=8)

    fw_seen = None
    for x in rep["controls"]:
        if x["framework"] != fw_seen:
            fw_seen = x["framework"]
            pdf.space(6)
            pdf.rule()
            pdf.text(f"Control mapping: {fw_seen}", 13, bold=True, gap=2)
        pdf.text(f"[{_LABEL[x['status']]}]  {x['id']}  {x['title']}", 10, bold=True, color=_COLOR[x["status"]])
        pdf.text("Requirement: " + x["requirement"], 8.5, indent=10)
        pdf.text("Evidence: " + x["evidence"], 8.5, indent=10, gap=4)
    return pdf.render()
