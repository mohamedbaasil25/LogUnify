"""CERT-In incident report (DRAFT) builder, aligned to CERT-In's published material.

Sources (read in full when this module was written):
  * Directions No. 20(3)/2022-CERT-In, 28 Apr 2022: para (ii) report Annexure I incidents within 6 hours of noticing
    them (email / phone / fax below); para (iii) designated Point of Contact (Annexure II format); para (iv) logs
    must be provided to CERT-In along with the report of an incident; Annexure I = the 20 incident types.
  * Incident Reporting Form, https://www.cert-in.org.in/PDF/certinirform.pdf: one page of fields. It says it is
    general guidance, that filling it is NOT mandatory, and that the information may be given in any readable form.
  * FAQ (May 2022): Q30 report "to the extent available" within 6 hours and complete later; Q13 the entity that
    notices the incident must report (not transferable); Q32 data-confidentiality duties are unchanged.

So this module does not claim "mandatory fields": it fills every field the official form asks for that the platform
can know, lists the ones a human must supply, and never files anything with CERT-In by itself.
"""
import fnmatch
import re
import textwrap
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ..intel.netutil import is_external, is_internal
from .redact import clean, redact
from .rules import get

IST = timezone(timedelta(hours=5, minutes=30), "IST")      # fixed offset: no DST, and no tzdata dependency on Windows
DEADLINE_HOURS = 6
FORM_URL = "https://www.cert-in.org.in/PDF/certinirform.pdf"
CONTACT = {"email": "incident@cert-in.org.in", "phone": "1800-11-4949", "fax": "1800-11-6969"}

# Annexure I of the Directions: types of incidents that must be reported (controlled vocabulary).
ANNEXURE_I = {
    "i": "Targeted scanning/probing of critical networks/systems",
    "ii": "Compromise of critical systems/information",
    "iii": "Unauthorised access of IT systems/data",
    "iv": "Defacement of website or intrusion into a website and unauthorised changes such as inserting malicious code, links to external websites etc.",
    "v": "Malicious code attacks such as spreading of virus/worm/Trojan/Bots/Spyware/Ransomware/Cryptominers",
    "vi": "Attack on servers such as Database, Mail and DNS and network devices such as Routers",
    "vii": "Identity Theft, spoofing and phishing attacks",
    "viii": "Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks",
    "ix": "Attacks on Critical infrastructure, SCADA and operational technology systems and Wireless networks",
    "x": "Attacks on Application such as E-Governance, E-Commerce etc.",
    "xi": "Data Breach",
    "xii": "Data Leak",
    "xiii": "Attacks on Internet of Things (IoT) devices and associated systems, networks, software, servers",
    "xiv": "Attacks or incident affecting Digital Payment systems",
    "xv": "Attacks through Malicious mobile Apps",
    "xvi": "Fake mobile Apps",
    "xvii": "Unauthorised access to social media accounts",
    "xviii": "Attacks or malicious/suspicious activities affecting Cloud computing systems/servers/software/applications",
    "xix": "Attacks or malicious/suspicious activities affecting systems/servers/networks/software/applications related to Big Data, Block chain, virtual assets, virtual asset exchanges, custodian wallets, Robotics, 3D and 4D Printing, additive manufacturing, Drones",
    "xx": "Attacks or malicious/suspicious activities affecting systems/servers/software/applications related to Artificial Intelligence and Machine Learning",
}

# Suggested Annexure I types per MITRE technique (first = primary). A SUGGESTION for the analyst, never a decision.
TECHNIQUE_TYPES = {
    "T1078": ("iii", "ii"), "T1133": ("iii", "ii"), "T1110": ("iii",),
    "T1003": ("ii", "iii"), "T1021": ("ii", "iii"), "T1059": ("ii", "v"), "T1068": ("ii", "iii"),
    "T1098": ("ii", "iii"), "T1136": ("ii", "iii"), "T1070": ("ii",), "T1562": ("ii",),
    "T1190": ("x", "vi", "ii"),
    "T1071": ("v", "ii"), "T1486": ("v", "ii"), "T1490": ("v", "ii"), "T1485": ("v", "ii"),
    "T1041": ("xi", "xii"), "T1048": ("xi", "xii"), "T1567": ("xi", "xii"),
}

# CERT-In FAQ Q30: Annexure I incidents meeting these criteria must be reported within the 6 hours (paraphrased).
REPORTABILITY_CRITERIA = (
    "Severe incident (e.g. DoS/DDoS, intrusion, spread of malware including ransomware) on any part of the public "
    "information infrastructure, including backbone network infrastructure",
    "Data breach or data leak",
    "Large-scale or most frequent incidents, e.g. intrusion into computer resources or websites",
    "Incident impacting the safety of human beings",
)

ANALYST_FIELDS = {       # what an analyst may supply (API validates against this set)
    "i_am", "affected_entity", "incident_type_ids", "incident_type_other", "critical", "critical_details",
    "domain_url", "ip_address", "operating_system", "make_model_cloud", "affected_application", "location",
    "network_isp", "description_addendum", "impact", "actions_taken", "ongoing",
}
I_AM_CHOICES = ("the affected entity", "reporting incident affecting other entity")


@dataclass(frozen=True)
class OrgProfile:
    name: str = ""
    address: str = ""
    location: str = ""                 # default location of affected systems (City, Region, Country)
    isp: str = ""
    poc_name: str = ""
    poc_designation: str = ""
    poc_email: str = ""
    poc_mobile: str = ""
    poc_phone: str = ""
    poc_fax: str = ""
    critical_assets: tuple[str, ...] = ()      # fnmatch patterns over host name / IP that count as mission-critical


# ------------------------------------------------------------------------------------------------ time helpers
def ts_pair(epoch: float | None) -> dict | None:
    if epoch is None:
        return None
    dt = datetime.fromtimestamp(epoch, timezone.utc)
    return {"utc": dt.isoformat(timespec="seconds"), "ist": dt.astimezone(IST).strftime("%d/%m/%Y %H:%M")}


def parse_ts(value) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def fmt_remaining(seconds: float) -> str:
    sign, s = ("-" if seconds < 0 else ""), int(abs(seconds))
    return f"{sign}{s // 3600}h{(s % 3600) // 60:02d}m"


# ------------------------------------------------------------------------------------------------ asset logic
def _first(v):
    return v[0] if isinstance(v, list) and v else v


def affected_asset(doc: dict) -> dict:
    """Which side of the event is the affected system and which is the remote party.

    Internal address first (destination of an inbound attack, source of outbound exfiltration); a public server
    falls back to the destination. Derived from log fields: the report flags it for the analyst to confirm.
    """
    src, dst = get(doc, "source", "ip"), get(doc, "destination", "ip")
    host_ip = _first(get(doc, "host", "ip"))
    internal = [ip for ip in (dst, src, host_ip) if ip and is_internal(ip)]
    if internal:
        ip = internal[0]
    elif src and dst and is_external(src) and is_external(dst):
        ip = dst                      # remote host hitting a public-facing server: the destination is the victim
    else:
        ip = None                     # a lone external address is the REMOTE party (attacker / exfiltration target)
    remote = next((x for x in (src, dst) if x and x != ip and is_external(x)), None)
    return {"ip": ip, "host": get(doc, "host", "name"), "remote_ip": remote}


def asset_key(doc: dict) -> str:
    """Grouping key for one incident: the affected asset, else the remote party (so different remotes stay separate)."""
    a = affected_asset(doc)
    return str(a["host"] or a["ip"] or a["remote_ip"] or get(doc, "source", "ip") or get(doc, "destination", "ip") or "unknown")


def suggest_types(technique_id: str) -> tuple[str, ...]:
    return TECHNIQUE_TYPES.get(technique_id.split(".")[0], ())


def _is_critical_asset(asset: dict, org: OrgProfile) -> bool:
    names = [str(x) for x in (asset["host"], asset["ip"]) if x]
    return any(fnmatch.fnmatch(n.lower(), pat.lower()) for n in names for pat in org.critical_assets)


# ------------------------------------------------------------------------------------------------ report
def build_report(alert, org: OrgProfile, *, now: float, evidence_ref: dict | None = None) -> dict:
    """Form-aligned DRAFT report for `alert` (duck-typed: see manager.Alert)."""
    doc, trig, an = alert.doc, alert.trigger, (alert.analyst or {})
    asset = affected_asset(doc)
    warnings: list[str] = []
    tid = trig["technique_id"]

    # ---- incident type (Annexure I)
    ids = [i for i in (an.get("incident_type_ids") or []) if i in ANNEXURE_I] or list(suggest_types(tid))
    analyst_types = bool(an.get("incident_type_ids"))
    incident_type = {
        "annexure_i": [{"id": i, "label": ANNEXURE_I[i]} for i in ids],
        "origin": "analyst" if analyst_types else f"suggested from MITRE {tid} {trig['technique_name']}; analyst must confirm",
        "other_specify": an.get("incident_type_other"),
    }

    # ---- affected system
    os_name = get(doc, "host", "os", "full") or get(doc, "host", "os", "name")
    app_name = get(doc, "service", "name") or get(doc, "process", "name")
    domain_url = get(doc, "url", "original") or get(doc, "url", "domain") or get(doc, "destination", "domain")
    system = {
        "domain_url": an.get("domain_url") or domain_url,
        "ip_address": an.get("ip_address") or asset["ip"],
        "host_name": asset["host"],
        "operating_system": an.get("operating_system") or os_name,
        "make_model_cloud": an.get("make_model_cloud"),
        "application": an.get("affected_application") or app_name,
        "location": an.get("location") or org.location or None,
        "network_isp": an.get("network_isp") or org.isp or None,
    }
    if "critical" in an:
        crit = {"answer": "Yes" if an["critical"] else "No", "details": an.get("critical_details"), "origin": "analyst"}
    elif _is_critical_asset(asset, org):
        crit = {"answer": "Yes", "details": "Matches the configured mission-critical asset list", "origin": "configuration"}
    else:
        crit = {"answer": None, "details": an.get("critical_details"), "origin": None}

    # ---- times
    occurred = parse_ts(doc.get("@timestamp"))
    raw = str(get(doc, "event", "original") or "")
    if re.match(r"^<\d{1,3}>[A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d", raw):
        warnings.append("The source log's timestamp has no year or timezone (RFC 3164 syslog); it was interpreted as UTC "
                        "of the current year. Verify the occurrence time against the source system.")
    ingested = get(doc, "event", "ingested")
    if ingested and doc.get("@timestamp") == ingested:
        warnings.append("The source log carried no timestamp, so the occurrence time shown is the time LogUnify ingested it. "
                        "Establish the real occurrence time from the source system.")

    # ---- remote party, enrichment (never present demo data to a regulator)
    remote = {"ip": asset["remote_ip"], "port": get(doc, "source", "port") if asset["remote_ip"] == get(doc, "source", "ip") else None,
              "domain": get(doc, "source", "domain")}
    geo = get(doc, "source", "geo")
    if geo and get(doc, "logunify", "geoip") == "mock":
        warnings.append("GeoIP in this deployment is demo data; country information was omitted.")
    elif geo and asset["remote_ip"]:
        remote["geo"] = {"country_iso_code": geo.get("country_iso_code"), "country_name": geo.get("country_name")}
    ind = get(doc, "threat", "indicator")
    if isinstance(ind, dict) and ind.get("provider"):
        if str(ind["provider"]).startswith("mock"):
            warnings.append("A threat-intelligence match came from the demo feed and was omitted.")
        else:
            remote["threat_intel"] = {k: ind.get(k) for k in ("provider", "type", "confidence", "description", "reference")}
    if trig["basis"] != "default":
        warnings.append(f"The MITRE technique was assigned by the heuristic rule '{trig['basis'].split(':', 1)[-1]}', "
                        "not by a validated detection: confirm it against the evidence.")

    excerpt = redact(get(doc, "event", "original") or doc.get("message"), 400)
    where = system["host_name"] or system["ip_address"] or "an unidentified asset"
    description = (
        f"Automated detection by LogUnify: an event on {where} scored {trig['score']:.2f} on the anomaly model "
        f"(alert threshold {trig['threshold']:.2f}) and matches MITRE ATT&CK {tid} {trig['technique_name']}. "
        + (f"Remote party {asset['remote_ip']}. " if asset["remote_ip"] else "")
        + (f"Log excerpt (redacted): {excerpt}" if excerpt else "")).strip()
    if an.get("description_addendum"):
        description += f"\n\nAnalyst addendum: {an['description_addendum']}"

    open_clock = alert.status in ("open", "acknowledged")
    remaining = alert.due_at - now
    # Drain3 keeps the literal values of a first-seen message in its template, so a template can carry a secret too.
    template_text = redact(get(doc, "logunify", "template", "text"), 300) or None
    report = {
        "form": {"name": "CERT-In Incident Reporting Form", "url": FORM_URL,
                 "note": "The form is general guidance and not mandatory to fill; CERT-In accepts the same information in "
                         "any readable form. This draft follows its structure."},
        "reference": alert.id,
        "status": "DRAFT: an analyst must verify and complete this before submission to CERT-In",
        "deadline": {
            "rule": "Report within 6 hours of noticing the incident (Directions 28 Apr 2022, para (ii); FAQ Q24)",
            "clock_started_at": ts_pair(alert.created_at),
            "report_due_at": ts_pair(alert.due_at),
            "seconds_remaining": int(remaining) if open_clock else None,
            "overdue": bool(open_clock and remaining <= 0),
            "submit_via": dict(CONTACT),
            "incomplete_information": "Submit what is available within 6 hours and add the rest later (FAQ Q30).",
        },
        "i_am": an.get("i_am") if an.get("i_am") in I_AM_CHOICES else I_AM_CHOICES[0],
        "reporter": {
            "name_role": ", ".join(x for x in (org.poc_name, org.poc_designation) if x) or None,
            "type": "Organization", "organization_name": org.name or None,
            "contact_no": org.poc_mobile or org.poc_phone or None, "email": org.poc_email or None,
            "address": org.address or None, "office_phone": org.poc_phone or None, "office_fax": org.poc_fax or None,
        },
        "affected_entity": an.get("affected_entity") or (org.name or None),
        "incident_type": incident_type,
        "affected_system_critical": crit,
        "affected_system": system,
        "description": description,
        "occurrence": ts_pair(occurred),
        "detection": ts_pair(alert.created_at),
        "additional_information": {
            "detection": {
                "method": "LogUnify: Drain3 template mining, Isolation Forest anomaly scoring, heuristic MITRE ATT&CK mapping",
                "anomaly_score": round(trig["score"], 4), "alert_threshold": trig["threshold"],
                "mitre": {"id": tid, "name": trig["technique_name"], "tactic": trig["tactic"], "basis": trig["basis"]},
                "log_template": template_text,
            },
            "remote_party": remote,
            "user": get(doc, "user", "name"),
            "process": get(doc, "process", "name"),
            "event": {k: get(doc, "event", k) for k in ("action", "category", "outcome", "dataset")},
            "log_source": {"format": get(doc, "logunify", "source_format"),
                           "observer": " ".join(x for x in (get(doc, "observer", "vendor"), get(doc, "observer", "product")) if x) or None},
            "occurrences": {"count": alert.occurrences, "first_seen": ts_pair(alert.created_at), "last_seen": ts_pair(alert.last_seen_at)},
            "evidence": {
                "event_id": get(doc, "event", "id"),
                "record_sha256": (alert.evidence or {}).get("record_sha256"),
                "integrity_reference": evidence_ref,
                "log_excerpt_redacted": excerpt,
                "full_record": f"GET /api/v1/alerts/{alert.id}/evidence (authenticated; unredacted)",
                "note": "Directions para (iv): logs must be provided to CERT-In along with the incident report.",
            },
            "analyst_notes": {"impact": an.get("impact"), "actions_taken": an.get("actions_taken"), "ongoing": an.get("ongoing")},
            "reportability_check": {
                "source": "CERT-In FAQ Q30", "criteria": list(REPORTABILITY_CRITERIA),
                "decision": "Analyst decides. If the incident is not reportable, close the alert as 'not_reportable' with the reason.",
            },
        },
        "data_quality_warnings": warnings,
    }
    report["completeness"] = _completeness(report, org, an)
    return report


def _blank(v) -> bool:
    return v is None or v == "" or v == []


def _completeness(r: dict, org: OrgProfile, an: dict) -> dict:
    s, n = r["affected_system"], r["additional_information"]["analyst_notes"]
    analyst = [(p, l) for p, l, v in (
        ("affected_system_critical.answer", "Is the affected system/network critical to the organization's mission? (Yes/No)", r["affected_system_critical"]["answer"]),
        ("affected_system.ip_address", "IP Address", s["ip_address"]),
        ("affected_system.operating_system", "Operating System", s["operating_system"]),
        ("affected_system.make_model_cloud", "Make/Model/Cloud details", s["make_model_cloud"]),
        ("affected_system.location", "Location of affected system (City, Region & Country)", s["location"]),
        ("affected_system.network_isp", "Network and name of ISP", s["network_isp"]),
        ("additional_information.analyst_notes.impact", "Impact (recommended)", n["impact"]),
        ("additional_information.analyst_notes.actions_taken", "Actions taken (recommended)", n["actions_taken"]),
    ) if _blank(v)]
    if not r["incident_type"]["annexure_i"] and not r["incident_type"]["other_specify"]:
        analyst.insert(0, ("incident_type.annexure_i", "Incident type (choose from Annexure I, or specify Other)"))
    config = [(p, l) for p, l, v in (
        ("reporter.name_role", "Reporter name & role: set LOGUNIFY_POC_NAME / LOGUNIFY_POC_DESIGNATION", r["reporter"]["name_role"]),
        ("reporter.organization_name", "Organization name: set LOGUNIFY_ORG_NAME", r["reporter"]["organization_name"]),
        ("reporter.contact_no", "Contact No.: set LOGUNIFY_POC_MOBILE or LOGUNIFY_POC_PHONE", r["reporter"]["contact_no"]),
        ("reporter.email", "Email: set LOGUNIFY_POC_EMAIL", r["reporter"]["email"]),
        ("reporter.address", "Address: set LOGUNIFY_ORG_ADDRESS", r["reporter"]["address"]),
    ) if _blank(v)]
    to_confirm = [{"field": "incident_type", "label": "Annexure I incident type (suggested from the MITRE technique)"}] \
        if r["incident_type"]["origin"] != "analyst" else []
    to_confirm.append({"field": "affected_system", "label": "Affected system / remote party (derived from log fields)"})
    for key, cfg_value, setting in (("location", org.location, "LOGUNIFY_ORG_LOCATION"), ("network_isp", org.isp, "LOGUNIFY_ORG_ISP")):
        if cfg_value and not an.get(key) and s[key] == cfg_value:          # a default, not knowledge about THIS system
            to_confirm.append({"field": f"affected_system.{key}", "label": f"{key.replace('_', ' ').title()}: defaulted from {setting}; confirm it applies to this system"})
    return {
        "needs_analyst": [{"field": p, "label": l} for p, l in analyst],
        "needs_configuration": [{"field": p, "label": l} for p, l in config],
        "to_confirm": to_confirm,
        "note": "Missing items do not stop the clock: report what is available within 6 hours and complete the rest "
                "afterwards (CERT-In FAQ Q30).",
    }


# ------------------------------------------------------------------------------------------------ rendering
def _v(x, marker: str = "[ANALYST]") -> str:
    return marker if _blank(x) else str(x)


def subject_line(kind: str, report: dict, label: str = "") -> str:
    tid = report["additional_information"]["detection"]["mitre"]["id"]
    name = report["additional_information"]["detection"]["mitre"]["name"]
    s = report["affected_system"]
    where = s["host_name"] or s["ip_address"]
    if not where:
        remote = report["additional_information"]["remote_party"]["ip"]
        where = f"unidentified asset (remote {remote})" if remote else "unidentified asset"
    due = report["deadline"]["report_due_at"]["ist"]
    prefix = {"incident.detected": "[CRITICAL][CERT-In 6h]", "incident.reminder": f"[REMINDER {label}]",
              "incident.overdue": "[OVERDUE][CERT-In 6h]"}.get(kind, "[ALERT]")
    return clean(f"{prefix} {tid} {name} on {where}: report due {due} IST ({report['reference']})")[:180]


def render_text(report: dict, kind: str = "incident.detected", label: str = "") -> str:
    d, r, t, s = report["deadline"], report["reporter"], report["incident_type"], report["affected_system"]
    a, det = report["additional_information"], report["additional_information"]["detection"]
    crit = report["affected_system_critical"]
    banner = {"incident.reminder": f"REMINDER ({label}): CERT-In 6-HOUR REPORTING CLOCK IS STILL RUNNING",
              "incident.overdue": "OVERDUE: THE CERT-In 6-HOUR REPORTING DEADLINE HAS PASSED: REPORT NOW",
              }.get(kind, "CRITICAL SECURITY INCIDENT: CERT-In 6-HOUR REPORTING CLOCK IS RUNNING")
    w = lambda text, ind="    ": textwrap.fill(str(text), 96, initial_indent=ind, subsequent_indent=ind)  # noqa: E731
    lines = [
        f"*** {banner} ***", "",
        f"Alert ID        : {report['reference']}",
        f"Clock started   : {d['clock_started_at']['ist']} IST (noticed by LogUnify automated detection)",
        f"REPORT DUE BY   : {d['report_due_at']['ist']} IST   (6 hours from noticing: Directions 28 Apr 2022, para (ii))",
        f"Submit to       : {d['submit_via']['email']}  |  phone {d['submit_via']['phone']}  |  fax {d['submit_via']['fax']}",
        "",
        "This is an automatically generated DRAFT for a human to verify. Submit what is available within 6 hours",
        "and complete the rest later (CERT-In FAQ Q30). LogUnify never files with CERT-In by itself.", "",
        "=== Incident Reporting Form (CERT-In form structure) ===",
        f"I am                          : {report['i_am']}",
        f"Reporter (name & role/title)  : {_v(r['name_role'], '[CONFIG]')}  ({r['type']})",
        f"Organization name             : {_v(r['organization_name'], '[CONFIG]')}",
        f"Contact no. / Email           : {_v(r['contact_no'], '[CONFIG]')} / {_v(r['email'], '[CONFIG]')}",
        f"Address                       : {_v(r['address'], '[CONFIG]')}",
        f"Affected entity               : {_v(report['affected_entity'], '[CONFIG]')}",
        "Incident type (Annexure I)    : " + ("; ".join(f"[{x['id']}] {x['label']}" for x in t["annexure_i"]) or "[ANALYST]"),
        f"   ({t['origin']})" + (f"  Other: {t['other_specify']}" if t["other_specify"] else ""),
        f"Critical to mission?          : {_v(crit['answer'])}" + (f"  ({crit['details']})" if crit["details"] else ""),
        f"Domain/URL                    : {_v(s['domain_url'], 'n/a')}",
        f"IP address                    : {_v(s['ip_address'])}   (host: {_v(s['host_name'], 'n/a')})",
        f"Operating system              : {_v(s['operating_system'])}",
        f"Make/Model/Cloud details      : {_v(s['make_model_cloud'])}",
        f"Affected application          : {_v(s['application'], 'n/a')}",
        f"Location (City, Region, Ctry) : {_v(s['location'])}",
        f"Network and name of ISP       : {_v(s['network_isp'])}",
        f"Occurrence date & time (IST)  : {report['occurrence']['ist'] if report['occurrence'] else '[ANALYST]'}",
        f"Detection date & time (IST)   : {report['detection']['ist']}",
        "Brief description of incident :", w(report["description"]), "",
        "=== Detection details ===",
        f"Anomaly score   : {det['anomaly_score']:.2f} (alert threshold {det['alert_threshold']:.2f})",
        f"MITRE ATT&CK    : {det['mitre']['id']} {det['mitre']['name']} ({det['mitre']['tactic']}); basis {det['mitre']['basis']}",
        f"Log template    : {_v(det['log_template'], 'n/a')}",
        f"Remote party    : {_v(a['remote_party']['ip'], 'n/a')}" + (f"  (threat intel: {a['remote_party']['threat_intel']['provider']})"
                                                                     if a["remote_party"].get("threat_intel") else ""),
        f"User / process  : {_v(a['user'], 'n/a')} / {_v(a['process'], 'n/a')}",
        f"Occurrences     : {a['occurrences']['count']} (first {a['occurrences']['first_seen']['ist']} IST, last {a['occurrences']['last_seen']['ist']} IST)", "",
        "=== Evidence (Directions para (iv): logs accompany the report) ===",
        f"Event id        : {_v(a['evidence']['event_id'], 'n/a')}",
        f"Record SHA-256  : {_v(a['evidence']['record_sha256'], 'n/a')}",
        f"Integrity anchor: {a['evidence']['integrity_reference'] or 'pending (record not yet in a sealed Merkle batch)'}",
        f"Full record     : {a['evidence']['full_record']}", "",
        "=== Reportability check (CERT-In FAQ Q30): analyst decides ===",
        *[textwrap.fill(c, 96, initial_indent="  [ ] ", subsequent_indent="      ") for c in a["reportability_check"]["criteria"]],
        "  If none applies, close the alert as 'not_reportable' and record why.", "",
    ]
    c = report["completeness"]
    if c["needs_analyst"] or c["needs_configuration"]:
        lines.append("=== Still missing (does not stop the clock) ===")
        lines += [f"  [ANALYST] {x['label']}" for x in c["needs_analyst"]]
        lines += [f"  [CONFIG]  {x['label']}" for x in c["needs_configuration"]]
        lines.append("")
    if report["data_quality_warnings"]:
        lines.append("=== Data-quality warnings ===")
        lines += [w(x, "  ! ") for x in report["data_quality_warnings"]]
    return "\n".join(lines).rstrip() + "\n"
