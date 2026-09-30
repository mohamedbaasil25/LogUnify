"""Offline policy-as-code linter: fails if any layer would violate the 180-day retention rule or a security baseline.

    python retention/policy_lint.py [--root .] [--required-mb 3000000]        (exit 1 on any ERROR)

Age semantics it encodes (getting these wrong silently shortens retention):
  * Elasticsearch ILM: phase min_age counts from ROLLOVER, so each document is >= min_age old when its index is deleted.
  * Splunk: a bucket freezes when its NEWEST event exceeds frozenTimePeriodInSecs (all events >= that old), but size caps
    (maxTotalDataSizeMB, volume caps) freeze earlier, so they must be large enough.
  * OpenSearch/Wazuh ISM: min_index_age counts from index CREATION; a daily index keeps receiving documents for up to a
    day, so the delete threshold must be retention + 1 day.
Everything here is static analysis of the files in this repo. It does not query a running cluster.
"""
import argparse
import json
import re
import sys
import xml.dom.minidom
from dataclasses import dataclass
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))      # `python retention/policy_lint.py` and `-m` both work

RETENTION_DAYS = 180
INDIA_REGIONS = {"ap-south-1", "ap-south-2", "centralindia", "southindia", "westindia", "asia-south1", "asia-south2"}
ES_PHASE_ACTIONS = {                                    # actions Elasticsearch ILM accepts per phase
    "hot": {"rollover", "set_priority", "unfollow", "readonly", "downsample", "searchable_snapshot", "forcemerge", "shrink"},
    "warm": {"set_priority", "unfollow", "readonly", "downsample", "allocate", "migrate", "shrink", "forcemerge"},
    "cold": {"set_priority", "unfollow", "readonly", "downsample", "searchable_snapshot", "allocate", "migrate"},
    "frozen": {"searchable_snapshot", "unfollow"},
    "delete": {"wait_for_snapshot", "delete"},
}
ES_ORDER = ["hot", "warm", "cold", "frozen", "delete"]
_UNIT_DAYS = {"d": 1.0, "h": 1 / 24, "m": 1 / 1440, "s": 1 / 86400, "ms": 1 / 86_400_000}


@dataclass
class Finding:
    level: str          # ERROR | WARN
    code: str
    msg: str

    def __str__(self):
        return f"{self.level:5} {self.code:5} {self.msg}"


def days(s: str) -> float:
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(d|h|m|s|ms)\s*", str(s))
    if not m:
        raise ValueError(f"bad duration {s!r}")
    return float(m.group(1)) * _UNIT_DAYS[m.group(2)]


def _load(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def parse_conf(p: Path) -> dict[str, dict[str, str]]:
    """Minimal Splunk .conf parser (stanzas, key = value, # comments; commented-out lines are ignored)."""
    out: dict[str, dict[str, str]] = {}
    cur = None
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #")[0].strip() if not raw.lstrip().startswith("#") else ""
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = out.setdefault(line[1:-1], {})
        elif "=" in line and cur is not None:
            k, v = line.split("=", 1)
            cur[k.strip()] = v.strip()
    return out


# ------------------------------------------------------------------------------------------------ Elasticsearch
def lint_elasticsearch(root: Path) -> list[Finding]:
    f: list[Finding] = []
    es = root / "elasticsearch"
    slm = _load(es / "slm-logunify-daily.json")
    tmpl = _load(es / "index-template-logunify.json")
    repo = _load(es / "snapshot-repository-s3.json")

    for name in ("ilm-logunify-cert-in.json", "ilm-logunify-cert-in-searchable.json"):
        pol = _load(es / name)["policy"]
        ph = pol["phases"]
        tag = name.replace(".json", "")
        for phase, body in ph.items():
            bad = set(body.get("actions", {})) - ES_PHASE_ACTIONS.get(phase, set())
            if phase not in ES_PHASE_ACTIONS:
                f.append(Finding("ERROR", "E4", f"{tag}: unknown phase '{phase}'"))
            elif bad:
                f.append(Finding("ERROR", "E4", f"{tag}: action(s) {sorted(bad)} are not valid in the {phase} phase"))
        d = ph.get("delete", {}).get("min_age")
        if d is None or days(d) < RETENTION_DAYS:
            f.append(Finding("ERROR", "E1", f"{tag}: delete.min_age {d!r} is below {RETENTION_DAYS} days"))
        ages = [(p, days(ph[p]["min_age"])) for p in ES_ORDER if p in ph and "min_age" in ph[p]]
        if any(b <= a for (_, a), (_, b) in zip(ages, ages[1:])):
            f.append(Finding("ERROR", "E3", f"{tag}: phase min_age values must strictly increase ({ages})"))
        ro = ph.get("hot", {}).get("actions", {}).get("rollover")
        if not ro:
            f.append(Finding("ERROR", "E2", f"{tag}: hot phase needs rollover (age is measured from rollover)"))
        elif "max_age" not in ro or days(ro["max_age"]) > 1:
            f.append(Finding("WARN", "E2", f"{tag}: rollover max_age should be <= 1d so over-retention stays <= 1 day"))
        acts = ph.get("delete", {}).get("actions", {})
        snap_before_delete = "wait_for_snapshot" in acts or any("searchable_snapshot" in ph.get(p, {}).get("actions", {}) for p in ("cold", "frozen"))
        if not snap_before_delete:
            f.append(Finding("ERROR", "E5", f"{tag}: nothing guarantees a snapshot exists before delete (wait_for_snapshot / searchable_snapshot)"))
        if "wait_for_snapshot" in acts and acts["wait_for_snapshot"].get("policy") != "logunify-daily":
            f.append(Finding("ERROR", "E5", f"{tag}: wait_for_snapshot must reference SLM policy logunify-daily"))
        if tag.endswith("searchable") and "searchable_snapshot" not in ph.get("cold", {}).get("actions", {}):
            f.append(Finding("WARN", "E5", f"{tag}: enterprise profile without a searchable_snapshot cold tier"))

    if days(slm["retention"]["expire_after"]) < RETENTION_DAYS:
        f.append(Finding("ERROR", "E6", "SLM retention.expire_after is below 180 days"))
    if "0 " not in slm["schedule"] and "*" not in slm["schedule"]:
        f.append(Finding("WARN", "E6", "SLM schedule looks non-daily"))
    if slm["repository"] != "logunify-archive":
        f.append(Finding("ERROR", "E6", "SLM repository must be logunify-archive"))
    if tmpl["template"]["settings"].get("index.lifecycle.name") != "logunify-cert-in":
        f.append(Finding("ERROR", "E7", "index template does not attach ILM policy logunify-cert-in"))
    if "data_stream" not in tmpl:
        f.append(Finding("ERROR", "E7", "index template must define a data stream (append-only, rollover-based age)"))
    if repo["settings"].get("region") not in INDIA_REGIONS:
        # Directions para (iv) says "within the Indian jurisdiction", but CERT-In's FAQ Q35 allows copies outside India as long as
        # they can be produced to CERT-In in reasonable time. A policy choice, not a violation: warn, let counsel decide.
        f.append(Finding("WARN", "E8", f"snapshot repository region {repo['settings'].get('region')!r} is outside India: "
                                       "allowed only if logs can be produced to CERT-In in reasonable time (FAQ Q35); Directions para (iv) says Indian jurisdiction"))
    if not repo["settings"].get("server_side_encryption"):
        f.append(Finding("ERROR", "E8", "snapshot repository must enable server-side encryption"))
    role = _load(es / "role-logunify-forwarder.json")
    privs = {p for i in role["indices"] for p in i["privileges"]}
    if privs - {"create_doc", "create", "auto_configure"}:
        f.append(Finding("ERROR", "E9", f"forwarder role is over-privileged: {sorted(privs)} (append-only expected)"))
    return f


# ------------------------------------------------------------------------------------------------ Splunk
def lint_splunk(root: Path, required_mb: int) -> list[Finding]:
    f: list[Finding] = []
    sp = root / "splunk"
    idx = parse_conf(sp / "indexes.conf").get("logunify", {})
    if int(idx.get("frozenTimePeriodInSecs", 0)) < RETENTION_DAYS * 86400:
        f.append(Finding("ERROR", "S1", f"frozenTimePeriodInSecs {idx.get('frozenTimePeriodInSecs')} is below {RETENTION_DAYS * 86400} (180 days)"))
    tot = int(idx.get("maxTotalDataSizeMB", 0))
    if tot < required_mb:
        f.append(Finding("ERROR", "S2", f"maxTotalDataSizeMB {tot} < {required_mb} needed for 180 days (size cap would freeze data early)"))
    if not (idx.get("coldToFrozenDir") or idx.get("coldToFrozenScript")):
        f.append(Finding("WARN", "S3", "no coldToFrozenDir/Script: frozen buckets are deleted irreversibly"))
    if int(idx.get("maxHotSpanSecs", 7_776_000)) > 86400:
        f.append(Finding("WARN", "S4", "maxHotSpanSecs > 1 day: freeze timing (over-retention) is coarser than a day"))
    vols = parse_conf(sp / "indexes.conf")
    cap = sum(int(v.get("maxVolumeDataSizeMB", 0)) for k, v in vols.items() if k.startswith("volume:") and "remote" not in k)
    if cap < required_mb:
        f.append(Finding("ERROR", "S2", f"sum of volume caps {cap} MB < {required_mb} MB required (volume cap freezes data early)"))
    hec = parse_conf(sp / "inputs.conf")
    tok = hec.get("http://logunify-forwarder", {})
    if tok.get("useACK") != "1":
        f.append(Finding("ERROR", "S5", "HEC token must set useACK = 1 (indexer acknowledgement)"))
    if tok.get("indexes") != "logunify":
        f.append(Finding("ERROR", "S5", "HEC token must be restricted to the logunify index (indexes = logunify)"))
    if hec.get("http", {}).get("enableSSL") != "1":
        f.append(Finding("ERROR", "S5", "HEC must enable SSL"))
    return f


# ------------------------------------------------------------------------------------------------ Wazuh
def lint_wazuh(root: Path) -> list[Finding]:
    f: list[Finding] = []
    wz = root / "wazuh"
    pol = _load(wz / "ism-policy-wazuh-cert-in.json")["policy"]
    states = {s["name"]: s for s in pol["states"]}
    chain, cur, seen = [], pol["default_state"], set()
    while cur and cur not in seen:                       # walk hot -> ... -> delete following the transitions
        seen.add(cur)
        tr = states[cur]["transitions"]
        chain.append((cur, days(tr[0]["conditions"]["min_index_age"]) if tr else None))
        cur = tr[0]["state_name"] if tr else None
    last = [a for _, a in chain if a is not None]
    if not last or last[-1] < RETENTION_DAYS + 1:
        f.append(Finding("ERROR", "W1", f"ISM delete threshold {last[-1] if last else None} d must be >= 181 (180 + 1-day index span; age counts from creation)"))
    if any(b <= a for a, b in zip(last, last[1:])):
        f.append(Finding("ERROR", "W2", f"ISM transition ages must strictly increase ({last})"))
    if "delete" not in states or not any("delete" in a for a in states["delete"]["actions"]):
        f.append(Finding("ERROR", "W2", "ISM policy has no delete state"))
    pats = {p for t in pol["ism_template"] for p in t["index_patterns"]}
    if not {"wazuh-alerts-*", "wazuh-archives-*"} <= pats:
        f.append(Finding("ERROR", "W3", "ISM template must cover wazuh-alerts-* AND wazuh-archives-* (CERT-In needs logs, not just alerts)"))
    sm = _load(wz / "sm-policy-wazuh-daily.json")
    if days(sm["deletion"]["condition"]["max_age"]) < RETENTION_DAYS:
        f.append(Finding("ERROR", "W4", "snapshot-management deletion.max_age is below 180 days"))
    doc = xml.dom.minidom.parse(str(wz / "rules" / "0800-logunify_rules.xml"))
    ids = [int(r.getAttribute("id")) for r in doc.getElementsByTagName("rule")]
    if len(ids) != len(set(ids)) or any(not 100000 <= i <= 120000 for i in ids):
        f.append(Finding("ERROR", "W5", f"rule ids must be unique and in the custom range 100000-120000: {ids}"))
    for r in doc.getElementsByTagName("field"):
        if r.getAttribute("type") == "pcre2":
            try:
                re.compile(r.firstChild.data)
            except re.error as e:
                f.append(Finding("ERROR", "W5", f"pcre2 pattern does not compile: {r.firstChild.data} ({e})"))
    if "<logall_json>yes</logall_json>" not in (wz / "ossec-manager-snippet.xml").read_text(encoding="utf-8"):
        f.append(Finding("ERROR", "W6", "manager snippet must enable logall_json (archives) for full-log retention"))
    return f


# ------------------------------------------------------------------------------------------------ forwarder
def lint_forwarder(root: Path) -> list[Finding]:
    f: list[Finding] = []
    d = root / "vector" / "vector.d"
    cfg: dict = {"sinks": {}, "transforms": {}, "sources": {}}
    for p in sorted(d.glob("*.yaml")):
        text = re.sub(r"\$\{[^}]*\}", "0", p.read_text(encoding="utf-8"))          # interpolation placeholders -> dummy scalars
        y = yaml.safe_load(text) or {}
        for k in ("sinks", "transforms", "sources"):
            cfg[k].update(y.get(k, {}) or {})
        if "acknowledgements" in y:
            cfg["acknowledgements"] = y["acknowledgements"]
    if not cfg.get("acknowledgements", {}).get("enabled"):
        f.append(Finding("ERROR", "V2", "global end-to-end acknowledgements must be enabled (offsets commit only after delivery)"))
    for name, s in cfg["sinks"].items():
        b = s.get("buffer", {})
        if b.get("type") != "disk" or b.get("when_full") != "block":
            f.append(Finding("ERROR", "V1", f"sink {name}: needs a disk buffer with when_full: block (no silent drops, survives restarts)"))
        if (s.get("tls") or {}).get("verify_certificate") is False or (s.get("tls") or {}).get("verify_hostname") is False:
            f.append(Finding("ERROR", "V4", f"sink {name}: TLS verification must not be disabled"))
    raw = (d / "20-sink-splunk-hec.yaml").read_text(encoding="utf-8")
    es_raw = (d / "10-sink-elasticsearch.yaml").read_text(encoding="utf-8")
    if not re.search(r"default_token:\s*['\"]?SECRET\[", raw):
        f.append(Finding("ERROR", "V3", "Splunk HEC token must come from SECRET[...], never a literal or environment value"))
    if not re.search(r"Authorization:\s*['\"]?SECRET\[", es_raw):
        f.append(Finding("ERROR", "V3", "Elasticsearch Authorization header must come from SECRET[...]"))
    spl, es = cfg["sinks"]["splunk_hec"], cfg["sinks"]["elasticsearch"]
    if not (spl.get("acknowledgements") or {}).get("indexer_acknowledgements_enabled"):
        f.append(Finding("ERROR", "V6", "Splunk sink must enable indexer acknowledgements"))
    if spl.get("index") != "logunify":
        f.append(Finding("ERROR", "V6", f"Splunk sink index {spl.get('index')!r} does not match the logunify index"))
    if es.get("mode") != "data_stream" or (es.get("bulk") or {}).get("action") != "create":
        f.append(Finding("ERROR", "V5", "Elasticsearch sink must use data_stream mode with bulk action create"))
    tmpl = _load(root / "elasticsearch" / "index-template-logunify.json")
    ds = es.get("data_stream") or {}
    stream = f"{ds.get('type')}-{ds.get('dataset')}-"
    if not any(pat.startswith(stream) for pat in tmpl["index_patterns"]):
        f.append(Finding("ERROR", "V5", f"data stream {stream}* is not covered by the index template patterns {tmpl['index_patterns']}"))
    if not str(es.get("id_key")):
        f.append(Finding("WARN", "V5", "Elasticsearch sink has no id_key: retries can create duplicates"))
    for text in (raw, es_raw):
        for m in re.finditer(r"(?i)^\s*(default_token|password|api_key|token):\s*([^\s#]+)", text, re.M):
            if not m.group(2).strip("'\"").startswith("SECRET["):
                f.append(Finding("ERROR", "V3", f"literal secret-looking value for {m.group(1)}"))
    return f


def lint_all(root: Path, required_mb: int = 3_000_000) -> list[Finding]:
    return lint_elasticsearch(root) + lint_splunk(root, required_mb) + lint_wazuh(root) + lint_forwarder(root)


def lint_sizing(root: Path, eps: float, outage_hours: float, doc_bytes: int | None) -> tuple[list[Finding], int]:
    """Check shipped capacity settings against a stated load (retention/capacity.py supplies the maths)."""
    from retention.capacity import plan
    p = plan(eps, doc_bytes, outage_hours, root=root)
    f: list[Finding] = []
    need = p["forwarder"]["min_disk_buffer_bytes_per_sink"]
    d = root / "vector" / "vector.d"
    for path in sorted(d.glob("*.yaml")):
        for m in re.finditer(r"max_size:\s*(\d+)", path.read_text(encoding="utf-8")):
            if int(m.group(1)) < need and "dlq" not in path.name:
                f.append(Finding("WARN", "V1", f"{path.name}: disk buffer {int(m.group(1)):,} B covers < {outage_hours:g} h of outage at {eps:g} EPS (need >= {need:,} B)"))
    return f, p["splunk"]["maxTotalDataSizeMB_needed"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--required-mb", type=int, default=3_000_000, help="storage Splunk needs for 180 days (retention/capacity.py)")
    ap.add_argument("--eps", type=float, help="sustained load; derives the Splunk size and forwarder buffer requirements")
    ap.add_argument("--outage-hours", type=float, default=4.0)
    ap.add_argument("--doc-bytes", type=int)
    a = ap.parse_args(argv)
    extra, required = [], a.required_mb
    if a.eps:
        extra, required = lint_sizing(Path(a.root), a.eps, a.outage_hours, a.doc_bytes)
    findings = lint_all(Path(a.root), required) + extra
    for x in findings:
        print(x)
    errors = sum(x.level == "ERROR" for x in findings)
    print(f"\n{errors} error(s), {len(findings) - errors} warning(s); CERT-In retention target {RETENTION_DAYS} days")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
