"""Evidence that the 180-day log-retention rule is configured, and (when reachable) actually applied.

Two evidence levels, always reported separately so nobody mistakes one for the other:
  static  the shipped policy files (Elasticsearch ILM + SLM, Splunk indexes.conf, Wazuh ISM + snapshot policy), parsed and
          linted with logunify-forwarder/retention/policy_lint.py. Proves the INTENDED policy, not what a cluster runs.
  live    read-only queries to a running cluster (Elasticsearch `_ilm/policy` and `_ilm/explain`). Proves the policy the
          cluster holds and that every LogUnify index is managed by it. Needs LOGUNIFY_ES_URL; Splunk/Wazuh have no live
          probe yet and stay static-only.
Neither proves that a deletion never happened early (that needs the cluster's own audit trail) or that snapshots restore.
"""
import sys
from pathlib import Path

import httpx

from .durations import to_days

REQUIRED_DAYS = 180
ES_POLICY = "logunify-cert-in"


def _lint_module(root: Path):
    sys.path.insert(0, str(root))
    try:
        from retention import policy_lint
        return policy_lint
    finally:
        sys.path.remove(str(root))


def static_proof(forwarder_root: str) -> dict:
    root = Path(forwarder_root)
    if not (root / "retention" / "policy_lint.py").is_file():
        return {"available": False, "reason": f"forwarder policy files not found at {root} (set LOGUNIFY_FORWARDER_ROOT)",
                "layers": [], "findings": [], "passed": None}
    pl = _lint_module(root)
    layers = []

    def add(layer, setting, d):
        layers.append({"layer": layer, "setting": setting, "days": round(d, 2), "required_days": REQUIRED_DAYS,
                       "ok": d >= REQUIRED_DAYS})

    es = root / "elasticsearch"
    for f in ("ilm-logunify-cert-in.json", "ilm-logunify-cert-in-searchable.json"):
        add("Elasticsearch ILM", f"{f}: delete.min_age", pl.days(pl._load(es / f)["policy"]["phases"]["delete"]["min_age"]))
    add("Elasticsearch SLM", "snapshot retention.expire_after",
        pl.days(pl._load(es / "slm-logunify-daily.json")["retention"]["expire_after"]))
    idx = pl.parse_conf(root / "splunk" / "indexes.conf").get("logunify", {})
    add("Splunk", "frozenTimePeriodInSecs", int(idx.get("frozenTimePeriodInSecs", 0)) / 86400)
    ism = pl._load(root / "wazuh" / "ism-policy-wazuh-cert-in.json")["policy"]
    states = {s["name"]: s for s in ism["states"]}
    cur, seen, last = ism["default_state"], set(), 0.0
    while cur and cur not in seen:
        seen.add(cur)
        tr = states[cur]["transitions"]
        if tr:
            last = pl.days(tr[0]["conditions"]["min_index_age"])
        cur = tr[0]["state_name"] if tr else None
    add("Wazuh/OpenSearch ISM", "delete state min_index_age (age from creation; +1 day index span)", last - 1)
    add("Wazuh snapshots", "snapshot-management deletion.max_age",
        pl.days(pl._load(root / "wazuh" / "sm-policy-wazuh-daily.json")["deletion"]["condition"]["max_age"]))
    findings = pl.lint_all(root)
    errors = [str(x) for x in findings if x.level == "ERROR"]
    return {"available": True, "layers": layers, "findings": [str(x) for x in findings], "lint_errors": len(errors),
            "passed": not errors and all(x["ok"] for x in layers),
            "basis": "static analysis of policy files in the repository; not a query of a running cluster"}


def live_elasticsearch(url: str, api_key: str | None, verify_ssl: bool = True, timeout: float = 10.0,
                       transport: httpx.BaseTransport | None = None) -> dict:
    """Read-only checks against a running Elasticsearch. Never raises: failures are returned as evidence."""
    if not url:
        return {"checked": False, "reason": "LOGUNIFY_ES_URL not set"}
    headers = {"Authorization": f"ApiKey {api_key}"} if api_key else {}
    out: dict = {"checked": True, "url": url.split("@")[-1], "checks": []}

    def check(name, ok, detail):
        out["checks"].append({"name": name, "ok": bool(ok), "detail": detail})

    try:
        with httpx.Client(base_url=url, headers=headers, verify=verify_ssl, timeout=timeout, transport=transport) as c:
            r = c.get(f"/_ilm/policy/{ES_POLICY}")
            if r.status_code != 200:
                check("ilm_policy_present", False, f"GET _ilm/policy/{ES_POLICY} -> HTTP {r.status_code}")
            else:
                phases = r.json()[ES_POLICY]["policy"]["phases"]
                delete = phases.get("delete", {}).get("min_age")
                d = to_days(delete) if delete else None
                check("ilm_policy_present", True, f"policy {ES_POLICY} exists")
                check("ilm_delete_min_age_ge_180d", d is not None and d >= REQUIRED_DAYS, f"delete.min_age = {delete!r}")
            r = c.get("/.ds-logs-logunify-*/_ilm/explain")
            if r.status_code != 200:
                check("indices_managed", False, f"GET _ilm/explain -> HTTP {r.status_code}")
            else:
                idxs = r.json().get("indices", {})
                unmanaged = [n for n, v in idxs.items() if not v.get("managed")]
                wrong = [n for n, v in idxs.items() if v.get("managed") and v.get("policy") != ES_POLICY]
                failed = [n for n, v in idxs.items() if v.get("step") == "ERROR" or v.get("failed_step")]
                check("indices_found", bool(idxs), f"{len(idxs)} backing index(es) matched .ds-logs-logunify-*")
                check("all_indices_managed", not unmanaged and not wrong,
                      f"unmanaged={unmanaged[:5]} other_policy={wrong[:5]}")
                check("no_ilm_errors", not failed, f"indices in ILM error: {failed[:5]}")
                ages = [v["age"] for v in idxs.values() if v.get("age")]
                out["oldest_index_age"] = max(ages, key=lambda a: to_days(a)) if ages else None
    except Exception as e:                                        # unreachable cluster, TLS error, bad JSON ...
        check("cluster_reachable", False, f"{type(e).__name__}: {str(e)[:200]}")
    out["passed"] = all(c["ok"] for c in out["checks"])
    return out
