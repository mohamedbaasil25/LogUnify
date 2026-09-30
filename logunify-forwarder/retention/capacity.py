"""Tiering capacity + cost model for the 180-day CERT-In retention policy.

    python retention/capacity.py --eps 500                     # table
    python retention/capacity.py --eps 500 --json              # machine-readable
    python retention/capacity.py --eps 2000 --outage-hours 8   # also sizes the forwarder's disk buffers

Tier boundaries and replica counts are READ FROM the ILM policy/template in this repo, so the model cannot drift from
what is deployed. Every other number is an ASSUMPTION you must replace:
  * doc-bytes: 885 B = average ECS document measured on LogUnify mock traffic (real logs are usually larger; measure yours)
  * expansion: index size / raw JSON size (best_compression, before/after forcemerge): rough industry rule of thumb
  * prices: PLACEHOLDERS, not quotes. Use your contract rates.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from retention.policy_lint import days  # noqa: E402

DEFAULTS = {
    "doc_bytes": 885,
    "expansion": {"hot": 0.80, "warm": 0.60, "cold": 0.60},     # index bytes per raw JSON byte
    "price_gb_month": {"hot": 0.115, "warm": 0.050, "cold": 0.030, "object": 0.020},   # PLACEHOLDER USD
    "snapshot_ratio": 0.50,                                     # object-store bytes per primary index byte (compressed, deduped)
    "splunk_disk_ratio": 0.50,                                  # Splunk on-disk bytes per raw byte, one copy
    "buffer_overhead": 1.3,                                     # disk-buffer framing overhead
}


def tiers_from_policy(root: Path = ROOT) -> dict:
    ph = json.loads((root / "elasticsearch" / "ilm-logunify-cert-in.json").read_text())["policy"]["phases"]
    tmpl = json.loads((root / "elasticsearch" / "index-template-logunify.json").read_text())
    warm, cold, delete = (days(ph[p]["min_age"]) for p in ("warm", "cold", "delete"))
    base_replicas = int(tmpl["template"]["settings"]["index.number_of_replicas"])
    cold_replicas = int(ph["cold"]["actions"].get("allocate", {}).get("number_of_replicas", base_replicas))
    rollover = days(ph["hot"]["actions"]["rollover"]["max_age"])
    return {"hot": {"days": warm, "replicas": base_replicas},
            "warm": {"days": cold - warm, "replicas": base_replicas},
            "cold": {"days": delete - cold + rollover, "replicas": cold_replicas},     # +rollover span: newest index is deleted up to a day late
            "retention_days": delete}


def plan(eps: float, doc_bytes: int | None = None, outage_hours: float = 4.0, overrides: dict | None = None,
         root: Path = ROOT) -> dict:
    a = {**DEFAULTS, **(overrides or {})}
    doc = doc_bytes or a["doc_bytes"]
    t = tiers_from_policy(root)
    raw_gb_day = eps * 86400 * doc / 1e9
    rows, total_gb, total_cost, primary_gb = {}, 0.0, 0.0, 0.0
    for name in ("hot", "warm", "cold"):
        prim = raw_gb_day * a["expansion"][name] * t[name]["days"]
        stored = prim * (1 + t[name]["replicas"])
        cost = stored * a["price_gb_month"][name]
        rows[name] = {"days": round(t[name]["days"], 1), "replicas": t[name]["replicas"], "primary_gb": round(prim, 1),
                      "stored_gb": round(stored, 1), "usd_month": round(cost, 2)}
        total_gb += stored; total_cost += cost; primary_gb += prim
    snap_gb = primary_gb * a["snapshot_ratio"]
    snap_cost = snap_gb * a["price_gb_month"]["object"]
    all_hot_gb = raw_gb_day * a["expansion"]["hot"] * t["retention_days"] * (1 + t["hot"]["replicas"])
    all_hot_cost = all_hot_gb * a["price_gb_month"]["hot"]
    with_snap = total_cost + snap_cost
    splunk_mb = raw_gb_day * 1000 * a["splunk_disk_ratio"] * t["retention_days"] * 1.25        # 25% headroom so size caps never beat age
    buf_bytes = int(outage_hours * 3600 * eps * doc * a["buffer_overhead"])
    return {
        "inputs": {"eps": eps, "doc_bytes": doc, "raw_gb_per_day": round(raw_gb_day, 1), "retention_days": t["retention_days"]},
        "elasticsearch_tiers": rows,
        "elasticsearch_totals": {"tier_stored_gb": round(total_gb, 1), "tier_usd_month": round(total_cost, 2),
                                 "snapshot_gb": round(snap_gb, 1), "snapshot_usd_month": round(snap_cost, 2),
                                 "usd_month_with_snapshots": round(with_snap, 2)},
        "baseline_all_hot": {"stored_gb": round(all_hot_gb, 1), "usd_month": round(all_hot_cost, 2)},
        "tiering_savings_pct": round(100 * (1 - with_snap / all_hot_cost), 1) if all_hot_cost else 0.0,
        "splunk": {"maxTotalDataSizeMB_needed": int(splunk_mb)},
        "forwarder": {"outage_hours": outage_hours, "min_disk_buffer_bytes_per_sink": buf_bytes,
                      "configured_bytes": 10_737_418_240, "configured_covers_hours": round(10_737_418_240 / (3600 * eps * doc * a["buffer_overhead"]), 1)},
    }


def render(p: dict) -> str:
    i, t, e = p["inputs"], p["elasticsearch_tiers"], p["elasticsearch_totals"]
    out = [f"Ingest {i['eps']:,.0f} EPS x {i['doc_bytes']} B = {i['raw_gb_per_day']:,.1f} GB/day raw; retention {i['retention_days']:.0f} days",
           "", f"{'tier':6} {'days':>6} {'replicas':>8} {'primary GB':>11} {'stored GB':>11} {'USD/month':>10}"]
    for n, r in t.items():
        out.append(f"{n:6} {r['days']:>6} {r['replicas']:>8} {r['primary_gb']:>11,} {r['stored_gb']:>11,} {r['usd_month']:>10,}")
    out += ["", f"tiers total     {e['tier_stored_gb']:>10,} GB   ${e['tier_usd_month']:,}/month",
            f"+ snapshots     {e['snapshot_gb']:>10,} GB   ${e['snapshot_usd_month']:,}/month (object storage, India region, WORM)",
            f"= Elasticsearch  ${e['usd_month_with_snapshots']:,}/month   vs all-hot ${p['baseline_all_hot']['usd_month']:,}/month  ->  saves {p['tiering_savings_pct']}%",
            "", f"Splunk maxTotalDataSizeMB needed (one copy, +25% headroom): {p['splunk']['maxTotalDataSizeMB_needed']:,}",
            f"Forwarder disk buffer for a {p['forwarder']['outage_hours']:g} h destination outage: >= {p['forwarder']['min_disk_buffer_bytes_per_sink']:,} B per sink "
            f"(shipped config: {p['forwarder']['configured_bytes']:,} B = {p['forwarder']['configured_covers_hours']} h)",
            "", "Prices, expansion ratios and doc size are assumptions; see the module docstring."]
    return "\n".join(out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--eps", type=float, required=True, help="sustained events per second")
    ap.add_argument("--doc-bytes", type=int, help=f"average ECS doc size (default {DEFAULTS['doc_bytes']})")
    ap.add_argument("--outage-hours", type=float, default=4.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = plan(a.eps, a.doc_bytes, a.outage_hours)
    print(json.dumps(res, indent=2) if a.json else render(res))
