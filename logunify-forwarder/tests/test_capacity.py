import json
import shutil
from pathlib import Path

import pytest

from retention.capacity import plan, tiers_from_policy

ROOT = Path(__file__).resolve().parent.parent


def test_tiers_are_read_from_the_ilm_policy():
    t = tiers_from_policy(ROOT)
    assert t["retention_days"] == 180 and t["hot"]["days"] == 7 and t["warm"]["days"] == 23
    assert t["cold"]["days"] == 151 and t["cold"]["replicas"] == 0            # 180-30 plus the 1-day rollover span
    assert t["hot"]["replicas"] == t["warm"]["replicas"] == 1


def test_costs_scale_linearly_and_tiering_saves_money():
    a, b = plan(100), plan(200)
    assert abs(b["elasticsearch_totals"]["tier_usd_month"] / a["elasticsearch_totals"]["tier_usd_month"] - 2) < 0.01
    assert a["tiering_savings_pct"] > 50
    assert a["baseline_all_hot"]["usd_month"] > a["elasticsearch_totals"]["usd_month_with_snapshots"]


def test_buffer_and_splunk_sizing_scale_with_load_and_outage():
    p1, p2 = plan(100, outage_hours=1), plan(100, outage_hours=4)
    assert p2["forwarder"]["min_disk_buffer_bytes_per_sink"] == 4 * p1["forwarder"]["min_disk_buffer_bytes_per_sink"]
    assert plan(200)["splunk"]["maxTotalDataSizeMB_needed"] > plan(100)["splunk"]["maxTotalDataSizeMB_needed"]
    assert plan(100, doc_bytes=1770)["inputs"]["raw_gb_per_day"] == pytest.approx(2 * plan(100, doc_bytes=885)["inputs"]["raw_gb_per_day"], rel=0.02)   # values are rounded to 0.1


def test_model_follows_the_policy_when_it_changes(tmp_path):
    shutil.copytree(ROOT / "elasticsearch", tmp_path / "elasticsearch")
    p = tmp_path / "elasticsearch" / "ilm-logunify-cert-in.json"
    d = json.loads(p.read_text())
    d["policy"]["phases"]["cold"]["min_age"] = "60d"                          # shorter cold, longer warm
    p.write_text(json.dumps(d))
    t = tiers_from_policy(tmp_path)
    assert t["warm"]["days"] == 53 and t["cold"]["days"] == 121
    assert plan(100, root=tmp_path)["elasticsearch_totals"]["tier_usd_month"] > plan(100)["elasticsearch_totals"]["tier_usd_month"]
