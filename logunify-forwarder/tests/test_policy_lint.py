"""The linter is only worth having if each rule demonstrably FIRES. Every case mutates a copy of the real configs."""
import json
import shutil
from pathlib import Path

import pytest

from retention.policy_lint import days, lint_all, lint_sizing, parse_conf

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def repo(tmp_path):
    for d in ("elasticsearch", "splunk", "wazuh", "vector"):
        shutil.copytree(ROOT / d, tmp_path / d, ignore=shutil.ignore_patterns("tests", "*.example"))
    return tmp_path


def edit_json(root: Path, rel: str, fn):
    p = root / rel
    data = json.loads(p.read_text(encoding="utf-8"))
    fn(data)
    p.write_text(json.dumps(data), encoding="utf-8")


def edit_text(root: Path, rel: str, old: str, new: str):
    p = root / rel
    s = p.read_text(encoding="utf-8")
    assert old in s, f"{old!r} not found in {rel}"
    p.write_text(s.replace(old, new), encoding="utf-8")


def codes(root: Path, level="ERROR", **kw):
    return {f.code for f in lint_all(root, **kw) if f.level == level}


def test_shipped_configuration_is_clean():
    assert lint_all(ROOT) == []


def test_duration_parsing():
    assert days("180d") == 180 and days("24h") == 1 and days("1440m") == 1 and days("500ms") < 1e-5
    with pytest.raises(ValueError):
        days("six months")


ILM = "elasticsearch/ilm-logunify-cert-in.json"


@pytest.mark.parametrize("mutation,code", [
    (lambda d: d["policy"]["phases"]["delete"].update(min_age="90d"), "E1"),
    (lambda d: d["policy"]["phases"]["delete"].update(min_age="179d"), "E1"),                       # one day short still fails
    (lambda d: d["policy"]["phases"]["delete"]["actions"].pop("wait_for_snapshot"), "E5"),
    (lambda d: d["policy"]["phases"]["hot"]["actions"].pop("rollover"), "E2"),
    (lambda d: d["policy"]["phases"]["cold"].update(min_age="5d"), "E3"),
    (lambda d: d["policy"]["phases"]["warm"]["actions"].update(searchable_snapshot={}), "E4"),
    (lambda d: d["policy"]["phases"]["cold"]["actions"].update(forcemerge={"max_num_segments": 1}), "E4"),
    (lambda d: d["policy"]["phases"].update(archive={"min_age": "100d", "actions": {}}), "E4"),
    (lambda d: d["policy"]["phases"]["delete"]["actions"]["wait_for_snapshot"].update(policy="other"), "E5"),
])
def test_elasticsearch_ilm_rules_fire(repo, mutation, code):
    edit_json(repo, ILM, mutation)
    assert code in codes(repo)


def test_long_rollover_span_warns(repo):
    edit_json(repo, ILM, lambda d: d["policy"]["phases"]["hot"]["actions"]["rollover"].update(max_age="30d"))
    assert "E2" in codes(repo, "WARN")


@pytest.mark.parametrize("rel,mutation,code", [
    ("elasticsearch/slm-logunify-daily.json", lambda d: d["retention"].update(expire_after="30d"), "E6"),
    ("elasticsearch/slm-logunify-daily.json", lambda d: d.update(repository="somewhere-else"), "E6"),
    ("elasticsearch/index-template-logunify.json", lambda d: d["template"]["settings"].update({"index.lifecycle.name": "logs"}), "E7"),
    ("elasticsearch/index-template-logunify.json", lambda d: d.pop("data_stream"), "E7"),
    ("elasticsearch/snapshot-repository-s3.json", lambda d: d["settings"].update(server_side_encryption=False), "E8"),
    ("elasticsearch/role-logunify-forwarder.json", lambda d: d["indices"][0]["privileges"].append("delete"), "E9"),
    ("elasticsearch/role-logunify-forwarder.json", lambda d: d["indices"][0]["privileges"].append("read"), "E9"),
])
def test_elasticsearch_supporting_rules_fire(repo, rel, mutation, code):
    edit_json(repo, rel, mutation)
    assert code in codes(repo)


def test_storing_the_archive_outside_india_is_a_warning_not_a_violation(repo):
    """CERT-In FAQ Q35 permits copies outside India if they can be produced in reasonable time; Directions para (iv) says India."""
    edit_json(repo, "elasticsearch/snapshot-repository-s3.json", lambda d: d["settings"].update(region="us-east-1"))
    assert "E8" in codes(repo, "WARN") and "E8" not in codes(repo)


def test_enterprise_profile_is_also_checked(repo):
    edit_json(repo, "elasticsearch/ilm-logunify-cert-in-searchable.json", lambda d: d["policy"]["phases"]["delete"].update(min_age="100d"))
    assert "E1" in codes(repo)


@pytest.mark.parametrize("old,new,code", [
    ("frozenTimePeriodInSecs = 15552000", "frozenTimePeriodInSecs = 7776000", "S1"),
    ("maxTotalDataSizeMB = 3000000", "maxTotalDataSizeMB = 500000", "S2"),
    ("maxVolumeDataSizeMB = 3000000", "maxVolumeDataSizeMB = 100000", "S2"),
])
def test_splunk_indexes_rules_fire(repo, old, new, code):
    edit_text(repo, "splunk/indexes.conf", old, new)
    assert code in codes(repo)


@pytest.mark.parametrize("old,new", [
    ("useACK = 1", "useACK = 0"),
    ("indexes = logunify", "indexes = *"),
    ("enableSSL = 1", "enableSSL = 0"),
])
def test_splunk_hec_rules_fire(repo, old, new):
    edit_text(repo, "splunk/inputs.conf", old, new)
    assert "S5" in codes(repo)


def test_splunk_warnings(repo):
    edit_text(repo, "splunk/indexes.conf", "coldToFrozenDir = /splunk/frozen/logunify", "")
    edit_text(repo, "splunk/indexes.conf", "maxHotSpanSecs = 86400", "maxHotSpanSecs = 7776000")
    assert {"S3", "S4"} <= codes(repo, "WARN")


def test_conf_parser_ignores_commented_settings(repo):
    conf = parse_conf(repo / "splunk" / "indexes.conf")
    assert "remotePath" not in conf["logunify"] and conf["logunify"]["frozenTimePeriodInSecs"] == "15552000"


def test_daily_index_off_by_one_is_caught(repo):
    """ISM ages count from index creation: deleting at exactly 180d would drop the last day's documents at ~179 days."""
    edit_json(repo, "wazuh/ism-policy-wazuh-cert-in.json",
              lambda d: d["policy"]["states"][2]["transitions"][0]["conditions"].update(min_index_age="180d"))
    assert "W1" in codes(repo)


@pytest.mark.parametrize("rel,mutation,code", [
    ("wazuh/ism-policy-wazuh-cert-in.json", lambda d: d["policy"]["states"][2]["transitions"][0]["conditions"].update(min_index_age="90d"), "W1"),
    ("wazuh/ism-policy-wazuh-cert-in.json", lambda d: d["policy"]["states"][1]["transitions"][0]["conditions"].update(min_index_age="3d"), "W2"),
    ("wazuh/ism-policy-wazuh-cert-in.json", lambda d: d["policy"]["ism_template"][0].update(index_patterns=["wazuh-alerts-*"]), "W3"),
    ("wazuh/sm-policy-wazuh-daily.json", lambda d: d["deletion"]["condition"].update(max_age="30d"), "W4"),
])
def test_wazuh_json_rules_fire(repo, rel, mutation, code):
    edit_json(repo, rel, mutation)
    assert code in codes(repo)


@pytest.mark.parametrize("rel,old,new,code", [
    ("wazuh/rules/0800-logunify_rules.xml", 'id="100110"', 'id="100100"', "W5"),                # duplicate id
    ("wazuh/rules/0800-logunify_rules.xml", 'id="100110"', 'id="5001"', "W5"),                  # outside custom range
    ("wazuh/rules/0800-logunify_rules.xml", "^(0\\.[89]\\d*|1(\\.0+)?)$", "^(0\\.[89]\\d*|1(\\.0+)?$", "W5"),   # unbalanced group
    ("wazuh/ossec-manager-snippet.xml", "<logall_json>yes</logall_json>", "<logall_json>no</logall_json>", "W6"),
])
def test_wazuh_rule_and_manager_checks_fire(repo, rel, old, new, code):
    edit_text(repo, rel, old, new)
    assert code in codes(repo)


VEC = "vector/vector.d"


@pytest.mark.parametrize("rel,old,new,code", [
    (f"{VEC}/10-sink-elasticsearch.yaml", "when_full: block", "when_full: drop_newest", "V1"),
    (f"{VEC}/20-sink-splunk-hec.yaml", "type: disk", "type: memory", "V1"),
    (f"{VEC}/00-common.yaml", "  enabled: true\n\n# Secrets", "  enabled: false\n\n# Secrets", "V2"),
    (f"{VEC}/20-sink-splunk-hec.yaml", 'default_token: "SECRET[fwd.splunk_hec_token]"', 'default_token: "abcd-1234"', "V3"),
    (f"{VEC}/10-sink-elasticsearch.yaml", 'Authorization: "SECRET[fwd.es_authorization]"', 'Authorization: "ApiKey abc"', "V3"),
    (f"{VEC}/10-sink-elasticsearch.yaml", "verify_certificate: true", "verify_certificate: false", "V4"),
    (f"{VEC}/20-sink-splunk-hec.yaml", "verify_hostname: true", "verify_hostname: false", "V4"),
    (f"{VEC}/10-sink-elasticsearch.yaml", "action: create", "action: index", "V5"),
    (f"{VEC}/10-sink-elasticsearch.yaml", "dataset: logunify", "dataset: other", "V5"),
    (f"{VEC}/20-sink-splunk-hec.yaml", "indexer_acknowledgements_enabled: true", "indexer_acknowledgements_enabled: false", "V6"),
    (f"{VEC}/20-sink-splunk-hec.yaml", "index: logunify\n", "index: main\n", "V6"),
])
def test_forwarder_rules_fire(repo, rel, old, new, code):
    edit_text(repo, rel, old, new)
    assert code in codes(repo)


def test_sizing_checks_use_stated_load(repo):
    warn, needed = lint_sizing(repo, eps=300, outage_hours=4, doc_bytes=None)
    assert warn == [] and needed <= 3_000_000                       # shipped config is sized for ~300 EPS
    warn, needed = lint_sizing(repo, eps=5000, outage_hours=4, doc_bytes=None)
    assert len(warn) == 3 and needed > 3_000_000
    assert "S2" in codes(repo, required_mb=needed)                  # at 5000 EPS the shipped Splunk size cap is too small
