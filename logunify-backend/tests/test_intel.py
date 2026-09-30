import random

from app.ecs.normalizer import to_ecs
from app.intel.engine import LogIntelligence
from app.intel.template_miner import TemplateMinerService
from app.intel.ecs_mapper import map_to_ecs
from app.parsers.detect import parse_auto
from app.mock.generators import gen_text


def analyze(intel, line):
    p = parse_auto(line)
    a = intel.analyze(p)
    return a, to_ecs(p)


def test_drain3_extracts_params_and_maps_ecs():
    svc = TemplateMinerService()
    svc.mine("Connection from 10.0.0.1 port 5000 closed after 12 ms")
    m = svc.mine("Connection from 10.0.0.2 port 5001 closed after 40 ms")
    assert "<IP>" in m.template and "<NUM>" in m.template
    f = map_to_ecs(m)
    assert f["source.ip"] == "10.0.0.2" and f["source.port"] == 5001


def test_direction_and_user_mapping():
    svc = TemplateMinerService()
    svc.mine("Session opened for user alice from 10.0.0.1")
    m = svc.mine("Session opened for user bob from 10.0.0.9")
    f = map_to_ecs(m)
    assert f["user.name"] == "bob" and f["source.ip"] == "10.0.0.9"
    m = svc.mine("Transfer to 8.8.8.8 port 443 status 200 bytes 1234")
    f = map_to_ecs(m)
    assert f["destination.ip"] == "8.8.8.8" and f["destination.port"] == 443
    assert f["http.response.status_code"] == 200 and f["network.bytes"] == 1234


def test_parser_fields_are_not_overridden():
    intel = LogIntelligence()
    p = parse_auto("<38>Oct 11 22:14:15 web-01 sshd[1]: Failed password for bob from 1.2.3.4 port 22 ssh2")
    p.fields["source.ip"] = "9.9.9.9"
    intel.analyze(p)
    assert p.fields["source.ip"] == "9.9.9.9"


def test_key_value_text():
    svc = TemplateMinerService()
    svc.mine("login attempt user=alice ip=10.0.0.1")
    f = map_to_ecs(svc.mine("login attempt user=bob ip=10.0.0.2"))
    assert f["user.name"] == "bob"


def test_warmup_score_zero_then_anomaly_tagged():
    random.seed(1)
    intel = LogIntelligence(threshold=0.7, warmup=300, refit_every=10**9)
    for _ in range(299):
        a, _ = analyze(intel, gen_text(rare_rate=0.0))
        assert a.score == 0.0 and not a.model_ready
    analyze(intel, gen_text(rare_rate=0.0))
    intel.scorer.fit_sync()                                  # deterministic: don't wait for the bg thread
    normal = [analyze(intel, gen_text(rare_rate=0.0))[0].score for _ in range(200)]
    assert all(0.0 <= s <= 1.0 for s in normal)
    assert sum(s > 0.7 for s in normal) / len(normal) < 0.05  # false-positive rate stays low

    a, doc = analyze(intel, "Audit log cleared by user root on db-01 from 203.0.113.9 after 3 failed sudo attempts")
    assert a.model_ready and a.is_new_template and a.score > 0.7
    assert a.technique == "T1070"                       # "Audit log cleared" -> Indicator Removal (rule: log_clearing)
    assert doc["threat"]["technique"]["id"] == "T1070" and doc["threat"]["framework"] == "MITRE ATT&CK"
    assert doc["logunify"]["mitre"]["basis"] == "rule:log_clearing"
    assert doc["logunify"]["anomaly"]["score"] == a.score
    assert doc["source"]["ip"] == "203.0.113.9"


def test_low_score_has_no_mitre_tag():
    intel = LogIntelligence(warmup=50)
    for _ in range(150):
        analyze(intel, gen_text(rare_rate=0.0))
    intel.scorer.fit_sync()
    a, doc = analyze(intel, "Cache refresh completed on web-01 in 55 ms")
    assert a.score <= 0.7 and "threat" not in doc
