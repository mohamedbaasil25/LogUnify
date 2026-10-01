import json
import textwrap
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.ecs.validate import validate
from app.main import create_app
from app.parsers import cli as parser_cli
from app.parsers.base import ParsedLog, ParseError
from app.parsers.fixtures import run_fixtures, untested_parsers
from app.parsers.sdk import DeclarativeParser, FunctionParser, ParserRegistry, build_registry
from app.pipeline.bus import InMemoryBus
from app.pipeline.metrics import MetricsRegistry
from app.pipeline.processor import Pipeline

FIXTURES = Path(__file__).resolve().parents[1] / "parser_fixtures"

ACME = textwrap.dedent('''
    name: acme_vpn
    version: "2.1.0"
    kind: regex
    description: Acme VPN gateway
    sniff:
      contains: ["ACMEVPN"]
      confidence: 0.9
    match:
      regex: '^(?P<ts>\\S+) ACMEVPN (?P<user>\\S+) (?P<verb>login|logout) from (?P<ip>\\S+) code=(?P<code>\\d+)'
    timestamp:
      field: ts
    message: "{user} {verb}"
    fields:
      user.name: {from: user}
      source.ip: {from: ip, type: ip}
      event.action: {from: verb}
      http.response.status_code: {from: code, type: int}
    rules:
      - when: {field: code, gte: 400, lt: 500}
        set: {event.outcome: failure}
    static:
      event.kind: event
      event.category: [authentication]
      event.type: [start]
      event.outcome: success
''')
ACME_LINE = "2026-10-01T10:00:00Z ACMEVPN bob login from 203.0.113.5 code=403"


def pipe(tmp_path, **kw):
    base = dict(alert_db_path=":memory:", mock_enabled=False, dlq_path=str(tmp_path / "dlq.jsonl"))
    base.update(kw)
    return Pipeline(InMemoryBus(100), MetricsRegistry(), Settings(**base))


# ---- the shipped parsers keep their contract -------------------------------------------------------------------------
def test_every_shipped_parser_passes_its_golden_fixtures_and_validates():
    reg = build_registry()
    results = run_fixtures(reg, FIXTURES)
    bad = [(r.parser, r.case, r.problems) for r in results if not r.ok]
    assert results and not bad, bad
    assert untested_parsers(reg, FIXTURES) == []                         # onboarding is not finished without a fixture


def test_fixture_harness_catches_regressions(tmp_path):
    fx = tmp_path / "fx" / "nginx_access"
    fx.mkdir(parents=True)
    src = FIXTURES / "nginx_access" / "502_error"
    (fx / "case.log").write_text(src.with_suffix(".log").read_text())
    exp = json.loads(src.with_suffix(".expected.json").read_text())
    exp["http.response.status_code"] = 200                              # wrong on purpose
    (fx / "case.expected.json").write_text(json.dumps(exp))
    res = run_fixtures(build_registry(), tmp_path / "fx")
    assert not res[0].ok and any("status_code" in p for p in res[0].problems)
    (fx / "case.expected.json").unlink()
    assert any("missing" in p for p in run_fixtures(build_registry(), tmp_path / "fx")[0].problems)


# ---- registry ---------------------------------------------------------------------------------------------------------
def test_detection_prefers_the_most_confident_parser():
    reg = build_registry()
    assert reg.detect('{"a": 1}').name == "json"
    assert reg.detect('{"eventSource":"x","eventName":"y","awsRegion":"z"}').name == "aws_cloudtrail"
    assert reg.detect("<38>Oct 11 22:14:15 h sshd[1]: hi").name == "syslog"
    assert reg.detect("CEF:0|a|b|1|2|n|5|src=1.1.1.1").name == "cef"
    assert reg.detect("<4>Oct 11 22:14:15 fw kernel: DROP IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP").name == "iptables_log"
    assert reg.detect("hello world").name == "text"


def test_hints_by_name_unknown_hint_and_registration_rules():
    reg = build_registry()
    assert reg.parse("<38>Oct 11 22:14:15 h a[1]: x", "syslog").parser == "syslog"
    with pytest.raises(ParseError, match="unknown format hint"):
        reg.parse("x", "nope")
    with pytest.raises(ValueError):
        reg.register(reg.get("json"))                                    # duplicate name
    with pytest.raises(ValueError):
        reg.register(FunctionParser("Bad-Name", "1", lambda t: None, lambda t: 0.0))
    with pytest.raises(TypeError):
        reg.register(object())
    r = ParserRegistry()
    r.register(FunctionParser("aa", "1", lambda t: ParsedLog("aa", t), lambda t: 0.5), priority=1)
    r.register(FunctionParser("bb", "1", lambda t: ParsedLog("bb", t), lambda t: 0.5), priority=2)
    assert r.detect("x").name == "bb"                                     # tie on confidence: higher priority wins
    assert r.parse("x").parser == "bb" and r.parse("x").parser_version == "1"


def test_a_crashing_sniff_is_ignored_not_fatal():
    r = build_registry()

    def boom(_t):
        raise RuntimeError("sniff bug")
    r.register(FunctionParser("buggy", "1", lambda t: ParsedLog("buggy", t), boom))
    assert r.parse("<38>Oct 11 22:14:15 h a[1]: x").parser == "syslog"


# ---- onboarding a new source with a YAML file only ------------------------------------------------------------------------
def test_new_source_is_onboarded_by_dropping_a_yaml_file(tmp_path):
    d = tmp_path / "parsers.d"
    d.mkdir()
    (d / "acme_vpn.yaml").write_text(ACME)
    p = pipe(tmp_path, parser_dir=str(d))
    doc = p.process(ACME_LINE.encode())
    assert doc["logunify"]["parser"] == {"name": "acme_vpn", "version": "2.1.0"}
    assert doc["user"]["name"] == "bob" and doc["source"]["ip"] == "203.0.113.5" and doc["http"]["response"]["status_code"] == 403
    assert doc["event"]["outcome"] == "failure" and doc["event"]["category"] == ["authentication"]      # rule beat the static default
    assert doc["@timestamp"] == "2026-10-01T10:00:00Z" or doc["@timestamp"].startswith("2026-10-01T10:00:00")
    assert validate(doc) == []


def test_bad_parser_files_are_skipped_loudly_and_do_not_stop_the_rest(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "good.yaml").write_text(ACME)
    (d / "badregex.yaml").write_text(ACME.replace("acme_vpn", "bad_regex").replace("(?P<user>\\S+)", "(?P<user>\\S+"))
    (d / "redos.yaml").write_text(ACME.replace("acme_vpn", "redos").replace("(?P<user>\\S+)", "(?P<user>(a+)+)"))
    (d / "nogroups.yaml").write_text(ACME.replace("acme_vpn", "no_groups").replace("(?P<", "(?:"))
    (d / "badfield.yaml").write_text(ACME.replace("acme_vpn", "bad_field").replace("{from: user}", "{from: missing_group}"))
    (d / "badtransform.yaml").write_text(ACME.replace("acme_vpn", "bad_tx").replace("{from: user}", "{from: user, transform: rot13}"))
    (d / "notyaml.yaml").write_text("::: not [valid")
    (d / "plugin.py").write_text("raise RuntimeError('plugin import failed')")
    r = build_registry(str(d), entry_points=False)
    assert "acme_vpn" in r.names() and len(r.errors) == 7
    assert any("catastrophic" in e for e in r.errors) and any("invalid regex" in e for e in r.errors)
    assert any("no group named" in e for e in r.errors) and any("rot13" in e or "transform" in e for e in r.errors)


def test_python_plugin_parsers(tmp_path):
    d = tmp_path / "plug"
    d.mkdir()
    (d / "colon_kv.py").write_text(textwrap.dedent('''
        from app.parsers.base import ParsedLog, ParseError

        class ColonKV:
            name = "colon_kv"
            version = "0.3.0"
            def sniff(self, text):
                return 0.95 if text.startswith("KV|") else 0.0
            def parse(self, text):
                try:
                    pairs = dict(p.split("=", 1) for p in text[3:].split(";"))
                except ValueError:
                    raise ParseError("bad kv")
                return ParsedLog("colon_kv", text, pairs.pop("ts", None), pairs.get("msg"), {"user.name": pairs.get("u")})

        PARSERS = [ColonKV()]
    '''))
    r = build_registry(str(d), entry_points=False)
    p = r.parse("KV|ts=2026-10-01T10:00:00Z;u=carol;msg=hi")
    assert (p.parser, p.parser_version, p.fields["user.name"]) == ("colon_kv", "0.3.0", "carol")
    with pytest.raises(ParseError):
        r.parse("KV|garbage")


def test_numeric_rule_ranges_need_all_operators():
    from app.parsers.sdk import _predicate
    get = lambda k: {"status": "502"}.get(k)       # noqa: E731
    assert not _predicate({"field": "status", "gte": 400, "lt": 500}, get)
    assert _predicate({"field": "status", "gte": 500}, get) and _predicate({"field": "status", "gte": 400, "lt": 600}, get)


def test_declarative_regex_only_sees_a_bounded_prefix_of_the_line():
    p = DeclarativeParser.from_file(Path(__file__).resolve().parents[1] / "app" / "parsers" / "builtin" / "nginx_access.yaml")
    long_line = '1.2.3.4 - - [01/Oct/2026:10:00:00 +0000] "GET /' + "a" * 60000 + ' HTTP/1.1" 200 5'
    t = time.perf_counter()
    with pytest.raises(ParseError):
        p.parse(long_line)
    assert time.perf_counter() - t < 0.5


# ---- ECS validation ---------------------------------------------------------------------------------------------------
def test_validator_flags_real_problems_and_accepts_untyped_known_roots():
    good = {"@timestamp": "2026-10-01T10:00:00Z", "ecs": {"version": "8.11.0"}, "event": {"kind": "event", "category": ["web"], "type": ["access"]},
            "source": {"ip": "1.2.3.4", "port": 22}, "labels": {"x": 1}, "logunify": {"anything": {"goes": 1}}, "url": {"unmodelled_field": "ok"}}
    assert validate(good) == []
    bad = {"@timestamp": "yesterday", "event": {"kind": "weird", "category": "web", "outcome": "maybe"}, "source": {"ip": "999.1.1.1", "port": "22"},
           "mystery": {"a": 1}, "labels": {"nested": [{"a": 1}]}}
    rules = {(r, f) for r, f, _ in validate(bad)}
    assert {("type_mismatch", "@timestamp"), ("bad_enum", "event.kind"), ("not_array", "event.category"), ("bad_enum", "event.outcome"),
            ("type_mismatch", "source.ip"), ("type_mismatch", "source.port"), ("unknown_root", "mystery.a"), ("labels_scalar", "labels.nested"),
            ("missing_required", "ecs.version")} <= rules


def test_strict_mode_dead_letters_violations_and_warn_mode_counts_them(tmp_path):
    bad_parser = FunctionParser("badecs", "1", lambda t: ParsedLog("badecs", t, None, t, {"source.ip": "not-an-ip", "mystery.x": 1}),
                                lambda t: 0.99 if t.startswith("BAD") else 0.0)
    for mode in ("warn", "strict"):
        p = pipe(tmp_path, taxonomy_mode=mode, dlq_path=str(tmp_path / f"{mode}.jsonl"))
        p.parsers.register(bad_parser)
        doc = p.process(b"BAD line")
        assert p.metrics.schema_violations["unknown_root:mystery.x"] == 1
        if mode == "warn":
            assert doc is not None and not p.metrics.dead_lettered
        else:
            assert doc is None and p.metrics.dead_lettered["schema_violation:unknown_root"] == 1
            p.dlq.flush()
            assert b"BAD line" in __import__("base64").b64decode(json.loads((tmp_path / "strict.jsonl").read_text())["raw_b64"])


# ---- API --------------------------------------------------------------------------------------------------------------
def test_api_lists_parsers_validates_formats_and_accepts_new_ones(tmp_path):
    d = tmp_path / "pd"
    d.mkdir()
    (d / "acme_vpn.yaml").write_text(ACME)
    (d / "broken.yaml").write_text("name: x\nversion: '1'\nkind: nope\nsniff: {contains: [a]}\n")
    s = Settings(mock_enabled=False, alert_db_path=":memory:", parser_dir=str(d), dlq_path=str(tmp_path / "dlq.jsonl"))
    with TestClient(create_app(s)) as c:
        r = c.get("/api/v1/parsers").json()
        assert {"acme_vpn", "nginx_access", "syslog"} <= {i["name"] for i in r["items"]} and any("broken.yaml" in e for e in r["errors"])
        assert c.post("/api/v1/ingest", json={"logs": ["x"], "format": "nonexistent"}).status_code == 422
        assert c.post("/api/v1/sources", json={"name": "vpn feed", "type": "http", "format": "nonexistent"}).status_code == 422
        src = c.post("/api/v1/sources", json={"name": "vpn feed", "type": "http", "format": "acme_vpn"})
        assert src.status_code == 201
        assert c.post(f"/api/v1/sources/{src.json()['id']}/ingest", json={"logs": [ACME_LINE]},
                      headers={"X-Source-Token": src.json()["token"]}).status_code == 202
        for _ in range(100):
            items = c.get("/api/v1/logs/recent?format=acme_vpn").json()["items"]
            if items:
                break
            time.sleep(0.05)
        assert items[0]["logunify"]["parser"]["name"] == "acme_vpn"
        assert c.post("/api/v1/parse", json={"log": ACME_LINE}).json()["ecs"]["logunify"]["source_format"] == "acme_vpn"


# ---- developer CLI ----------------------------------------------------------------------------------------------------
def test_scaffold_then_test_flow(tmp_path, capsys):
    import shutil
    pdir, fx = tmp_path / "parsers.d", tmp_path / "fx"
    shutil.copytree(FIXTURES, fx)                                       # shipped parsers keep their fixtures; only my_source is new
    assert parser_cli.main(["scaffold", "my_source", "--dir", str(pdir), "--fixtures", str(fx)]) == 0
    assert parser_cli.main(["scaffold", "my_source", "--dir", str(pdir), "--fixtures", str(fx)]) == 2        # never overwrites
    assert parser_cli.main(["scaffold", "Bad Name", "--dir", str(pdir)]) == 2
    assert parser_cli.main(["test", "--parser-dir", str(pdir), "--fixtures", str(fx)]) == 1               # no expectation yet: fails
    assert parser_cli.main(["test", "--parser-dir", str(pdir), "--fixtures", str(fx), "--update"]) == 0
    assert parser_cli.main(["test", "--parser-dir", str(pdir), "--fixtures", str(fx), "--strict"]) == 0
    out = capsys.readouterr().out
    assert "my_source/001" in out
    assert parser_cli.main(["try", "my_source", "2026-10-01T10:00:00Z web-01 REPLACE_ME hello", "--parser-dir", str(pdir)]) == 0
    assert parser_cli.main(["list", "--parser-dir", str(pdir)]) == 0
