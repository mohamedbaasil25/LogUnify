import json
import re
import shutil
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.compliance import report
from app.compliance.durations import to_days
from app.compliance.pdf import Pdf
from app.compliance.retention import live_elasticsearch, static_proof
from app.config import Settings
from app.main import create_app
from app.security import tokens

FORWARDER = str(Path(__file__).resolve().parents[2] / "logunify-forwarder")
SECRET = "s" * 40


def make(tmp_path, **kw):
    base = dict(mock_enabled=False, alert_db_path=str(tmp_path / "a.db"), audit_db_path=str(tmp_path / "au.db"),
                forwarder_root=FORWARDER, auth_mode="jwt", jwt_secret=SECRET, compliance_report_dir=str(tmp_path / "rep"))
    base.update(kw)
    return create_app(Settings(**base))


def admin():
    return {"Authorization": "Bearer " + tokens.encode({"sub": "cso", "exp": time.time() + 600, "roles": ["admin"]}, SECRET)}


def test_durations():
    assert to_days("180d") == 180 and to_days("12h") == 0.5


def test_static_proof_on_shipped_policies():
    p = static_proof(FORWARDER)
    assert p["available"] and p["passed"], p
    assert {x["layer"] for x in p["layers"]} >= {"Elasticsearch ILM", "Splunk", "Wazuh/OpenSearch ISM"}
    assert all(x["ok"] for x in p["layers"])


def test_static_proof_missing_files(tmp_path):
    p = static_proof(str(tmp_path))
    assert p["available"] is False and p["passed"] is None


def test_static_proof_detects_shortened_policy(tmp_path):
    root = tmp_path / "fw"
    shutil.copytree(FORWARDER, root, ignore=shutil.ignore_patterns("tools", ".venv", "__pycache__", ".pytest_cache"))
    f = root / "elasticsearch" / "ilm-logunify-cert-in.json"
    d = json.loads(f.read_text())
    d["policy"]["phases"]["delete"]["min_age"] = "90d"
    f.write_text(json.dumps(d))
    p = static_proof(str(root))
    assert p["passed"] is False and p["lint_errors"] >= 1
    assert any(not x["ok"] for x in p["layers"])


# ---- live probe against a stubbed Elasticsearch (NOT a real cluster) --------------------------------------------
def _es(indices, delete="181d", policy_status=200):
    def handler(req: httpx.Request):
        if req.url.path == "/_ilm/policy/logunify-cert-in":
            if policy_status != 200:
                return httpx.Response(policy_status, json={})
            return httpx.Response(200, json={"logunify-cert-in": {"policy": {"phases": {"delete": {"min_age": delete}}}}})
        if req.url.path.endswith("/_ilm/explain"):
            return httpx.Response(200, json={"indices": indices})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


GOOD = {".ds-logs-logunify-default-2026.01.01-000001": {"managed": True, "policy": "logunify-cert-in", "age": "12.5d", "step": "complete"}}


def test_live_pass():
    r = live_elasticsearch("http://es.test", "k", transport=_es(GOOD))
    assert r["passed"] and r["oldest_index_age"] == "12.5d"


@pytest.mark.parametrize("kw,failing", [
    (dict(indices=GOOD, delete="30d"), "ilm_delete_min_age_ge_180d"),
    (dict(indices={"i": {"managed": False}}), "all_indices_managed"),
    (dict(indices={"i": {"managed": True, "policy": "other"}}), "all_indices_managed"),
    (dict(indices={"i": {"managed": True, "policy": "logunify-cert-in", "step": "ERROR"}}), "no_ilm_errors"),
    (dict(indices={}), "indices_found"),
    (dict(indices=GOOD, policy_status=404), "ilm_policy_present"),
])
def test_live_failures(kw, failing):
    r = live_elasticsearch("http://es.test", None, transport=_es(**kw))
    assert not r["passed"] and any(c["name"] == failing and not c["ok"] for c in r["checks"])


def test_live_unreachable_never_raises():
    def boom(req):
        raise httpx.ConnectError("refused")
    r = live_elasticsearch("http://es.test", None, transport=httpx.MockTransport(boom))
    assert r["checked"] and not r["passed"]
    assert not live_elasticsearch("", None)["checked"]


# ---- report / controls / PDF ---------------------------------------------------------------------------------------
def by_id(rep, fw, cid):
    return next(c for c in rep["controls"] if c["framework"] == fw and c["id"] == cid)


def test_report_states_real_gaps(tmp_path):
    with TestClient(make(tmp_path, auth_mode="off")) as c:
        rep = c.get("/api/v1/compliance/report").json()
    assert by_id(rep, "CERT-In", "Dir.(iv)")["status"] in ("met", "partial")
    assert by_id(rep, "PCI-DSS 4.0", "10.5.1")["status"] == "gap"          # 180 d < 12 months: must not be papered over
    assert by_id(rep, "HIPAA", "164.316(b)(2)(i)")["status"] == "gap"
    assert by_id(rep, "PCI-DSS 4.0", "10.3.1")["status"] == "gap"           # auth off => access control is a gap
    assert by_id(rep, "PCI-DSS 4.0", "10.3.4")["status"] == "partial"       # mock ledger is never "met"
    assert set(rep["summary"]) == {"CERT-In", "PCI-DSS 4.0", "HIPAA", "ISO 27001:2022"}
    assert by_id(rep, "ISO 27001:2022", "A.8.17")["status"] == "manual"


def test_report_with_auth_reflects_rbac(tmp_path):
    with TestClient(make(tmp_path)) as c:
        rep = c.get("/api/v1/compliance/report", headers=admin()).json()
        assert by_id(rep, "PCI-DSS 4.0", "10.3.1")["status"] == "met"
        assert by_id(rep, "ISO 27001:2022", "A.5.34")["status"] == "partial"
        only = c.get("/api/v1/compliance/report?framework=HIPAA", headers=admin()).json()
        assert {x["framework"] for x in only["controls"]} == {"HIPAA"}


def test_report_hash_is_reproducible(tmp_path):
    with TestClient(make(tmp_path, auth_mode="off")) as c:
        rep = c.get("/api/v1/compliance/report").json()
    import hashlib
    body = {k: v for k, v in rep.items() if k != "report_sha256"}
    assert hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == rep["report_sha256"]


def test_compliance_is_admin_only(tmp_path):
    with TestClient(make(tmp_path)) as c:
        v = {"Authorization": "Bearer " + tokens.encode({"sub": "v", "exp": time.time() + 60, "roles": ["analyst"]}, SECRET)}
        assert c.get("/api/v1/compliance/report", headers=v).status_code == 403
        assert c.get("/api/v1/compliance/report.pdf").status_code == 401


def test_pdf_is_wellformed(tmp_path):
    with TestClient(make(tmp_path, auth_mode="off")) as c:
        r = c.get("/api/v1/compliance/report.pdf")
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    pdf = r.content
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    assert len(r.headers["x-report-sha256"]) == 64
    # every xref offset must point at "<n> 0 obj"
    start = int(re.search(rb"startxref\n(\d+)", pdf).group(1))
    table = pdf[start:].split(b"\n")
    n = int(table[1].split()[1])
    for i in range(1, n):
        off = int(table[2 + i].split()[0])
        assert pdf[off:].startswith(f"{i} 0 obj".encode()), i
    assert b"PCI-DSS 4.0" in pdf and b"180-day retention proof" in pdf


def test_pdf_paginates_and_survives_odd_text():
    d = Pdf("t", "f")
    for i in range(300):
        d.text(f"line {i} (paren) \\ backslash ≤ x " + "y" * 200, 9)
    out = d.render()
    assert out.count(b"/Type /Page ") >= 3 and out.startswith(b"%PDF")


def test_scheduled_report_files(tmp_path):
    from app.compliance.scheduler import write_report
    app = make(tmp_path, auth_mode="off")
    path = write_report(app.state.settings, app.state.pipeline, app.state.audit)
    assert path.exists() and path.with_suffix(".json").exists()
    assert json.loads(path.with_suffix(".json").read_text())["report_sha256"]
