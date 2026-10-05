"""Deterministic backend for end-to-end UI tests (Playwright) and manual demos. NOT for production.

    python scripts/e2e_server.py --port 8000 [--secret ...]

* JWT auth on, shared secret given by --secret / E2E_JWT_SECRET (tests mint their own tokens with it)
* in-memory stores, raw archive on (key generated per run), no demo traffic, no notification channels
* anomaly scoring is stubbed so that a log containing "audit log cleared" scores 0.95 (everything else 0.10): a CERT-In alert can then
  be raised on demand through POST /api/v1/ingest, which the real model could not do reliably on a fresh start
"""
import argparse
import base64
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--secret", default=os.environ.get("E2E_JWT_SECRET", "e2e-secret-e2e-secret-e2e-secret-0123456789"))
    a = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="logunify-e2e-")
    for k, v in {"AUDIT_DB_PATH": ":memory:", "STATE_DB_PATH": ":memory:", "AUTH_DB_PATH": ":memory:", "ALERT_DB_PATH": ":memory:",
                 "DLQ_PATH": f"{tmp}/dlq.jsonl", "RAW_ARCHIVE_DIR": f"{tmp}/raw"}.items():
        os.environ[f"LOGUNIFY_{k}"] = v

    import uvicorn

    from app.config import Settings
    from app.main import create_app

    s = Settings(mock_enabled=False, auth_mode="jwt", jwt_secret=a.secret, audit_hmac_key="k" * 32, raw_archive_enabled=True,
                 raw_archive_key=base64.b64encode(os.urandom(32)).decode(), alert_db_path=":memory:", audit_db_path=":memory:",
                 state_db_path=":memory:", auth_db_path=":memory:", dlq_path=f"{tmp}/dlq.jsonl", raw_archive_dir=f"{tmp}/raw",
                 org_name="Acme Bank Ltd", org_address="1 MG Road, Mumbai", org_location="Mumbai, Maharashtra, India", poc_name="Asha Rao",
                 poc_designation="CISO", poc_email="ciso@acme.example", poc_mobile="+91 90000 00001", ti_mock_feed=False)
    app = create_app(s)

    scorer = app.state.pipeline.intel.scorer

    def stub(rows, learn):
        return [0.95 if False else 0.10 for _ in rows]
    scorer.score_many = stub
    type(scorer).ready = property(lambda self: True)

    intel = app.state.pipeline.intel
    real = intel.analyze_many

    def analyze_many(parsed_list, no_learn=None):        # make the trigger text-driven, deterministic
        out = real(parsed_list, no_learn)
        for p, an in zip(parsed_list, out):
            if "audit log cleared" in (p.original or "").lower():
                p.fields["logunify.anomaly.score"] = 0.95
                from app.intel import mitre
                t = mitre.tag(p.fields, p.message or p.original)
                p.fields.update(t)
                an.score, an.technique = 0.95, t.get("threat.technique.id")
        return out
    intel.analyze_many = analyze_many

    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
