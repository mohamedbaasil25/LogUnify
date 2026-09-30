import base64
import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.security import tokens
from app.security.audit import AuditLog

SECRET = "s" * 40


def tok(role="analyst", sub="alice", secret=SECRET, **over):
    claims = {"sub": sub, "exp": time.time() + 600, "roles": [role], **over}
    return tokens.encode(claims, secret)


def hdr(t):
    return {"Authorization": f"Bearer {t}"}


def make(tmp_path, **kw):
    base = dict(mock_enabled=False, alert_db_path=str(tmp_path / "a.db"), auth_mode="jwt", jwt_secret=SECRET,
                audit_db_path=str(tmp_path / "audit.db"), audit_hmac_key="k" * 32, alert_api_key="legacy-key")
    base.update(kw)
    return create_app(Settings(**base))


@pytest.fixture
def client(tmp_path):
    with TestClient(make(tmp_path)) as c:
        yield c


# ---- tokens -------------------------------------------------------------------------------------------------
def test_token_checks():
    good = tok()
    assert tokens.decode(good, SECRET)["sub"] == "alice"
    for bad, why in [(tok(exp=time.time() - 600), "expired"), (good[:-2] + "xx", "signature"),
                     (tok(secret="o" * 40), "signature"), (tokens.encode({"sub": "a"}, SECRET), "exp")]:
        with pytest.raises(tokens.TokenError, match=why):
            tokens.decode(bad, SECRET)
    with pytest.raises(tokens.TokenError, match="issuer"):
        tokens.decode(tok(iss="x"), SECRET, issuer="idp")
    with pytest.raises(tokens.TokenError, match="audience"):
        tokens.decode(tok(aud="other"), SECRET, audience="logunify")


def test_alg_none_rejected():
    def b(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    none_tok = f'{b({"alg": "none"})}.{b({"sub": "a", "exp": time.time() + 99})}.'
    with pytest.raises(tokens.TokenError, match="algorithm"):
        tokens.decode(none_tok, SECRET)


# ---- RBAC ---------------------------------------------------------------------------------------------------
def test_no_token_and_bad_token(client):
    assert client.get("/api/v1/metrics").status_code == 401
    assert client.get("/api/v1/metrics", headers=hdr("garbage")).status_code == 401
    assert client.get("/health").status_code == 200          # liveness stays public


def test_role_matrix(client):
    v, a, ad = hdr(tok("viewer")), hdr(tok("analyst")), hdr(tok("admin"))
    assert client.get("/api/v1/metrics", headers=v).status_code == 200
    assert client.get("/api/v1/logs/recent", headers=v).status_code == 403     # raw logs: analyst+
    assert client.get("/api/v1/logs/recent", headers=a).status_code == 200
    assert client.get("/api/v1/sources", headers=a).status_code == 200
    body = {"name": "web-feed", "type": "http"}
    assert client.post("/api/v1/sources", json=body, headers=a).status_code == 403   # config: admin
    r = client.post("/api/v1/sources", json=body, headers=ad)
    assert r.status_code == 201
    assert client.delete(f"/api/v1/sources/{r.json()['id']}", headers=a).status_code == 403
    assert client.delete(f"/api/v1/sources/{r.json()['id']}", headers=ad).status_code == 204
    assert client.get("/api/v1/audit", headers=a).status_code == 403
    assert client.get("/api/v1/audit", headers=ad).status_code == 200


def test_highest_role_wins_and_unknown_ignored(client):
    t = tokens.encode({"sub": "bob", "exp": time.time() + 60, "roles": ["viewer", "admin", "god"]}, SECRET)
    assert client.get("/api/v1/audit", headers=hdr(t)).status_code == 200
    none = tokens.encode({"sub": "bob", "exp": time.time() + 60, "roles": ["god"]}, SECRET)
    assert client.get("/api/v1/metrics", headers=hdr(none)).status_code == 403


def test_keycloak_style_claim_path(tmp_path):
    with TestClient(make(tmp_path, jwt_roles_claim="realm_access.roles")) as c:
        t = tokens.encode({"sub": "k", "exp": time.time() + 60, "realm_access": {"roles": ["admin"]}}, SECRET)
        assert c.get("/api/v1/audit", headers=hdr(t)).status_code == 200


def test_alerts_accept_api_key_or_analyst_jwt(client):
    assert client.get("/api/v1/alerts").status_code == 401
    assert client.get("/api/v1/alerts", headers={"X-API-Key": "legacy-key"}).status_code == 200
    assert client.get("/api/v1/alerts", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/v1/alerts", headers=hdr(tok("analyst"))).status_code == 200
    assert client.get("/api/v1/alerts", headers=hdr(tok("viewer"))).status_code == 403


def test_jwt_mode_requires_strong_secret(tmp_path):
    with pytest.raises(ValueError):
        make(tmp_path, jwt_secret="short")
    with pytest.raises(ValueError):
        make(tmp_path, jwt_secret=None)


def test_auth_off_is_open_but_audited(tmp_path):
    with TestClient(make(tmp_path, auth_mode="off")) as c:
        assert c.get("/api/v1/logs/recent").status_code == 200
        rows = c.app.state.audit.list()
        assert rows[0]["actor"] == "anonymous" and rows[0]["auth"] == "disabled"


# ---- audit --------------------------------------------------------------------------------------------------
def test_actions_and_denials_are_audited(client):
    ad = hdr(tok("admin", sub="root"))
    client.post("/api/v1/sources", json={"name": "feed-1", "type": "http"}, headers=ad)
    client.get("/api/v1/logs/recent", headers=hdr(tok("viewer", sub="vic")))          # denied
    client.get("/api/v1/metrics")                                                    # unauthenticated
    rows = client.get("/api/v1/audit?limit=50", headers=ad).json()["items"]
    seen = {(r["actor"], r["action"], r["outcome"]) for r in rows}
    assert ("root", "sources.create", "allowed") in seen
    assert ("vic", "logs.view", "denied:403") in seen
    assert ("unauthenticated", "metrics.view", "denied:401") in seen
    assert client.post("/api/v1/audit/verify", headers=ad).json()["valid"] is True


def test_proof_download_is_audited(client):
    ad = hdr(tok("admin", sub="root"))
    client.get("/api/v1/integrity/batches/nope/proof/0", headers=ad)                  # 404 but access was attempted
    acts = [r["action"] for r in client.get("/api/v1/audit", headers=ad).json()["items"]]
    assert "integrity.proof.download" in acts


def test_polled_reads_are_sampled(client):
    v = hdr(tok("analyst", sub="poller"))
    for _ in range(5):
        client.get("/api/v1/logs/recent", headers=v)
    rows = [r for r in client.get("/api/v1/audit?limit=50", headers=hdr(tok("admin"))).json()["items"]
            if r["actor"] == "poller"]
    assert len(rows) == 1


def test_secrets_never_reach_the_audit_detail():
    log = AuditLog(":memory:")
    log.append("a", "admin", "jwt", "x", "/p", detail={"note": "password=hunter2 Bearer abc.def.ghi"})
    d = str(log.list()[0]["detail"])
    assert "hunter2" not in d and "abc.def.ghi" not in d


def _log(tmp_path, key=None):
    path = str(tmp_path / "chain.db")
    log = AuditLog(path, key)
    for i in range(5):
        log.append("u", "admin", "jwt", f"act{i}", "/r")
    return log, path


def test_chain_detects_edit(tmp_path):
    log, path = _log(tmp_path, key="k" * 32)
    assert log.verify(log.head())["valid"]
    raw = sqlite3.connect(path)
    with pytest.raises(sqlite3.DatabaseError):                                     # triggers block casual tampering
        raw.execute("UPDATE audit SET actor='evil' WHERE seq=2")
    with pytest.raises(sqlite3.DatabaseError):
        raw.execute("DELETE FROM audit WHERE seq=3")
    raw.execute("DROP TRIGGER audit_no_update")                                    # an attacker with DDL rights...
    raw.execute("UPDATE audit SET actor='evil' WHERE seq=2")
    raw.commit()
    v = log.verify()
    assert not v["valid"] and v["broken_at"] == 2


def test_gap_and_tail_truncation(tmp_path):
    log, path = _log(tmp_path)
    head = log.head()
    raw = sqlite3.connect(path)
    raw.execute("DROP TRIGGER audit_no_delete")
    raw.execute("DELETE FROM audit WHERE seq=5")                                   # truncate the tail
    raw.commit()
    assert log.verify()["valid"]                                                   # invisible from inside the chain...
    assert not log.verify(head)["valid"]                                           # ...caught by a witnessed head
    raw.execute("DELETE FROM audit WHERE seq=2")
    raw.commit()
    assert log.verify()["broken_at"] == 2


def test_keyed_chain_resists_recompute(tmp_path):
    log, _ = _log(tmp_path, key="k" * 32)
    other = AuditLog(str(tmp_path / "chain.db"), "z" * 32)                        # attacker without the key
    assert not other.verify()["valid"]
    assert log.verify()["valid"]


def test_anchor_head_on_ledger(client):
    r = client.post("/api/v1/audit/anchor", headers=hdr(tok("admin")))
    assert r.status_code == 201 and r.json()["mock_ledger"] is True
