import base64
import http.server
import json
import threading
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.security import tokens
from app.security.oidc import Jwks, Revocations

ISS, AUD = "https://idp.example.org/realms/soc", "logunify"


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk_rsa(key, kid):
    n = key.public_key().public_numbers()
    return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
            "n": b64(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")), "e": b64(n.e.to_bytes((n.e.bit_length() + 7) // 8, "big"))}


def jwk_ec(key, kid):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "use": "sig", "crv": "P-256", "kid": kid, "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}


def sign(header: dict, claims: dict, key=None, alg="RS256") -> str:
    h, c = b64(json.dumps(header).encode()), b64(json.dumps(claims).encode())
    msg = f"{h}.{c}".encode()
    if alg == "RS256":
        sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    else:
        r, s = utils.decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{h}.{c}.{b64(sig)}"


def claims(**over):
    now = time.time()
    return {"sub": "alice", "iss": ISS, "aud": AUD, "exp": now + 600, "iat": now, "jti": "tok-1",
            "realm_access": {"roles": ["analyst"]}, **over}


@pytest.fixture(scope="module")
def keys():
    return {"rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048), "rsa2": rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "ec": ec.generate_private_key(ec.SECP256R1())}


@pytest.fixture
def app(tmp_path, keys):
    jwks = tmp_path / "jwks.json"
    jwks.write_text(json.dumps({"keys": [jwk_rsa(keys["rsa"], "k-rsa"), jwk_ec(keys["ec"], "k-ec")]}))
    s = Settings(mock_enabled=False, alert_db_path=":memory:", audit_db_path=":memory:", dlq_path=str(tmp_path / "d.jsonl"),
                 auth_mode="jwt", jwt_secret="s" * 40, jwt_jwks_file=str(jwks), jwt_issuer=ISS, jwt_audience=AUD,
                 jwt_roles_claim="realm_access.roles")
    return create_app(s)


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


# ---- signatures ---------------------------------------------------------------------------------------------------
def test_rs256_and_es256_tokens_are_accepted(app, keys):
    with TestClient(app) as c:
        rs = sign({"alg": "RS256", "kid": "k-rsa", "typ": "JWT"}, claims(), keys["rsa"])
        es = sign({"alg": "ES256", "kid": "k-ec"}, claims(jti="tok-2"), keys["ec"], "ES256")
        for t in (rs, es):
            r = c.get("/api/v1/auth/me", headers=bearer(t))
            assert r.status_code == 200 and r.json()["sub"] == "alice" and r.json()["role"] == "analyst" and r.json()["expires_in_s"] > 500
        assert c.get("/api/v1/logs/recent", headers=bearer(rs)).status_code == 200                    # analyst may read logs
        assert c.get("/api/v1/audit", headers=bearer(rs)).status_code == 403                          # ...but not the audit log


def test_forged_and_confused_tokens_are_rejected(app, keys):
    with TestClient(app) as c:
        h = {"alg": "RS256", "kid": "k-rsa"}
        bad = {
            "wrong key (attacker's own RSA key, right kid)": sign(h, claims(), keys["rsa2"]),
            "unknown kid": sign({"alg": "RS256", "kid": "nope"}, claims(), keys["rsa"]),
            "kid of an EC key used with RS256": sign({"alg": "RS256", "kid": "k-ec"}, claims(), keys["rsa"]),
            "expired": sign(h, claims(exp=time.time() - 3600), keys["rsa"]),
            "wrong issuer": sign(h, claims(iss="https://evil.example"), keys["rsa"]),
            "wrong audience": sign(h, claims(aud="another-app"), keys["rsa"]),
            "alg none": b64(json.dumps({"alg": "none"}).encode()) + "." + b64(json.dumps(claims()).encode()) + ".",
            "HS384": tokens.encode(claims(), "s" * 40).replace(b64(b'{"alg":"HS256","typ":"JWT"}'), b64(b'{"alg":"HS384","typ":"JWT"}')),
        }
        for why, t in bad.items():
            assert c.get("/api/v1/auth/me", headers=bearer(t)).status_code == 401, why


def test_hs256_with_the_public_key_as_secret_is_not_an_oracle(app, keys):
    """Classic alg-confusion: sign HS256 using the RSA *public key text* as the HMAC secret. HS256 only ever verifies against the
    configured shared secret, so it must fail."""
    pub = json.dumps(jwk_rsa(keys["rsa"], "k-rsa"))
    forged = tokens.encode(claims(), pub)
    with TestClient(app) as c:
        assert c.get("/api/v1/auth/me", headers=bearer(forged)).status_code == 401
        good = tokens.encode(claims(), "s" * 40)                                                      # the real shared secret still works
        assert c.get("/api/v1/auth/me", headers=bearer(good)).status_code == 200


def test_settings_validation_for_idp_mode(tmp_path):
    f = tmp_path / "j.json"
    f.write_text("{}")
    base = dict(mock_enabled=False, alert_db_path=":memory:", audit_db_path=":memory:", auth_mode="jwt")
    with pytest.raises(ValueError, match="needs LOGUNIFY_JWT_SECRET"):
        create_app(Settings(**base))
    with pytest.raises(ValueError, match="ISSUER and LOGUNIFY_JWT_AUDIENCE"):
        create_app(Settings(**base, jwt_jwks_file=str(f)))                                            # a JWKS without iss/aud would accept foreign tokens
    with pytest.raises(ValueError):
        Jwks(url="http://idp.example.org/jwks")                                                       # plain http to a remote host
    Jwks(url="https://idp.example.org/jwks")
    Jwks(url="http://127.0.0.1:9/jwks")


# ---- JWKS fetching ------------------------------------------------------------------------------------------------------
class JwksServer:
    def __init__(self, doc):
        self.doc, self.hits, self.fail = doc, 0, False
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.hits += 1
                if outer.fail:
                    self.send_response(503)
                    self.end_headers()
                    return
                body = json.dumps(outer.doc).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}/jwks"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


def test_jwks_url_cache_rotation_and_outage(keys):
    srv = JwksServer({"keys": [jwk_rsa(keys["rsa"], "k1")]})
    try:
        j = Jwks(url=srv.url, ttl_s=3600)
        assert j.get("k1", now=0)["kid"] == "k1" and srv.hits == 1
        assert j.get("k1", now=10) and srv.hits == 1                                                  # served from cache
        srv.doc = {"keys": [jwk_rsa(keys["rsa"], "k1"), jwk_rsa(keys["rsa2"], "k2")]}                 # the IdP rotates in a new key
        assert j.get("k2", now=100)["kid"] == "k2" and srv.hits == 2                                  # unknown kid -> one refresh
        before = srv.hits
        for i in range(50):
            assert j.get(f"forged-{i}", now=101) is None
        assert srv.hits == before                                                                      # forged kids cannot trigger a fetch storm
        srv.fail = True
        assert j.get("k1", now=100_000)["kid"] == "k1"                                                 # cache expired + IdP down: keep serving cached keys
        assert j.fetch_errors >= 1
        empty = Jwks(url=srv.url)
        assert empty.get("k1") is None                                                                 # nothing cached and IdP down: fail closed
    finally:
        srv.close()


# ---- revocation ---------------------------------------------------------------------------------------------------------
def test_revoke_by_jti_and_by_subject(app, keys):
    with TestClient(app) as c:
        admin = sign({"alg": "RS256", "kid": "k-rsa"}, claims(sub="root", jti="adm", realm_access={"roles": ["admin"]}), keys["rsa"])
        alice = sign({"alg": "RS256", "kid": "k-rsa"}, claims(jti="a-1"), keys["rsa"])
        alice2 = sign({"alg": "RS256", "kid": "k-rsa"}, claims(jti="a-2"), keys["rsa"])
        assert c.get("/api/v1/auth/me", headers=bearer(alice)).status_code == 200
        assert c.post("/api/v1/auth/revoke", json={"jti": "a-1"}, headers=bearer(alice)).status_code == 403            # analysts cannot revoke
        assert c.post("/api/v1/auth/revoke", json={"jti": "a-1", "exp": time.time() + 600}, headers=bearer(admin)).status_code == 200
        r = c.get("/api/v1/auth/me", headers=bearer(alice))
        assert r.status_code == 401 and "revoked" in r.json()["detail"]
        assert c.get("/api/v1/auth/me", headers=bearer(alice2)).status_code == 200                                    # another token of hers still works
        assert c.post("/api/v1/auth/revoke", json={"sub": "alice"}, headers=bearer(admin)).status_code == 200
        assert c.get("/api/v1/auth/me", headers=bearer(alice2)).status_code == 401                                    # all issued before now: dead
        time.sleep(1.1)
        fresh = sign({"alg": "RS256", "kid": "k-rsa"}, claims(jti="a-3"), keys["rsa"])
        assert c.get("/api/v1/auth/me", headers=bearer(fresh)).status_code == 200                                    # issued AFTER the revocation: a new login works
        assert c.get("/api/v1/auth/me", headers=bearer(alice2)).status_code == 401                                   # the old one stays dead
        assert c.delete("/api/v1/auth/revoke/subject/alice", headers=bearer(admin)).status_code == 200
        assert c.get("/api/v1/auth/me", headers=bearer(alice2)).status_code == 200                                   # lifting the revocation restores it
        assert c.post("/api/v1/auth/revoke", json={}, headers=bearer(admin)).status_code == 422
        assert any(r["action"] == "auth.revoke" for r in c.get("/api/v1/audit", headers=bearer(admin)).json()["items"])


def test_subject_revocation_blocks_tokens_without_iat_and_persists(tmp_path):
    rv = Revocations(str(tmp_path / "auth.db"))
    rv.revoke_subject("mallory", "root", not_before=1000)
    assert rv.is_revoked({"sub": "mallory", "iat": 999}) and rv.is_revoked({"sub": "mallory"}) and not rv.is_revoked({"sub": "mallory", "iat": 1001})
    rv.revoke_jti("j1", exp=time.time() + 100, by="root")
    rv.revoke_jti("old", exp=time.time() - 5, by="root")
    again = Revocations(str(tmp_path / "auth.db"))                                                     # restart: state survives, expired entries drop
    assert again.is_revoked({"sub": "x", "jti": "j1"}) and not again.is_revoked({"sub": "x", "jti": "old"})
    assert again.is_revoked({"sub": "mallory", "iat": 5})


def test_hs256_only_deployments_still_work(tmp_path):
    s = Settings(mock_enabled=False, alert_db_path=":memory:", audit_db_path=":memory:", dlq_path=str(tmp_path / "d.jsonl"),
                 auth_mode="jwt", jwt_secret="s" * 40)
    with TestClient(create_app(s)) as c:
        t = tokens.encode({"sub": "bob", "exp": time.time() + 60, "roles": ["viewer"]}, "s" * 40)
        assert c.get("/api/v1/auth/me", headers=bearer(t)).json()["role"] == "viewer"
        rs = sign({"alg": "RS256", "kid": "x"}, claims(), rsa.generate_private_key(public_exponent=65537, key_size=2048))
        assert c.get("/api/v1/auth/me", headers=bearer(rs)).status_code == 401                          # no JWKS configured: RS256 not accepted


def test_replicas_sharing_the_revocation_file_see_each_others_revocations(tmp_path):
    a, b = Revocations(str(tmp_path / "auth.db"), refresh_s=5), Revocations(str(tmp_path / "auth.db"), refresh_s=5)
    t0 = time.monotonic()
    assert not b.is_revoked({"sub": "eve", "iat": 1, "jti": "x"}, now=t0)
    a.revoke_jti("x", exp=time.time() + 100, by="root")
    assert not b.is_revoked({"sub": "eve", "iat": 1, "jti": "x"}, now=t0 + 1)                         # cached for up to refresh_s
    assert b.is_revoked({"sub": "eve", "iat": 1, "jti": "x"}, now=t0 + 6)                             # ...then picked up
