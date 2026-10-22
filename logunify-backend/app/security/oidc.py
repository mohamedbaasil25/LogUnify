"""Token verification for real identity providers (Keycloak, Entra ID, Okta...): RS256 / ES256 against a JWKS, plus the
shared-secret HS256 path, plus revocation.

How it decides (alg-confusion safe): the token's `alg` selects the ONLY key family that may verify it.
  HS256        -> the configured shared secret (LOGUNIFY_JWT_SECRET), never a JWKS key
  RS256 / ES256 -> a JWKS key of the matching type (`kty` RSA / EC) found by `kid`, never the shared secret
  anything else (`none`, HS384, PS256...) -> rejected.
Both families can be enabled at once. A JWKS comes from LOGUNIFY_JWT_JWKS_FILE (a static file: the air-gapped option) or
LOGUNIFY_JWT_JWKS_URL (https, or loopback http), cached for `jwt_jwks_ttl_s`; an unknown `kid` triggers one refresh per
`MIN_REFRESH_S`, so a stream of forged kids cannot turn this API into a fetch amplifier. If the IdP is unreachable the cached keys
keep working; with no cache the verification fails closed.

Revocation (`Revocations`): a token can be revoked by `jti`, or every token of a subject issued before now (by `iat`). Entries
persist in SQLite and are dropped once the token would have expired anyway. Tokens without `jti`/`iat` can only be revoked per subject
with `iat`-less subjects blocked outright. Revocation only exists inside this API: it does not log the user out at the IdP.
"""
import base64
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from . import tokens
from .tokens import TokenError

log = logging.getLogger("logunify.security")
MIN_REFRESH_S = 30.0
_ALGS = {"RS256": "RSA", "ES256": "EC"}


def _b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Jwks:
    def __init__(self, file: str = "", url: str = "", ttl_s: float = 3600.0, timeout_s: float = 5.0):
        self.file, self.url, self.ttl, self.timeout = file, url, ttl_s, timeout_s
        if url:
            u = urlparse(url)
            if u.scheme != "https" and not (u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1", "::1")):
                raise ValueError("LOGUNIFY_JWT_JWKS_URL must be https (plain http only for loopback)")
        self._keys: dict[str, dict] = {}
        self._fetched = 0.0
        self._last_miss_refresh = 0.0
        self._lk = threading.Lock()
        self.fetch_errors = 0

    @property
    def configured(self) -> bool:
        return bool(self.file or self.url)

    def _load(self, now: float) -> None:
        if self.file:
            doc = json.loads(Path(self.file).read_text(encoding="utf-8"))
        else:
            import httpx
            r = httpx.get(self.url, timeout=self.timeout, follow_redirects=False)
            r.raise_for_status()
            doc = r.json()
        keys = {k["kid"]: k for k in doc.get("keys", []) if k.get("kid") and k.get("kty") in ("RSA", "EC") and k.get("use", "sig") == "sig"}
        if not keys:
            raise ValueError("JWKS contains no usable signing keys")
        self._keys, self._fetched = keys, now

    def get(self, kid: str, now: float | None = None) -> dict | None:
        now = time.monotonic() if now is None else now
        with self._lk:
            stale = not self._keys or now - self._fetched > self.ttl
            if stale or (kid not in self._keys and now - self._last_miss_refresh > MIN_REFRESH_S):
                if kid not in self._keys and not stale:
                    self._last_miss_refresh = now
                try:
                    self._load(now)
                except Exception as e:                       # IdP down: keep serving from the cache, never crash a request
                    self.fetch_errors += 1
                    log.warning("JWKS refresh failed (%s); using cached keys", type(e).__name__)
                    self._fetched = now - self.ttl + 60       # retry in a minute, not on every request
            return self._keys.get(kid)


def _verify_signature(alg: str, jwk: dict, signing_input: bytes, sig: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    try:
        if alg == "RS256":
            key = rsa.RSAPublicNumbers(int.from_bytes(_b64(jwk["e"]), "big"), int.from_bytes(_b64(jwk["n"]), "big")).public_key()
            key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            if jwk.get("crv") != "P-256" or len(sig) != 64:
                return False
            key = ec.EllipticCurvePublicNumbers(int.from_bytes(_b64(jwk["x"]), "big"), int.from_bytes(_b64(jwk["y"]), "big"),
                                                ec.SECP256R1()).public_key()
            key.verify(utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                       signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


class TokenVerifier:
    def __init__(self, settings):
        self.s = settings
        self.secret = settings.jwt_secret.get_secret_value() if settings.jwt_secret else ""
        self.jwks = Jwks(settings.jwt_jwks_file, settings.jwt_jwks_url, settings.jwt_jwks_ttl_s)

    def verify(self, token: str, now: float | None = None) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenError("not a JWT")
        try:
            header = json.loads(_b64(parts[0]))
            claims = json.loads(_b64(parts[1]))
        except (ValueError, UnicodeDecodeError) as e:
            raise TokenError("malformed token") from e
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise TokenError("malformed token")
        alg = header.get("alg")
        if alg == "HS256":
            if not self.secret:
                raise TokenError("HS256 tokens are not accepted here")
            return tokens.decode(token, self.secret, self.s.jwt_issuer, self.s.jwt_audience, self.s.jwt_leeway_s, now)
        if alg in _ALGS and self.jwks.configured:
            jwk = self.jwks.get(str(header.get("kid", "")))
            if jwk is None or jwk.get("kty") != _ALGS[alg] or ("alg" in jwk and jwk["alg"] != alg):
                raise TokenError("unknown signing key")
            if not _verify_signature(alg, jwk, f"{parts[0]}.{parts[1]}".encode(), _b64(parts[2])):
                raise TokenError("bad signature")
            tokens.check_claims(claims, self.s.jwt_issuer, self.s.jwt_audience, self.s.jwt_leeway_s, now)
            return claims
        raise TokenError("unsupported algorithm")


class Revocations:
    """Revoked token ids and per-subject 'not before' marks. In memory for speed, SQLite for durability."""

    def __init__(self, path: str = ":memory:", refresh_s: float = 5.0):
        self.refresh_s, self._shared = refresh_s, path != ":memory:"
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS revoked_jti (jti TEXT PRIMARY KEY, exp REAL NOT NULL, by TEXT, ts REAL)")
        self._db.execute("CREATE TABLE IF NOT EXISTS revoked_sub (sub TEXT PRIMARY KEY, not_before REAL NOT NULL, by TEXT, ts REAL)")
        self._db.commit()
        self._lk = threading.Lock()
        self._jti: dict[str, float] = {}
        self._sub: dict[str, float] = {}
        self._loaded = 0.0
        self._reload()
        self.purge()

    def _reload(self, now: float | None = None) -> None:
        """Re-read the tables: another replica sharing the same file may have revoked something."""
        self._jti = {r[0]: r[1] for r in self._db.execute("SELECT jti, exp FROM revoked_jti")}
        self._sub = {r[0]: r[1] for r in self._db.execute("SELECT sub, not_before FROM revoked_sub")}
        self._loaded = time.monotonic() if now is None else now

    def revoke_jti(self, jti: str, exp: float, by: str) -> None:
        with self._lk:
            self._jti[jti] = exp
            self._db.execute("INSERT OR REPLACE INTO revoked_jti VALUES (?,?,?,?)", (jti, exp, by, time.time()))
            self._db.commit()

    def revoke_subject(self, sub: str, by: str, not_before: float | None = None) -> float:
        nb = time.time() if not_before is None else not_before
        with self._lk:
            self._sub[sub] = nb
            self._db.execute("INSERT OR REPLACE INTO revoked_sub VALUES (?,?,?,?)", (sub, nb, by, time.time()))
            self._db.commit()
        return nb

    def unrevoke_subject(self, sub: str) -> bool:
        with self._lk:
            had = self._sub.pop(sub, None) is not None
            self._db.execute("DELETE FROM revoked_sub WHERE sub=?", (sub,))
            self._db.commit()
        return had

    def is_revoked(self, claims: dict, now: float | None = None) -> str | None:
        t = time.monotonic() if now is None else now
        if self._shared and t - self._loaded > self.refresh_s:
            with self._lk:
                self._reload(t)
        jti, sub = claims.get("jti"), claims.get("sub")
        if jti and jti in self._jti:
            return "token revoked"
        nb = self._sub.get(sub)
        if nb is not None:
            iat = claims.get("iat")
            if not isinstance(iat, (int, float)) or iat < nb:        # no iat => cannot prove it is newer: treat as revoked
                return "subject's tokens revoked"
        return None

    def purge(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lk:
            for j in [j for j, e in self._jti.items() if e < now]:
                del self._jti[j]
            self._db.execute("DELETE FROM revoked_jti WHERE exp < ?", (now,))
            self._db.commit()

    def listing(self) -> dict:
        return {"jti": sorted(self._jti), "subjects": {k: v for k, v in self._sub.items()}}
