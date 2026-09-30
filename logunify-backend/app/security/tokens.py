"""Minimal JWT (HS256) verification for bearer auth. Stdlib only.

Scope, stated plainly: this validates tokens signed with a SHARED secret (HS256): what a small deployment, a gateway that
mints its own tokens, and the tests use. It does NOT fetch a JWKS or verify RS256/ES256 tokens, which is what a real
Keycloak / Entra ID issues by default. To plug in an IdP, swap `decode()` for PyJWT + JWKS; `Principal` extraction and RBAC
are IdP-agnostic and unchanged.

Hardening: the algorithm is pinned (`none` and anything but HS256 rejected, so no alg-confusion), `exp` is mandatory,
`nbf`/`iss`/`aud` are checked when configured, and the signature is compared in constant time.
"""
import base64
import hashlib
import hmac
import json
import time

MIN_SECRET_BYTES = 32


class TokenError(Exception):
    """Invalid, expired or malformed token. The message is safe to log (never contains the token)."""


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception as e:
        raise TokenError("malformed base64") from e


def encode(claims: dict, secret: str) -> str:
    """Mint an HS256 token (used by tests and `python -m app.security.mint`; a real IdP normally issues these)."""
    head = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64e(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64e(sig)}"


def decode(token: str, secret: str, issuer: str = "", audience: str = "", leeway: int = 30,
           now: float | None = None) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("not a JWT")
    try:
        header = json.loads(_b64d(parts[0]))
        claims = json.loads(_b64d(parts[1]))
    except (ValueError, UnicodeDecodeError) as e:
        raise TokenError("malformed token") from e
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise TokenError("malformed token")
    if header.get("alg") != "HS256":
        raise TokenError("unsupported algorithm (only HS256 is accepted)")
    expected = hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64d(parts[2])):
        raise TokenError("bad signature")
    t = time.time() if now is None else now
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise TokenError("missing exp")
    if t > exp + leeway:
        raise TokenError("token expired")
    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and t + leeway < nbf:
        raise TokenError("token not yet valid")
    if issuer and claims.get("iss") != issuer:
        raise TokenError("wrong issuer")
    if audience:
        aud = claims.get("aud")
        if audience not in (aud if isinstance(aud, list) else [aud]):
            raise TokenError("wrong audience")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise TokenError("missing sub")
    return claims
