"""Role-based access control: bearer JWT -> Principal(viewer | analyst | admin) -> per-route `guard(...)`.

  viewer   health, pipeline metrics, integrity summaries; never raw log content
  analyst  everything that exposes log/alert content: recent logs, anomalies, proofs, alerts + CERT-In drafts, TI matches
  admin    configuration and destructive/system actions: sources, IOC import, ledger anchoring, audit log

Modes (LOGUNIFY_AUTH_MODE): `off` (default; every caller is treated as `anonymous` admin, a startup warning is logged and
the audit log records auth=disabled) or `jwt` (Authorization: Bearer <token>; any failure is 401/403 and audited).
The legacy X-API-Key of the alert API keeps working for /api/v1/alerts* as an `analyst` credential.
Every guard writes an audit record (reads of polled endpoints are sampled, see audit.append).
"""
import logging
from dataclasses import dataclass

from fastapi import HTTPException, Request

from .tokens import MIN_SECRET_BYTES, TokenError

log = logging.getLogger("logunify.security")
ROLES = ("viewer", "analyst", "admin")
_RANK = {r: i for i, r in enumerate(ROLES)}


@dataclass(frozen=True)
class Principal:
    sub: str
    role: str
    auth: str           # jwt | api-key | disabled
    exp: float | None = None
    jti: str | None = None

    def allows(self, role: str) -> bool:
        return _RANK[self.role] >= _RANK[role]


def validate_settings(s) -> None:
    """Fail closed at startup: jwt mode without a strong secret must not silently run open."""
    if s.auth_mode not in ("off", "jwt"):
        raise ValueError("LOGUNIFY_AUTH_MODE must be 'off' or 'jwt'")
    if s.auth_mode == "jwt":
        has_secret = s.jwt_secret is not None
        has_jwks = bool(s.jwt_jwks_file or s.jwt_jwks_url)
        if not has_secret and not has_jwks:
            raise ValueError("auth_mode=jwt needs LOGUNIFY_JWT_SECRET (HS256) and/or LOGUNIFY_JWT_JWKS_FILE / LOGUNIFY_JWT_JWKS_URL (RS256, ES256)")
        if has_secret and len(s.jwt_secret.get_secret_value().encode()) < MIN_SECRET_BYTES:
            raise ValueError(f"LOGUNIFY_JWT_SECRET must be at least {MIN_SECRET_BYTES} bytes")
        if has_jwks and not (s.jwt_issuer and s.jwt_audience):
            raise ValueError("with a JWKS (a real IdP) set LOGUNIFY_JWT_ISSUER and LOGUNIFY_JWT_AUDIENCE: without them any token the "
                             "IdP signed for ANY application would be accepted here")
    else:
        log.warning("AUTH IS DISABLED (LOGUNIFY_AUTH_MODE=off): every API caller is treated as admin. Dev use only.")


def roles_from_claims(claims: dict, path: str) -> list[str]:
    """Follow a dotted claim path (`roles`, or Keycloak's `realm_access.roles`); accepts a list or a space/comma string."""
    node = claims
    for part in path.split("."):
        node = node.get(part) if isinstance(node, dict) else None
    if isinstance(node, str):
        node = node.replace(",", " ").split()
    return [r for r in node if isinstance(r, str)] if isinstance(node, list) else []


def _client(request: Request) -> str | None:
    h = getattr(request.app.state, "hardening", None)
    return h.client_ip(request) if h else (request.client.host if request.client else None)


def authenticate(request: Request, allow_api_key: bool = False) -> Principal:
    """Resolve the caller or raise HTTPException(401/403). Auth failures are audited by `guard`."""
    s = request.app.state.settings
    if allow_api_key and s.alert_api_key is not None:
        import hmac
        supplied = request.headers.get("x-api-key")
        if supplied and hmac.compare_digest(supplied.encode(), s.alert_api_key.get_secret_value().encode()):
            return Principal("api-key", "analyst", "api-key")
    if s.auth_mode == "off":
        return Principal("anonymous", "admin", "disabled")
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "Bearer token required", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = request.app.state.verifier.verify(token.strip())
    except TokenError as e:
        raise HTTPException(401, f"Invalid token: {e}", headers={"WWW-Authenticate": "Bearer"}) from None
    if (why := request.app.state.revocations.is_revoked(claims)):
        raise HTTPException(401, f"Invalid token: {why}", headers={"WWW-Authenticate": "Bearer"})
    roles = [r for r in roles_from_claims(claims, s.jwt_roles_claim) if r in _RANK]
    if not roles:
        raise HTTPException(403, "Token carries no LogUnify role (viewer, analyst or admin)")
    return Principal(claims["sub"], max(roles, key=_RANK.__getitem__), "jwt", claims.get("exp"), claims.get("jti"))


def guard(min_role: str, action: str | None = None, sample_s: float | dict = 0, allow_api_key: bool = False):
    """FastAPI dependency factory. `action` names the audit record; None = derive from the route name."""
    assert min_role in _RANK

    def dep(request: Request) -> Principal:
        audit = request.app.state.audit
        act = action or request.scope["route"].name
        path, client = request.url.path, _client(request)
        try:
            p = authenticate(request, allow_api_key)
        except HTTPException as e:
            audit.append("unauthenticated", "none", "none", act, path, "denied:401", client, {"reason": e.detail},
                         sample_s=30, sample_key=client)       # one row per client per 30 s; the rest are counted (`coalesced`)
            raise
        if not p.allows(min_role):
            audit.append(p.sub, p.role, p.auth, act, path, "denied:403", client, {"needs": min_role}, sample_s=30, sample_key=client)
            raise HTTPException(403, f"Requires role '{min_role}' (you are '{p.role}')")
        s = sample_s.get(act, 0) if isinstance(sample_s, dict) else sample_s
        audit.append(p.sub, p.role, p.auth, act, path, "allowed", client, {"method": request.method}, s)
        request.state.principal = p
        return p

    return dep
