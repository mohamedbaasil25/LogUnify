"""Who am I, and token revocation (admin)."""
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, model_validator

from ..security.rbac import Principal, guard

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.get("/me")
def me(p: Principal = Depends(guard("viewer", "auth.me", sample_s=300))):
    """The identity this API sees for your credentials: what the dashboard shows and uses to hide actions you may not perform."""
    return {"sub": p.sub, "role": p.role, "auth": p.auth, "exp": p.exp,
            "expires_in_s": None if p.exp is None else max(0, int(p.exp - time.time()))}


class RevokeBody(BaseModel):
    sub: str | None = Field(None, max_length=200, description="revoke every token of this subject issued before now")
    jti: str | None = Field(None, max_length=200, description="revoke one token by its jti claim")
    exp: float | None = Field(None, description="that token's exp (so the entry can be dropped when the token would expire anyway)")

    @model_validator(mode="after")
    def _one(self):
        if (self.sub is None) == (self.jti is None):
            raise ValueError("provide exactly one of `sub` or `jti`")
        return self


@router.post("/revoke", dependencies=[Depends(guard("admin", "auth.revoke"))])
def revoke(body: RevokeBody, request: Request):
    """Revoke tokens inside THIS API (it does not sign the user out of the identity provider). Tokens need `jti` (single) or `iat` (per subject)."""
    rv, by = request.app.state.revocations, request.state.principal.sub
    if body.sub:
        return {"revoked": "subject", "sub": body.sub, "not_before": rv.revoke_subject(body.sub, by)}
    rv.revoke_jti(body.jti, body.exp or time.time() + 86400, by)
    return {"revoked": "jti", "jti": body.jti}


@router.delete("/revoke/subject/{sub}", dependencies=[Depends(guard("admin", "auth.unrevoke"))])
def unrevoke(sub: str, request: Request):
    if not request.app.state.revocations.unrevoke_subject(sub):
        raise HTTPException(404, "that subject is not revoked")
    return {"restored": sub}


@router.get("/revoked", dependencies=[Depends(guard("admin", "auth.revoked.list"))])
def revoked(request: Request):
    return request.app.state.revocations.listing()
