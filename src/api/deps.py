"""
FastAPI dependencies: authentication + RBAC + shared singletons.

Auth resolution order:
  1. ``Authorization: Bearer <token>`` (stateless HMAC token)
  2. ``X-API-Key: <secret>``
  3. ``X-Agent-ID: <id>`` — accepted ONLY when auth is not enforced
     (dev mode: no NETRA_API_KEYS configured).

Public endpoints (/, /health, /metrics, /dashboard, /docs…) skip auth.
"""

import logging

from fastapi import Depends, Header, HTTPException, Request

from src.core import security
from src.core.security import AuthContext, role_satisfies

logger = logging.getLogger("netra.auth")


def _unauthorized(detail: str) -> HTTPException:
    try:
        from src.core.metrics import metrics as registry

        registry.auth_failure()
    except Exception:
        pass
    return HTTPException(
        status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer, ApiKey"}
    )


async def get_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_agent_id: str | None = Header(default=None, alias="X-Agent-ID"),
) -> AuthContext:
    # 1. Bearer token
    if authorization and authorization.lower().startswith("bearer "):
        ctx = security.verify_access_token(authorization.split(" ", 1)[1].strip())
        if ctx:
            return ctx
        raise _unauthorized("Invalid or expired access token")
    # 2. API key
    if x_api_key:
        ctx = security.verify_api_key(x_api_key)
        if ctx:
            return ctx
        raise _unauthorized("Invalid API key")
    # 3. Dev-mode header
    if x_agent_id and not security.auth_enforced():
        return AuthContext(
            agent_id=x_agent_id, role=security.ROLE_ANALYST, auth_method="dev-header"
        )
    # 4. Nothing valid
    if security.auth_enforced():
        raise _unauthorized("Authentication required (Bearer token or X-API-Key)")
    # Auth not enforced and no identity supplied → anonymous analyst (local dev).
    return AuthContext(
        agent_id=x_agent_id or "anonymous", role=security.ROLE_ANALYST, auth_method="dev-header"
    )


def require_role(minimum: str):
    """Dependency factory enforcing an RBAC minimum role."""

    async def _guard(ctx: AuthContext = Depends(get_auth)) -> AuthContext:
        if not role_satisfies(ctx.role, minimum):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Insufficient privileges: '{minimum}' role required (you are '{ctx.role}')"
                ),
            )
        return ctx

    return _guard


require_viewer = require_role(security.ROLE_VIEWER)
require_analyst = require_role(security.ROLE_ANALYST)
require_admin = require_role(security.ROLE_ADMIN)
