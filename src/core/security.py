"""
Zero-Trust security layer for Project Netra-Core.

Provides (stdlib-only, no third-party dependencies):
  1. API-key authentication with constant-time comparison + role mapping.
  2. Stateless HMAC-signed access tokens (JWT-like, no library needed).
  3. Legal warrant validation — expiry + scope enforcement (the real legal gate).
  4. RBAC role hierarchy: viewer < analyst < admin.

When no API keys are configured the gateway runs in *dev mode*: requests
carrying an ``X-Agent-ID`` header are trusted as ``analyst``. The moment
``NETRA_API_KEYS`` is set, authentication is enforced on every endpoint
(except ``/``, ``/health`` and ``/metrics``).
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger("netra.security")

# ─── Roles ─────────────────────────────────────────────────────────────────
ROLE_VIEWER = "viewer"
ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"
_ROLE_RANK = {ROLE_VIEWER: 0, ROLE_ANALYST: 1, ROLE_ADMIN: 2}


def role_satisfies(granted: str, required: str) -> bool:
    """True if `granted` role meets or exceeds `required` role."""
    return _ROLE_RANK.get(granted, -1) >= _ROLE_RANK.get(required, 99)


@dataclass(frozen=True)
class AuthContext:
    agent_id: str
    role: str
    auth_method: str  # "api_key" | "token" | "dev-header"


# ─── API keys ──────────────────────────────────────────────────────────────
def _load_keys(env_var: str) -> tuple:
    raw = os.getenv(env_var, "")
    return tuple(k.strip() for k in raw.split(",") if k.strip())


def _fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def verify_api_key(provided: str) -> AuthContext | None:
    """
    Validate a raw API secret against configured keys.
    Returns an AuthContext with the mapped role, or None.
    Keys may be configured as ``secret`` or ``agent-id:secret``.
    """
    if not provided:
        return None
    admin_keys = _load_keys("NETRA_ADMIN_KEYS")
    api_keys = _load_keys("NETRA_API_KEYS")

    for configured in list(admin_keys) + list(api_keys):
        agent_id = "api-client"
        secret = configured
        if ":" in configured:
            agent_id, secret = configured.split(":", 1)
        if hmac.compare_digest(_fingerprint(provided), _fingerprint(secret)):
            role = ROLE_ADMIN if configured in admin_keys else ROLE_ANALYST
            return AuthContext(agent_id=agent_id, role=role, auth_method="api_key")
    return None


def auth_enforced() -> bool:
    return bool(_load_keys("NETRA_API_KEYS") or _load_keys("NETRA_ADMIN_KEYS"))


# ─── Stateless HMAC access tokens ──────────────────────────────────────────
def _token_secret() -> bytes:
    secret = os.getenv("NETRA_TOKEN_SECRET", "")
    if secret:
        return secret.encode()
    # Ephemeral dev secret (rotates every process start — tokens don't survive restarts).
    logger.warning("NETRA_TOKEN_SECRET not set — using ephemeral token secret (dev only)")
    return os.urandom(32)


_TOKEN_SECRET = None


def _get_token_secret() -> bytes:
    global _TOKEN_SECRET
    if _TOKEN_SECRET is None:
        _TOKEN_SECRET = _token_secret()
    return _TOKEN_SECRET


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def create_access_token(agent_id: str, role: str = ROLE_ANALYST, ttl_seconds: int = 3600) -> str:
    """Issue a stateless HMAC-SHA256 signed token: ``payload.signature``."""
    now = int(time.time())
    payload = {
        "sub": agent_id,
        "role": role,
        "iat": now,
        "exp": now + max(ttl_seconds, 60),
        "jti": uuid.uuid4().hex,
    }
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64e(hmac.new(_get_token_secret(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_access_token(token: str) -> AuthContext | None:
    """Verify a token issued by :func:`create_access_token`."""
    try:
        body, sig = token.split(".", 1)
        expected = _b64e(hmac.new(_get_token_secret(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig):
            return None
        payload = json.loads(_b64d(body))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        role = payload.get("role", ROLE_VIEWER)
        if role not in _ROLE_RANK:
            return None
        return AuthContext(
            agent_id=str(payload.get("sub", "unknown")), role=role, auth_method="token"
        )
    except Exception:
        return None


# ─── Warrant validation (the Zero-Trust legal gate) ────────────────────────
# Evidence target → accepted warrant scope flags (besides full_access).
_TARGET_SCOPE_FLAGS = {
    "android": ("android_logical_acquisition", "mobile_forensics"),
    "cloud": ("cloud_audit", "aws_audit"),
    "media": ("media_forensics", "image_analysis"),
    "network": ("network_forensics", "traffic_analysis"),
}


def _as_utc(dt) -> datetime | None:
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    if isinstance(dt, str):
        try:
            parsed = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            return None
    return None


def validate_warrant(
    legal_authority, target_type: str, enforce_expiry: bool = True
) -> tuple[bool, str]:
    """
    Validate the legal authority attached to a case intake request.

    Checks:
      1. warrant_id present
      2. warrant not expired (unless enforcement disabled)
      3. scope authorizes the requested target_type
    Returns (allowed, reason).
    """
    warrant_id = getattr(legal_authority, "warrant_id", "") or ""
    if not str(warrant_id).strip():
        return False, "Legal authority missing: warrant_id is required"

    if enforce_expiry:
        expires_at = _as_utc(getattr(legal_authority, "expires_at", None))
        if expires_at is None:
            return False, "Invalid warrant: expires_at is missing or unparseable"
        if expires_at < datetime.now(timezone.utc):
            return (
                False,
                f"Warrant {warrant_id} expired at {expires_at.isoformat()} — access denied",
            )

    scope = getattr(legal_authority, "scope", None) or {}
    if isinstance(scope, dict):
        if scope.get("full_access") is True:
            return True, "authorized: full_access"
        for flag in _TARGET_SCOPE_FLAGS.get(target_type, ()):
            if scope.get(flag) is True:
                return True, f"authorized: scope flag '{flag}'"
    return False, (
        f"Warrant {warrant_id} scope does not authorize target_type='{target_type}'. "
        f"Required: full_access or one of {list(_TARGET_SCOPE_FLAGS.get(target_type, ()))}"
    )
