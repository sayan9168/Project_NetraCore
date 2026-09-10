from datetime import datetime, timedelta, timezone

from src.core import security
from src.core.models import LegalAuthority


def _warrant(**kw):
    base = {
        "warrant_id": "W-1",
        "issued_by": "Court",
        "expires_at": datetime.now(timezone.utc) + timedelta(days=30),
        "scope": {"full_access": True},
    }
    base.update(kw)
    return LegalAuthority(**base)


def test_valid_warrant_full_access():
    ok, reason = security.validate_warrant(_warrant(), "network")
    assert ok is True


def test_expired_warrant_rejected():
    w = _warrant(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    ok, reason = security.validate_warrant(w, "network", enforce_expiry=True)
    assert ok is False and "expired" in reason.lower()


def test_expired_warrant_allowed_when_not_enforced():
    w = _warrant(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    ok, _ = security.validate_warrant(w, "network", enforce_expiry=False)
    assert ok is True


def test_scope_flag_authorizes_target():
    w = _warrant(scope={"network_forensics": True})
    ok, _ = security.validate_warrant(w, "network")
    assert ok is True
    ok, reason = security.validate_warrant(w, "android")
    assert ok is False and "scope" in reason.lower()


def test_missing_warrant_id_rejected():
    w = _warrant(warrant_id="  ")
    ok, _ = security.validate_warrant(w, "network")
    assert ok is False


def test_api_key_roles(monkeypatch):
    monkeypatch.setenv("NETRA_API_KEYS", "agent1:secret-analyst")
    monkeypatch.setenv("NETRA_ADMIN_KEYS", "root:secret-admin")
    analyst = security.verify_api_key("secret-analyst")
    assert analyst and analyst.role == "analyst" and analyst.agent_id == "agent1"
    admin = security.verify_api_key("secret-admin")
    assert admin and admin.role == "admin"
    assert security.verify_api_key("wrong") is None
    assert security.auth_enforced() is True


def test_token_roundtrip():
    token = security.create_access_token("agent-7", "analyst", ttl_seconds=600)
    ctx = security.verify_access_token(token)
    assert ctx and ctx.agent_id == "agent-7" and ctx.role == "analyst"


def test_token_tamper_rejected():
    token = security.create_access_token("agent-7", "analyst")
    body, sig = token.split(".")
    assert security.verify_access_token(body + ".AAAA") is None


def test_role_hierarchy():
    assert security.role_satisfies("admin", "viewer")
    assert security.role_satisfies("analyst", "analyst")
    assert not security.role_satisfies("viewer", "admin")
