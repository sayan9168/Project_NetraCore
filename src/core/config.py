"""
Centralized application configuration for Project Netra-Core.

All settings are overridable via environment variables (12-factor style).
See config/environments/.env.example for the full list.

Zero third-party dependencies by design — this module must import anywhere.
"""

import os
from dataclasses import dataclass, field


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        return default


def _env_bool(key: str, default: bool) -> bool:
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _env_list(key: str, default: str = "") -> list:
    raw = os.getenv(key, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    """Immutable application settings snapshot."""

    # ── Identity ──────────────────────────────────────────────────────────
    app_name: str = "Project Netra-Core"
    version: str = "6.2.0"
    env: str = _env("ENV", "development")
    classification: str = "RESTRICTED / LAW-ENFORCEMENT GRADE"

    # ── Paths ─────────────────────────────────────────────────────────────
    vault_db_path: str = _env("NETRA_VAULT_DB", "data/netra_vault.db")
    legal_db_path: str = _env("NETRA_LEGAL_DB", "data/legal_knowledge.db")
    audit_log_dir: str = _env("NETRA_AUDIT_DIR", "logs/audit")
    report_dir: str = _env("NETRA_REPORT_DIR", "data/reports")
    threat_feed_path: str = _env("NETRA_THREAT_FEED", "data/threat_feed.json")

    # ── Security / Auth ───────────────────────────────────────────────────
    # Comma-separated API secrets. When empty → dev mode (X-Agent-ID trusted).
    api_keys: tuple = field(default_factory=lambda: tuple(_env_list("NETRA_API_KEYS")))
    admin_keys: tuple = field(default_factory=lambda: tuple(_env_list("NETRA_ADMIN_KEYS")))
    token_secret: str = _env("NETRA_TOKEN_SECRET", "")
    token_ttl_seconds: int = _env_int("NETRA_TOKEN_TTL", 3600)
    # Reject cases whose warrant has expired (zero-trust legal gate).
    enforce_warrant_expiry: bool = _env_bool("NETRA_ENFORCE_WARRANT_EXPIRY", True)
    # Allowed CORS origins (comma-separated). Empty = same-origin only.
    cors_origins: tuple = field(default_factory=lambda: tuple(_env_list("NETRA_CORS_ORIGINS")))

    # ── Orchestrator ──────────────────────────────────────────────────────
    module_timeout_seconds: float = _env_float("NETRA_MODULE_TIMEOUT", 120.0)
    module_retries: int = _env_int("NETRA_MODULE_RETRIES", 1)
    max_evidence_read_mb: int = _env_int("NETRA_MAX_EVIDENCE_MB", 8)

    # ── Cache / Queue ─────────────────────────────────────────────────────
    redis_url: str = _env("REDIS_URL", "")
    cache_ttl_seconds: int = _env_int("NETRA_CACHE_TTL", 300)

    # ── Observability ─────────────────────────────────────────────────────
    otlp_endpoint: str = _env("OTLP_ENDPOINT", "")
    log_level: str = _env("LOG_LEVEL", "INFO")

    # ── Rate limits ───────────────────────────────────────────────────────
    rate_limit_intake: str = _env("NETRA_RL_INTAKE", "30/minute")
    rate_limit_read: str = _env("NETRA_RL_READ", "60/minute")
    rate_limit_report: str = _env("NETRA_RL_REPORT", "5/minute")

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"

    @property
    def auth_enforced(self) -> bool:
        """Auth is enforced only when API keys are configured."""
        return len(self.api_keys) > 0

    def redacted(self) -> dict:
        """Safe-to-log representation (secrets masked)."""
        return {
            "app_name": self.app_name,
            "version": self.version,
            "env": self.env,
            "auth_enforced": self.auth_enforced,
            "admin_keys_configured": len(self.admin_keys) > 0,
            "enforce_warrant_expiry": self.enforce_warrant_expiry,
            "module_timeout_seconds": self.module_timeout_seconds,
            "redis_configured": bool(self.redis_url),
            "otlp_configured": bool(self.otlp_endpoint),
        }


settings = Settings()
