import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    from datetime import timezone

    return datetime.now(timezone.utc)


class LegalAuthority(BaseModel):
    class Config:
        extra = "forbid"

    warrant_id: str
    issued_by: str
    expires_at: datetime
    scope: dict


class CaseIntakeRequest(BaseModel):
    class Config:
        extra = "forbid"

    case_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    legal_authority: LegalAuthority
    target_type: Literal["android", "cloud", "media", "network"]
    evidence_uri: str
    priority: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"


class Finding(BaseModel):
    class Config:
        extra = "forbid"

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    module: Literal["MODULE_A", "MODULE_B", "MODULE_C", "MODULE_D", "MODULE_E"]
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    title: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    raw_data: dict = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_utcnow)


def finding_to_dict(finding) -> dict:
    """Serialize a Finding across pydantic v1/v2."""
    if hasattr(finding, "model_dump"):
        return finding.model_dump(mode="json")
    if hasattr(finding, "dict"):
        return finding.dict()
    return dict(finding.__dict__)


# ─── Auth schemas ──────────────────────────────────────────────────────────
class TokenRequest(BaseModel):
    class Config:
        extra = "forbid"

    api_key: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    agent_id: str


class AuthContextModel(BaseModel):
    agent_id: str
    role: str
    auth_method: str


# ─── Case management schemas ───────────────────────────────────────────────
class CaseListItem(BaseModel):
    case_id: str
    target_type: str
    priority: str
    status: str
    findings_count: int = 0
    created_by: str | None = None
    created_at: str | None = None


class CaseListResponse(BaseModel):
    items: list[CaseListItem]
    total: int
    limit: int
    offset: int


class CaseSummary(BaseModel):
    case_id: str
    target_type: str | None = None
    priority: str | None = None
    status: str | None = None
    total_findings: int
    severity_breakdown: dict[str, int]
    module_breakdown: dict[str, int]
    chain_status: str
    court_admissibility: str
    created_by: str | None = None


class PaginatedFindings(BaseModel):
    items: list[dict]
    total: int
    limit: int
    offset: int
    case_id: str


class JobStatus(BaseModel):
    job_id: str
    status: Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED"]
    case_id: str
    created_at: str
    finished_at: str | None = None
    findings_count: int | None = None
    error: str | None = None


class AuditVerifyResponse(BaseModel):
    log_file: str
    entries: int
    chain_status: str
    failed_at: int | None = None


class HealthDetail(BaseModel):
    status: str
    version: str
    classification: str
    env: str
    auth_enforced: bool
    cache_backend: str
    otel_active: bool
    modules: list[str]
    cases_registered: int
    uptime_seconds: float
