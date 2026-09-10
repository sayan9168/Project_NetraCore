"""
Project Netra-Core — Production Enterprise API Gateway.

v6.2.0 highlights:
  * API-key + HMAC-token auth with RBAC (viewer / analyst / admin)
  * Real zero-trust warrant gate (expiry + scope enforcement)
  * Case registry: list / summary / search / delete / export
  * Async case intake with background job tracking
  * RSA-signed court reports, audit-chain verification
  * Prometheus /metrics, security headers, request IDs, CORS
  * Static SOC dashboard served at /dashboard
"""

import logging
import os
import time
import traceback
from contextlib import asynccontextmanager

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from src.api.deps import get_auth, require_admin, require_analyst, require_viewer
from src.core import security
from src.core.audit import ImmutableAuditLogger
from src.core.cache import get_cache
from src.core.config import settings
from src.core.database import EvidenceVault
from src.core.metrics import metrics as registry
from src.core.middleware import RequestIDMiddleware, SecurityHeadersMiddleware, TelemetryMiddleware
from src.core.models import (
    AuditVerifyResponse,
    CaseIntakeRequest,
    CaseListItem,
    CaseListResponse,
    CaseSummary,
    Finding,
    HealthDetail,
    JobStatus,
    PaginatedFindings,
    TokenRequest,
    TokenResponse,
)
from src.core.orchestrator import ForensicOrchestrator
from src.core.report_generator import ForensicReportGenerator
from src.modules.module_a import AndroidTriageModule
from src.modules.module_b import SteganalysisModule
from src.modules.module_c import CloudAuditModule
from src.modules.module_d import LegalNLPModule
from src.modules.module_e import NetworkIOCModule

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("netra.api")

BOOT_TIME = time.time()

# ─── Rate Limiter ──────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Netra-Core v{settings.version} starting | {settings.redacted()}")
    try:
        from seed_legal_db import seed_legal_vault

        if not os.path.exists(settings.legal_db_path):
            seed_legal_vault(settings.legal_db_path)
    except Exception as exc:
        logger.warning(f"Legal DB seed skipped: {exc}")
    yield
    logger.info("Netra-Core shutting down")


app = FastAPI(
    title="Project Netra-Core API",
    version=settings.version,
    description="Government Cyber-Defense & Forensic Engine — RESTRICTED",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── Middleware stack ──────────────────────────────────────────────────────
app.add_middleware(TelemetryMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# ─── Global Exception Handler ──────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_id = os.urandom(8).hex()
    logger.error(f"Unhandled exception [{error_id}]: {exc}\n{traceback.format_exc()}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "error_id": error_id,
            "detail": str(exc) if not settings.is_production else "Contact SOC operator",
            "type": exc.__class__.__name__,
        },
    )


# ─── Optional Observability ────────────────────────────────────────────────
try:
    from src.core.observability import setup_observability, traced

    setup_observability(app, otlp_endpoint=settings.otlp_endpoint or None)
    OTEL_ON = True
except ImportError:

    def traced(name=None):
        def d(fn):
            return fn

        return d

    OTEL_ON = False
    logger.info("OpenTelemetry not available")


# ─── Dependencies ──────────────────────────────────────────────────────────
audit_logger = ImmutableAuditLogger(log_dir=settings.audit_log_dir)
vault = EvidenceVault(db_path=settings.vault_db_path)

modules = {
    "MODULE_A": AndroidTriageModule(),
    "MODULE_B": SteganalysisModule(),
    "MODULE_C": CloudAuditModule(),
    "MODULE_D": LegalNLPModule(),
    "MODULE_E": NetworkIOCModule(
        feed_path=settings.threat_feed_path, max_read_mb=settings.max_evidence_read_mb
    ),
}


class ConnectionManager:
    def __init__(self):
        self.active_connections: list = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        registry.ws_connect(1)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            registry.ws_connect(-1)

    async def broadcast_critical_event(self, message: dict):
        dead = []
        for conn in self.active_connections:
            try:
                await conn.send_json(message)
            except Exception:
                dead.append(conn)
        for c in dead:
            self.disconnect(c)


manager = ConnectionManager()
orchestrator = ForensicOrchestrator(
    modules,
    audit_logger,
    vault,
    soc_manager=manager,
    module_timeout=settings.module_timeout_seconds,
    module_retries=settings.module_retries,
)


def get_orchestrator():
    return orchestrator


def get_vault():
    return vault


# ═══════════════════════════════════════════════════════════════════════════
#  Public endpoints
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/", tags=["system"])
@limiter.limit("60/minute")
async def root(request: Request):
    return {
        "service": settings.app_name,
        "version": settings.version,
        "status": "OPERATIONAL",
        "classification": settings.classification,
        "env": settings.env,
        "otel_active": OTEL_ON,
        "auth_enforced": security.auth_enforced(),
        "features": [
            "Zero-Trust Legal Gate (expiry + scope)",
            "API-Key / Token Auth + RBAC",
            "HMAC-SHA256 Evidence Ledger",
            "Async DAG Orchestrator (A/B/C/D/E)",
            "Network IOC Forensics (Module E)",
            "Rate Limiting (SlowAPI)",
            "WebSocket SOC Alerts",
            "FTS5 Legal NLP",
            "RSA-Signed Court Reports",
            "Prometheus Metrics",
            "Case Registry + Evidence Export",
        ],
    }


@app.get("/health", tags=["system"])
async def health():
    return {"status": "OPERATIONAL", "classification": "RESTRICTED"}


@app.get("/v2/health", response_model=HealthDetail, tags=["system"])
async def health_detail():
    cache = get_cache()
    return HealthDetail(
        status="OPERATIONAL",
        version=settings.version,
        classification=settings.classification,
        env=settings.env,
        auth_enforced=security.auth_enforced(),
        cache_backend=cache.backend,
        otel_active=OTEL_ON,
        modules=sorted(modules.keys()),
        cases_registered=vault.count_cases(),
        uptime_seconds=round(time.time() - BOOT_TIME, 1),
    )


@app.get("/metrics", tags=["system"])
async def prometheus_metrics():
    return PlainTextResponse(registry.render_prometheus(), media_type="text/plain; version=0.0.4")


@app.get("/dashboard", tags=["system"])
async def dashboard():
    path = os.path.join(os.getcwd(), "dashboard.html")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Dashboard not deployed")
    return FileResponse(path, media_type="text/html")


# ═══════════════════════════════════════════════════════════════════════════
#  Auth
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/v1/auth/token", response_model=TokenResponse, tags=["auth"])
@limiter.limit("10/minute")
async def issue_token(request: Request, body: TokenRequest):
    ctx = security.verify_api_key(body.api_key)
    if not ctx:
        registry.auth_failure()
        raise HTTPException(status_code=401, detail="Invalid API key")
    token = security.create_access_token(
        ctx.agent_id, ctx.role, ttl_seconds=settings.token_ttl_seconds
    )
    audit_logger.record(ctx.agent_id, "TOKEN_ISSUED", ctx.agent_id, {"role": ctx.role})
    return TokenResponse(
        access_token=token,
        expires_in=settings.token_ttl_seconds,
        role=ctx.role,
        agent_id=ctx.agent_id,
    )


@app.get("/v1/auth/me", tags=["auth"])
async def whoami(ctx=Depends(get_auth)):
    return {"agent_id": ctx.agent_id, "role": ctx.role, "auth_method": ctx.auth_method}


# ═══════════════════════════════════════════════════════════════════════════
#  Case intake (sync + async)
# ═══════════════════════════════════════════════════════════════════════════
def _enforce_warrant(case_request: CaseIntakeRequest, actor: str) -> None:
    allowed, reason = security.validate_warrant(
        case_request.legal_authority,
        case_request.target_type,
        enforce_expiry=settings.enforce_warrant_expiry,
    )
    audit_logger.record(
        actor,
        "WARRANT_CHECK",
        case_request.case_id,
        {"reason": reason, "target": case_request.target_type},
        status="SUCCESS" if allowed else "DENIED",
    )
    if not allowed:
        raise HTTPException(status_code=403, detail=f"Warrant rejected: {reason}")


@app.post("/v1/cases/intake", response_model=list[Finding], tags=["cases"])
@limiter.limit("30/minute")
@traced("case_intake")
async def intake_case(
    request: Request,
    case_request: CaseIntakeRequest,
    ctx=Depends(require_analyst),
    orch: ForensicOrchestrator = Depends(get_orchestrator),
):
    _enforce_warrant(case_request, ctx.agent_id)
    return await orch.execute_case(case_request, actor=ctx.agent_id)


@app.post("/v1/cases/intake/async", response_model=JobStatus, status_code=202, tags=["cases"])
@limiter.limit("30/minute")
async def intake_case_async(
    request: Request,
    case_request: CaseIntakeRequest,
    ctx=Depends(require_analyst),
    orch: ForensicOrchestrator = Depends(get_orchestrator),
):
    """Queue a case for background execution; poll /v1/jobs/{id}."""
    _enforce_warrant(case_request, ctx.agent_id)
    return orch.submit_case(case_request, actor=ctx.agent_id)


@app.get("/v1/jobs/{job_id}", response_model=JobStatus, tags=["cases"])
@limiter.limit("60/minute")
async def get_job(
    request: Request,
    job_id: str,
    ctx=Depends(require_viewer),
    orch: ForensicOrchestrator = Depends(get_orchestrator),
):
    job = orch.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


# ═══════════════════════════════════════════════════════════════════════════
#  Case registry & findings
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/v1/cases", response_model=CaseListResponse, tags=["cases"])
@limiter.limit("60/minute")
async def list_cases(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    priority: str | None = Query(None),
    target_type: str | None = Query(None),
    ctx=Depends(require_viewer),
    v: EvidenceVault = Depends(get_vault),
):
    rows, total = v.list_cases(
        limit=limit, offset=offset, priority=priority, target_type=target_type
    )
    return CaseListResponse(
        items=[
            CaseListItem(
                **{
                    k: r.get(k)
                    for k in (
                        "case_id",
                        "target_type",
                        "priority",
                        "status",
                        "findings_count",
                        "created_by",
                        "created_at",
                    )
                }
            )
            for r in rows
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get("/v1/cases/{case_id}/findings", tags=["findings"])
@limiter.limit("60/minute")
async def get_findings(
    request: Request,
    case_id: str,
    severity: str | None = Query(None),
    module: str | None = Query(None),
    q: str | None = Query(None, description="Full-text search in title/payload"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ctx=Depends(require_viewer),
    v: EvidenceVault = Depends(get_vault),
):
    items, total = v.search_findings(
        case_id, query=q, severity=severity, module=module, limit=limit, offset=offset
    )
    if total == 0 and offset == 0:
        # Backward-compat: legacy clients expect 404 when a case has no findings.
        raise HTTPException(status_code=404, detail="No evidence found")
    return PaginatedFindings(items=items, total=total, limit=limit, offset=offset, case_id=case_id)


@app.get("/v1/cases/{case_id}/summary", response_model=CaseSummary, tags=["cases"])
@limiter.limit("60/minute")
async def case_summary(
    request: Request,
    case_id: str,
    ctx=Depends(require_viewer),
    v: EvidenceVault = Depends(get_vault),
):
    stats = v.get_case_stats(case_id)
    if stats["total"] == 0 and v.get_case_meta(case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    verification = v.verify_chain(case_id)
    meta = v.get_case_meta(case_id) or {}
    return CaseSummary(
        case_id=case_id,
        target_type=meta.get("target_type"),
        priority=meta.get("priority"),
        status=meta.get("status"),
        total_findings=stats["total"],
        severity_breakdown=stats["severity_breakdown"],
        module_breakdown=stats["module_breakdown"],
        chain_status=verification["chain_status"],
        court_admissibility=verification["court_admissibility"],
        created_by=meta.get("created_by"),
    )


@app.delete("/v1/cases/{case_id}", tags=["cases"])
@limiter.limit("10/minute")
async def delete_case(
    request: Request,
    case_id: str,
    ctx=Depends(require_admin),
    v: EvidenceVault = Depends(get_vault),
):
    removed = v.delete_case(case_id)
    audit_logger.record(ctx.agent_id, "CASE_DELETED", case_id, {"findings_removed": removed})
    try:
        get_cache().invalidate_prefix(f"case:{case_id}")
    except Exception:
        pass
    return {"case_id": case_id, "deleted": True, "findings_removed": removed}


@app.get("/v1/cases/{case_id}/export", tags=["cases"])
@limiter.limit("10/minute")
async def export_case(
    request: Request,
    case_id: str,
    ctx=Depends(require_viewer),
    v: EvidenceVault = Depends(get_vault),
):
    bundle = v.export_case_bundle(case_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Case not found")
    audit_logger.record(
        ctx.agent_id, "CASE_EXPORTED", case_id, {"records": bundle["verification"]["records"]}
    )
    return bundle


# ═══════════════════════════════════════════════════════════════════════════
#  Evidence verification & reports
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/v1/evidence/verify/{case_id}", tags=["evidence"])
@limiter.limit("30/minute")
async def verify_evidence_chain(
    request: Request,
    case_id: str,
    ctx=Depends(require_viewer),
    v: EvidenceVault = Depends(get_vault),
):
    result = v.verify_chain(case_id)
    if result["records"] == 0:
        raise HTTPException(status_code=404, detail="No chain")
    return result


@app.get("/v1/cases/{case_id}/report/pdf", tags=["reports"])
@limiter.limit("5/minute")
async def download_report(
    request: Request,
    case_id: str,
    ctx=Depends(require_viewer),
    v: EvidenceVault = Depends(get_vault),
):
    generator = ForensicReportGenerator(v)
    out = os.path.join(settings.report_dir, f"{case_id}.pdf")
    os.makedirs(settings.report_dir, exist_ok=True)
    result = generator.generate_pdf(case_id, out)
    if result["status"] == "ERROR":
        raise HTTPException(status_code=404, detail=result["message"])
    audit_logger.record(ctx.agent_id, "REPORT_GENERATED", case_id, {"path": out, "signed": False})
    return FileResponse(out, media_type="application/pdf", filename=f"NetraCore_{case_id}.pdf")


@app.get("/v1/cases/{case_id}/report/signed", tags=["reports"])
@limiter.limit("5/minute")
async def download_signed_report(
    request: Request,
    case_id: str,
    ctx=Depends(require_analyst),
    v: EvidenceVault = Depends(get_vault),
):
    """Generate an RSA-4096 signed court report + detached signature sidecar."""
    try:
        from src.core.report_generator import ForensicReportGeneratorSigned
    except ImportError as exc:
        raise HTTPException(status_code=501, detail=f"Signing engine unavailable: {exc}") from exc
    try:
        generator = ForensicReportGeneratorSigned(v)
    except ImportError as exc:
        raise HTTPException(status_code=501, detail=f"Signing engine unavailable: {exc}") from exc
    out = os.path.join(settings.report_dir, f"{case_id}.signed.pdf")
    os.makedirs(settings.report_dir, exist_ok=True)
    result = generator.generate_signed_pdf(case_id, out)
    if result["status"] == "ERROR":
        raise HTTPException(status_code=404, detail=result["message"])
    audit_logger.record(ctx.agent_id, "REPORT_GENERATED", case_id, {"path": out, "signed": True})
    return FileResponse(
        out, media_type="application/pdf", filename=f"NetraCore_{case_id}.signed.pdf"
    )


@app.get("/v1/cases/{case_id}/report/signature", tags=["reports"])
@limiter.limit("30/minute")
async def report_signature(request: Request, case_id: str, ctx=Depends(require_viewer)):
    """Fetch the detached signature sidecar for a signed report."""
    import json as _json

    sidecar = os.path.join(settings.report_dir, f"{case_id}.signed.pdf.sig")
    if not os.path.exists(sidecar):
        raise HTTPException(status_code=404, detail="No signed report for this case yet")
    with open(sidecar) as f:
        return _json.load(f)


# ═══════════════════════════════════════════════════════════════════════════
#  Audit
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/v1/audit/verify", response_model=AuditVerifyResponse, tags=["audit"])
@limiter.limit("30/minute")
async def verify_audit(
    request: Request,
    log_file: str | None = Query(None, description="Basename e.g. audit_20260910.jsonl"),
    ctx=Depends(require_viewer),
):
    path = None
    if log_file:
        safe = os.path.basename(log_file)
        path = os.path.join(audit_logger.log_dir, safe)
    return audit_logger.verify_chain(path)


@app.get("/v1/audit/recent", tags=["audit"])
@limiter.limit("30/minute")
async def recent_audit(
    request: Request, limit: int = Query(50, ge=1, le=500), ctx=Depends(require_viewer)
):
    return {"entries": audit_logger.read_entries(limit=limit)}


@app.get("/v1/stats", tags=["system"])
@limiter.limit("30/minute")
async def global_stats(
    request: Request, ctx=Depends(require_viewer), v: EvidenceVault = Depends(get_vault)
):
    stats = v.global_stats()
    stats["runtime"] = registry.snapshot()
    return stats


# ═══════════════════════════════════════════════════════════════════════════
#  WebSocket SOC stream
# ═══════════════════════════════════════════════════════════════════════════
@app.websocket("/ws/soc-dashboard")
async def ws_endpoint(websocket: WebSocket, token: str | None = None):
    # Optional token auth when auth is enforced (?token=...).
    if security.auth_enforced():
        if not token or not security.verify_access_token(token):
            await websocket.close(code=4401)
            return
    await manager.connect(websocket)
    try:
        await websocket.send_json(
            {"event_type": "CONNECTED", "service": "Netra-Core SOC", "version": settings.version}
        )
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"status": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
