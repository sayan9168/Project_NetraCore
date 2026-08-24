"""
Production Enterprise API Gateway v6.1.2 - Full Error Handling
"""
import logging
import json
import os
import traceback
from fastapi import FastAPI, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import FileResponse, JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from typing import List

from src.core.models import CaseIntakeRequest, Finding
from src.core.orchestrator import ForensicOrchestrator
from src.core.audit import ImmutableAuditLogger
from src.core.database import EvidenceVault
from src.core.report_generator import ForensicReportGenerator

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(name)s | %(levelname)s | %(message)s')
logger = logging.getLogger("netra.api")

# ─── Rate Limiter ──────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Project Netra-Core API",
    version="6.1.2-ErrorSafe",
    description="Government Cyber-Defense & Forensic Engine"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ─── Global Exception Handler (catches ALL unhandled errors) ───────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catches any unhandled exception and returns structured JSON error."""
    error_id = os.urandom(8).hex()
    tb = traceback.format_exc()
    logger.error(f"Unhandled exception [{error_id}]: {exc}\n{tb}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "error_id": error_id,
            "detail": str(exc),
            "type": exc.__class__.__name__
        }
    )


# ─── Optional Observability ────────────────────────────────────────────────
try:
    from src.core.observability import setup_observability, traced
    setup_observability(app, otlp_endpoint=os.getenv("OTLP_ENDPOINT"))
    OTEL_ON = True
except ImportError:
    def traced(name=None):
        def d(fn): return fn
        return d
    OTEL_ON = False
    logger.info("OpenTelemetry not available")


# ─── Dependencies ──────────────────────────────────────────────────────────
audit_logger = ImmutableAuditLogger()
vault = EvidenceVault()

from src.modules.module_a import AndroidTriageModule
from src.modules.module_b import SteganalysisModule
from src.modules.module_c import CloudAuditModule
from src.modules.module_d import LegalNLPModule

modules = {
    "MODULE_A": AndroidTriageModule(),
    "MODULE_B": SteganalysisModule(),
    "MODULE_C": CloudAuditModule(),
    "MODULE_D": LegalNLPModule(),
}


class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

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
orchestrator = ForensicOrchestrator(modules, audit_logger, vault, soc_manager=manager)


def get_orchestrator(): return orchestrator
def get_vault(): return vault


@app.on_event("startup")
async def startup_event():
    from seed_legal_db import seed_legal_vault
    if not os.path.exists("data/legal_knowledge.db"):
        seed_legal_vault()
    logger.info("API v6.1.2 started with global error handler")


# ─── Endpoints ─────────────────────────────────────────────────────────────

@app.get("/")
@limiter.limit("60/minute")
async def root(request: Request):
    return {
        "service": "Project Netra-Core",
        "version": "6.1.2-ErrorSafe",
        "status": "OPERATIONAL",
        "otel_active": OTEL_ON,
        "features": [
            "Zero-Trust Legal Gate",
            "HMAC-SHA256 Evidence Ledger",
            "Rate Limiting (SlowAPI)",
            "WebSocket SOC Alerts",
            "FTS5 Legal NLP",
            "Pure Python Image Forensics",
            "Global Error Handler"
        ]
    }


@app.get("/health")
async def health():
    return {"status": "OPERATIONAL", "classification": "RESTRICTED"}


@app.post("/v1/cases/intake", response_model=List[Finding])
@limiter.limit("30/minute")
@traced("case_intake")
async def intake_case(
    request: Request,
    case_request: CaseIntakeRequest,
    x_agent_id: str = Header(..., alias="X-Agent-ID"),
    orch: ForensicOrchestrator = Depends(get_orchestrator),
):
    if not case_request.legal_authority.warrant_id:
        raise HTTPException(status_code=403, detail="Legal authority missing")
    return await orch.execute_case(case_request, actor=x_agent_id)


@app.get("/v1/cases/{case_id}/findings")
@limiter.limit("60/minute")
async def get_findings(request: Request, case_id: str, v: EvidenceVault = Depends(get_vault)):
    findings = v.get_case_findings(case_id)
    if not findings:
        raise HTTPException(status_code=404, detail="No evidence found")
    return findings


@app.get("/v1/evidence/verify/{case_id}")
@limiter.limit("30/minute")
async def verify_evidence_chain(request: Request, case_id: str, v: EvidenceVault = Depends(get_vault)):
    chain = v.get_case_chain(case_id)
    if not chain:
        raise HTTPException(status_code=404, detail="No chain")
    valid, prev = True, "GENESIS"
    for raw, p, c, sig in chain:
        if p != prev or not v.seal.verify(json.loads(raw), p, c, sig):
            valid = False
            break
        prev = c
    return {
        "case_id": case_id,
        "chain_status": "INTACT" if valid else "TAMPERED",
        "court_admissibility": "VALID" if valid else "REJECTED",
        "records": len(chain)
    }


@app.get("/v1/cases/{case_id}/report/pdf")
@limiter.limit("5/minute")
async def download_report(request: Request, case_id: str, v: EvidenceVault = Depends(get_vault)):
    generator = ForensicReportGenerator(v)
    out = f"data/reports/{case_id}.pdf"
    os.makedirs("data/reports", exist_ok=True)
    result = generator.generate_pdf(case_id, out)
    if result["status"] == "ERROR":
        raise HTTPException(status_code=404, detail=result["message"])
    return FileResponse(out, media_type="application/pdf", filename=f"NetraCore_{case_id}.pdf")


@app.websocket("/ws/soc-dashboard")
async def ws_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"status": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
