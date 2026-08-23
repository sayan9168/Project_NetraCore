import logging
import json
import asyncio
import os
from fastapi import FastAPI, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from typing import List
from src.core.models import CaseIntakeRequest, Finding
from src.core.orchestrator import ForensicOrchestrator
from src.core.audit import ImmutableAuditLogger
from src.core.database import EvidenceVault
from src.core.report_generator import ForensicReportGenerator
from src.modules.module_a import AndroidTriageModule
from src.modules.module_b import SteganalysisModule
from src.modules.module_c import CloudAuditModule
from src.modules.module_d import LegalNLPModule

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(name)s | %(levelname)s | %(message)s')

app = FastAPI(title="Project Netra-Core API", version="5.0.0-Court-Ready")

# Dependency Injection
audit_logger = ImmutableAuditLogger()
vault = EvidenceVault()
modules = {
    "MODULE_A": AndroidTriageModule(),
    "MODULE_B": SteganalysisModule(),
    "MODULE_C": CloudAuditModule(),
    "MODULE_D": LegalNLPModule()
}

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_critical_event(self, message: dict):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)
        for conn in dead_connections:
            self.disconnect(conn)

manager = ConnectionManager()
orchestrator = ForensicOrchestrator(modules, audit_logger, vault, soc_manager=manager)

def get_orchestrator(): return orchestrator
def get_vault(): return vault

@app.on_event("startup")
async def startup_event():
    from seed_legal_db import seed_legal_vault
    if not os.path.exists("data/legal_knowledge.db"):
        seed_legal_vault()

@app.get("/")
async def root():
    return {
        "service": "Project Netra-Core", 
        "version": "5.0.0-Court-Ready",
        "status": "OPERATIONAL", 
        "endpoints": ["/v1/cases/intake", "/v1/cases/{id}/findings", "/v1/evidence/verify/{id}", "/v1/cases/{id}/report/pdf"]
    }

@app.post("/v1/cases/intake", response_model=List[Finding])
async def intake_case(
    request: CaseIntakeRequest,
    x_agent_id: str = Header(..., alias="X-Agent-ID"),
    orch: ForensicOrchestrator = Depends(get_orchestrator)
):
    if not request.legal_authority.warrant_id:
        raise HTTPException(status_code=403, detail="Access Denied.")
    return await orch.execute_case(request, actor=x_agent_id)

@app.get("/v1/cases/{case_id}/findings")
async def get_findings(case_id: str, v: EvidenceVault = Depends(get_vault)):
    findings = v.get_case_findings(case_id)
    if not findings:
        raise HTTPException(status_code=404, detail="No evidence found.")
    return findings

@app.get("/v1/evidence/verify/{case_id}")
async def verify_evidence_chain(case_id: str, v: EvidenceVault = Depends(get_vault)):
    chain_data = v.get_case_chain(case_id)
    if not chain_data:
        raise HTTPException(status_code=404, detail="No evidence chain found.")
        
    is_valid = True
    prev_hash = "GENESIS"
    
    for raw_json, db_prev_hash, db_current_hash, db_signature in chain_data:
        if db_prev_hash != prev_hash:
            is_valid = False
            break
        data_dict = json.loads(raw_json)
        if not v.seal.verify(data_dict, db_prev_hash, db_current_hash, db_signature):
            is_valid = False
            break
        prev_hash = db_current_hash
        
    return {
        "case_id": case_id,
        "chain_status": "INTACT" if is_valid else "TAMPERED",
        "court_admissibility": "VALID" if is_valid else "REJECTED"
    }

@app.get("/v1/cases/{case_id}/report/pdf")
async def download_forensic_report(case_id: str, v: EvidenceVault = Depends(get_vault)):
    """
    Court Admissibility Endpoint.
    Generates and downloads a formal PDF report with cryptographic appendix.
    """
    generator = ForensicReportGenerator(v)
    output_dir = "data/reports"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"{case_id}_forensic_report.pdf")
    
    result = generator.generate_pdf(case_id, output_path)
    
    if result["status"] == "ERROR":
        raise HTTPException(status_code=404, detail=result["message"])
        
    return FileResponse(
        output_path, 
        media_type="application/pdf",
        filename=f"NetraCore_Report_{case_id}.pdf"
    )

@app.websocket("/ws/soc-dashboard")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"status": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
