import asyncio
import logging
from typing import List, Dict, Any
from src.core.models import CaseIntakeRequest, Finding
from src.core.audit import ImmutableAuditLogger
from src.core.database import EvidenceVault

logger = logging.getLogger("netra.orchestrator")

class ForensicOrchestrator:
    def __init__(self, modules: Dict[str, Any], audit_logger: ImmutableAuditLogger, vault: EvidenceVault, soc_manager=None):
        self.modules = modules
        self.audit = audit_logger
        self.vault = vault
        self.soc_manager = soc_manager # WebSocket Manager

    async def execute_case(self, request: CaseIntakeRequest, actor: str) -> List[Finding]:
        self.audit.record(actor, "CASE_STARTED", request.case_id, {"target": request.target_type})
        
        tasks = [self._run_module_safely(name, module, request) for name, module in self.modules.items()]
        results = await asyncio.gather(*tasks)
        
        all_findings = []
        for res in results:
            if isinstance(res, list):
                all_findings.extend(res)
                
        if all_findings:
            self.vault.store_findings(request.case_id, all_findings)
            
            # REAL-TIME SOC ALERTING
            if self.soc_manager:
                for finding in all_findings:
                    if finding.severity in ["CRITICAL", "HIGH"]:
                        alert_payload = {
                            "event_type": "THREAT_DETECTED",
                            "case_id": request.case_id,
                            "module": finding.module,
                            "severity": finding.severity,
                            "title": finding.title,
                            "timestamp": finding.timestamp.isoformat() if hasattr(finding.timestamp, 'isoformat') else str(finding.timestamp)
                        }
                        await self.soc_manager.broadcast_critical_event(alert_payload)
                
        self.audit.record(actor, "CASE_COMPLETED", request.case_id, {"findings_count": len(all_findings)})
        return all_findings

    async def _run_module_safely(self, name: str, module: Any, request: CaseIntakeRequest) -> List[Finding]:
        try:
            return await module.run(request)
        except Exception as e:
            logger.error(f"Module {name} failed: {str(e)}")
            return []
