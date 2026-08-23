import asyncio
import logging
from src.core.models import CaseIntakeRequest, Finding

logger = logging.getLogger("netra.module_a")

class AndroidTriageModule:
    async def run(self, request: CaseIntakeRequest) -> list[Finding]:
        logger.info(f"Module A: Initiating read-only triage for {request.case_id}")
        await asyncio.sleep(1) # Simulating I/O bound forensic extraction
        
        findings = []
        if request.target_type == "android":
            findings.append(Finding(
                module="MODULE_A",
                severity="MEDIUM",
                title="Anti-Forensic Hidden Directory Detected",
                description="Found obfuscated directory in /data/local/tmp/",
                confidence=0.85,
                raw_data={"path": "/data/local/tmp/.shadow_cache"}
            ))
        return findings
