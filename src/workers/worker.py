"""
Production Async Worker for Module B (PyTorch Inference).
Runs as separate process, consumes jobs from Redis queue.
"""
import asyncio
import logging
from arq import create_pool
from arq.connections import RedisSettings

from src.modules.module_b import SteganalysisModule
from src.core.database import EvidenceVault
from src.core.models import CaseIntakeRequest
from src.workers.worker_settings import WorkerSettings

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(message)s")
logger = logging.getLogger("netra.worker")

stego_module = SteganalysisModule()
vault = EvidenceVault()


async def process_image_forensics(ctx, case_id: str, evidence_uri: str):
    """Background PyTorch ELA + CNN inference."""
    logger.info(f"Worker processing image forensics for {case_id}")

    request = CaseIntakeRequest(
        case_id=case_id,
        legal_authority={"warrant_id": "W-WORKER", "issued_by": "System",
                        "expires_at": "2099-01-01T00:00:00Z", "scope": {}},
        target_type="media",
        evidence_uri=evidence_uri
    )

    findings = await stego_module.run(request)
    if findings:
        vault.store_findings(case_id, findings)

    logger.info(f"Worker completed {case_id}: {len(findings)} findings")
    return {"case_id": case_id, "findings": len(findings)}


async def startup(ctx):
    logger.info("Worker pool started")


async def shutdown(ctx):
    logger.info("Worker pool shutting down")


# Expose for ARQ
WorkerSettings.functions = [process_image_forensics]
WorkerSettings.on_startup = startup
WorkerSettings.on_shutdown = shutdown
