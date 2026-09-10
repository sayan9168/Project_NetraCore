"""
Async DAG Orchestrator — routes each case through the right forensic modules,
executes them concurrently with per-module timeout + retries, seals findings
into the tamper-evident vault, and broadcasts SOC alerts.

Routing DAG (target_type → modules):
    android → A → D ─┐
    cloud   → C → D ─┼→ E (IOC sweep, always) → seal → alert
    media   → B → D ─┘
    network → E → C → D

Module D (Legal NLP) always runs last so statutes map onto real findings.
"""

import asyncio
import logging
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from src.core.audit import ImmutableAuditLogger
from src.core.database import EvidenceVault
from src.core.models import CaseIntakeRequest, Finding

logger = logging.getLogger("netra.orchestrator")

# Ordered DAG stages per target type. Stages run sequentially; modules inside
# one stage run concurrently (fault-isolated).
DAG_ROUTES: dict[str, list[list[str]]] = {
    "android": [["MODULE_A", "MODULE_E"], ["MODULE_D"]],
    "cloud": [["MODULE_C", "MODULE_E"], ["MODULE_D"]],
    "media": [["MODULE_B", "MODULE_E"], ["MODULE_D"]],
    "network": [["MODULE_E", "MODULE_C"], ["MODULE_D"]],
}

ALERT_SEVERITIES = ("CRITICAL", "HIGH")


class ForensicOrchestrator:
    def __init__(
        self,
        modules: dict[str, Any],
        audit_logger: ImmutableAuditLogger,
        vault: EvidenceVault,
        soc_manager=None,
        module_timeout: float = 120.0,
        module_retries: int = 1,
    ):
        self.modules = modules
        self.audit = audit_logger
        self.vault = vault
        self.soc_manager = soc_manager  # WebSocket Manager
        self.module_timeout = module_timeout
        self.module_retries = module_retries
        self._jobs: dict[str, dict] = {}  # in-memory async job registry

    # ── routing ───────────────────────────────────────────────────────────
    def route(self, target_type: str) -> list[list[str]]:
        stages = DAG_ROUTES.get(target_type, [["MODULE_E"], ["MODULE_D"]])
        # Drop modules that aren't registered (partial deployments).
        routed = [[m for m in stage if m in self.modules] for stage in stages]
        return [stage for stage in routed if stage]

    # ── sync execution ────────────────────────────────────────────────────
    async def execute_case(self, request: CaseIntakeRequest, actor: str) -> list[Finding]:
        started = time.perf_counter()
        self.audit.record(
            actor,
            "CASE_STARTED",
            request.case_id,
            {
                "target": request.target_type,
                "priority": request.priority,
                "evidence_uri": request.evidence_uri,
            },
        )
        try:
            self.vault.register_case(
                request.case_id, request.target_type, request.priority, created_by=actor
            )
        except Exception as exc:
            logger.warning(f"Case registry write failed: {exc}")

        all_findings: list[Finding] = []
        module_stats: dict[str, int] = {}
        for stage in self.route(request.target_type):
            tasks = [self._run_module_safely(name, request) for name in stage]
            for name, result in zip(stage, await asyncio.gather(*tasks), strict=True):
                module_stats[name] = len(result)
                all_findings.extend(result)

        if all_findings:
            self.vault.store_findings(request.case_id, all_findings)
            await self._broadcast_alerts(request.case_id, all_findings)

        duration = time.perf_counter() - started
        severity_counts = dict(Counter(f.severity for f in all_findings))
        try:
            from src.core.metrics import metrics as registry

            registry.case_completed(severity_counts)
        except Exception:
            pass
        try:
            self.vault.touch_case(request.case_id, "COMPLETED")
        except Exception:
            pass
        self.audit.record(
            actor,
            "CASE_COMPLETED",
            request.case_id,
            {
                "findings_count": len(all_findings),
                "modules": module_stats,
                "duration_s": round(duration, 2),
                "severity": severity_counts,
            },
        )
        logger.info(
            f"Case {request.case_id} completed: {len(all_findings)} findings in {duration:.1f}s"
        )
        return all_findings

    async def _run_module_safely(self, name: str, request: CaseIntakeRequest) -> list[Finding]:
        module = self.modules[name]
        attempts = max(self.module_retries, 0) + 1
        last_error: str | None = None
        for attempt in range(1, attempts + 1):
            started = time.perf_counter()
            try:
                result = await asyncio.wait_for(module.run(request), timeout=self.module_timeout)
                findings = result if isinstance(result, list) else []
                self._record_metric(name, time.perf_counter() - started, failed=False)
                return findings
            except asyncio.TimeoutError:
                last_error = f"timeout after {self.module_timeout}s"
                logger.warning(f"Module {name} timed out (attempt {attempt}/{attempts})")
            except Exception as e:
                last_error = str(e)
                logger.error(f"Module {name} failed (attempt {attempt}/{attempts}): {e}")
            self._record_metric(name, time.perf_counter() - started, failed=True)
            if attempt < attempts:
                await asyncio.sleep(min(2**attempt, 8))  # exponential backoff
        logger.error(f"Module {name} exhausted retries. Last error: {last_error}")
        return []

    @staticmethod
    def _record_metric(name: str, duration: float, failed: bool) -> None:
        try:
            from src.core.metrics import metrics as registry

            registry.module_run(name, duration, failed=failed)
        except Exception:
            pass

    async def _broadcast_alerts(self, case_id: str, findings: list[Finding]) -> None:
        if not self.soc_manager:
            return
        sent = 0
        for finding in findings:
            if finding.severity in ALERT_SEVERITIES:
                ts = (
                    finding.timestamp.isoformat()
                    if hasattr(finding.timestamp, "isoformat")
                    else str(finding.timestamp)
                )
                await self.soc_manager.broadcast_critical_event(
                    {
                        "event_type": "THREAT_DETECTED",
                        "case_id": case_id,
                        "module": finding.module,
                        "severity": finding.severity,
                        "title": finding.title,
                        "timestamp": ts,
                    }
                )
                sent += 1
        if sent:
            try:
                from src.core.metrics import metrics as registry

                registry.soc_alert(sent)
            except Exception:
                pass

    # ── async (background) execution ──────────────────────────────────────
    def submit_case(self, request: CaseIntakeRequest, actor: str) -> dict:
        """Queue a case for background execution. Returns the job record."""
        job_id = uuid.uuid4().hex[:12]
        job = {
            "job_id": job_id,
            "status": "QUEUED",
            "case_id": request.case_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "findings_count": None,
            "error": None,
            "_request": request,
            "_actor": actor,
        }
        self._jobs[job_id] = job
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            loop.create_task(self._drain_job(job_id))
        return {k: v for k, v in job.items() if not k.startswith("_")}

    def get_job(self, job_id: str) -> dict | None:
        job = self._jobs.get(job_id)
        if not job:
            return None
        return {k: v for k, v in job.items() if not k.startswith("_")}

    async def _drain_job(self, job_id: str) -> None:
        job = self._jobs.get(job_id)
        if not job:
            return
        job["status"] = "RUNNING"
        try:
            findings = await self.execute_case(job["_request"], job["_actor"])
            job["status"] = "COMPLETED"
            job["findings_count"] = len(findings)
        except Exception as exc:  # noqa: BLE001 - job boundary must not crash
            logger.exception(f"Background job {job_id} failed")
            job["status"] = "FAILED"
            job["error"] = str(exc)
        finally:
            job["finished_at"] = datetime.now(timezone.utc).isoformat()
