import asyncio

from src.core.audit import ImmutableAuditLogger
from src.core.database import EvidenceVault
from src.core.models import Finding
from src.core.orchestrator import ForensicOrchestrator
from tests.conftest import make_case


class _StubModule:
    def __init__(self, module="MODULE_E", severity="HIGH"):
        self.module = module
        self.severity = severity
        self.calls = 0

    async def run(self, request):
        self.calls += 1
        return [
            Finding(
                module=self.module,
                severity=self.severity,
                title="stub",
                description="stub",
                confidence=0.5,
            )
        ]


class _BoomModule:
    async def run(self, request):
        raise RuntimeError("boom")


def _orchestrator(tmp_path, modules):
    audit = ImmutableAuditLogger(log_dir=str(tmp_path / "audit"))
    vault = EvidenceVault(db_path=str(tmp_path / "vault.db"))
    return ForensicOrchestrator(modules, audit, vault, module_timeout=5, module_retries=0)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_routing_runs_expected_modules(tmp_path):
    mods = {
        "MODULE_A": _StubModule("MODULE_A", "LOW"),
        "MODULE_C": _StubModule("MODULE_C", "LOW"),
        "MODULE_D": _StubModule("MODULE_D", "INFO"),
        "MODULE_E": _StubModule("MODULE_E", "HIGH"),
    }
    orch = _orchestrator(tmp_path, mods)
    findings = _run(orch.execute_case(make_case(target_type="network"), actor="op"))
    ran = {f.module for f in findings}
    assert ran == {"MODULE_E", "MODULE_C", "MODULE_D"}
    assert mods["MODULE_A"].calls == 0  # not routed for network


def test_fault_isolation(tmp_path):
    mods = {"MODULE_E": _BoomModule(), "MODULE_D": _StubModule("MODULE_D", "INFO")}
    orch = _orchestrator(tmp_path, mods)
    findings = _run(orch.execute_case(make_case(target_type="network"), actor="op"))
    assert [f.module for f in findings] == ["MODULE_D"]


def test_findings_sealed_and_case_registered(tmp_path):
    mods = {
        "MODULE_E": _StubModule("MODULE_E", "CRITICAL"),
        "MODULE_D": _StubModule("MODULE_D", "INFO"),
    }
    orch = _orchestrator(tmp_path, mods)
    req = make_case(case_id="CASE-SEAL-1", target_type="network")
    _run(orch.execute_case(req, actor="op"))
    assert orch.vault.verify_chain("CASE-SEAL-1")["chain_status"] == "INTACT"
    meta = orch.vault.get_case_meta("CASE-SEAL-1")
    assert meta["status"] == "COMPLETED" and meta["findings_count"] == 2


def test_soc_alert_only_for_high_and_critical(tmp_path):
    sent = []

    class _SOC:
        async def broadcast_critical_event(self, msg):
            sent.append(msg)

    mods = {
        "MODULE_E": _StubModule("MODULE_E", "CRITICAL"),
        "MODULE_D": _StubModule("MODULE_D", "INFO"),
    }
    orch = _orchestrator(tmp_path, mods)
    orch.soc_manager = _SOC()
    _run(orch.execute_case(make_case(target_type="network"), actor="op"))
    assert len(sent) == 1 and sent[0]["severity"] == "CRITICAL"


def test_background_job_lifecycle(tmp_path):
    async def _scenario():
        mods = {
            "MODULE_E": _StubModule("MODULE_E", "LOW"),
            "MODULE_D": _StubModule("MODULE_D", "INFO"),
        }
        orch = _orchestrator(tmp_path, mods)
        job = orch.submit_case(make_case(case_id="CASE-JOB-1", target_type="network"), actor="op")
        assert job["status"] in ("QUEUED", "RUNNING")
        for _ in range(100):
            current = orch.get_job(job["job_id"])
            if current["status"] in ("COMPLETED", "FAILED"):
                return current
            await asyncio.sleep(0.05)
        raise AssertionError("job never finished")

    result = _run(_scenario())
    assert result["status"] == "COMPLETED"
    assert result["findings_count"] == 2
