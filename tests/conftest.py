"""
Shared pytest fixtures. Every test runs inside an isolated temp working
directory so the real ./data and ./logs are never touched.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture(autouse=True)
def isolated_workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETRA_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("NETRA_LEGAL_DB", str(tmp_path / "legal.db"))
    monkeypatch.setenv("NETRA_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setenv("NETRA_REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.delenv("NETRA_API_KEYS", raising=False)
    monkeypatch.delenv("NETRA_ADMIN_KEYS", raising=False)
    # Seed legal DB for Module D FTS5 tests
    from seed_legal_db import seed_legal_vault

    seed_legal_vault(str(tmp_path / "legal.db"))
    return tmp_path


@pytest.fixture()
def vault(isolated_workdir):
    from src.core.database import EvidenceVault

    return EvidenceVault(db_path=str(isolated_workdir / "vault.db"))


@pytest.fixture()
def auth_headers():
    return {"X-Agent-ID": "pytest-agent"}


def make_case(**overrides):
    from src.core.models import CaseIntakeRequest

    payload = {
        "case_id": "CASE-TEST-001",
        "legal_authority": {
            "warrant_id": "W-TEST-1",
            "issued_by": "Test Court",
            "expires_at": "2099-12-31T23:59:59Z",
            "scope": {"full_access": True},
        },
        "target_type": "network",
        "evidence_uri": "test evidence",
        "priority": "HIGH",
    }
    payload.update(overrides)
    return CaseIntakeRequest(**payload)
