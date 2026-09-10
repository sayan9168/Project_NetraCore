import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(isolated_workdir, monkeypatch):
    # Import app AFTER workdir isolation so vault/audit land in tmp_path.
    import importlib

    import src.api.main as main

    importlib.reload(main)
    return TestClient(main.app)


def _intake_payload(**overrides):
    payload = {
        "case_id": "CASE-API-001",
        "legal_authority": {
            "warrant_id": "W-API-1",
            "issued_by": "Test Court",
            "expires_at": "2099-12-31T23:59:59Z",
            "scope": {"full_access": True},
        },
        "target_type": "network",
        "evidence_uri": "beacon to 203.0.113.45",
        "priority": "HIGH",
    }
    payload.update(overrides)
    return payload


def test_root_and_health(client):
    assert client.get("/").status_code == 200
    assert client.get("/health").json()["status"] == "OPERATIONAL"
    detail = client.get("/v2/health").json()
    assert "MODULE_E" in detail["modules"]
    assert "X-Request-ID" in client.get("/health").headers


def test_metrics_endpoint(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "netra_cases_total" in resp.text
    assert "text/plain" in resp.headers["content-type"]


def test_intake_rejects_expired_warrant(client, auth_headers):
    payload = _intake_payload()
    payload["legal_authority"]["expires_at"] = "2020-01-01T00:00:00Z"
    resp = client.post("/v1/cases/intake", json=payload, headers=auth_headers)
    assert resp.status_code == 403
    assert "expired" in resp.json()["detail"].lower()


def test_intake_rejects_missing_scope(client, auth_headers):
    payload = _intake_payload()
    payload["legal_authority"]["scope"] = {"cloud_audit": True}
    payload["target_type"] = "android"
    resp = client.post("/v1/cases/intake", json=payload, headers=auth_headers)
    assert resp.status_code == 403


def test_full_case_lifecycle(client, auth_headers):
    # 1. Intake
    resp = client.post("/v1/cases/intake", json=_intake_payload(), headers=auth_headers)
    assert resp.status_code == 200, resp.text
    findings = resp.json()
    assert len(findings) >= 2
    assert any(f["severity"] == "CRITICAL" for f in findings)  # feed hit 203.0.113.45

    # 2. Paginated findings + filter
    resp = client.get("/v1/cases/CASE-API-001/findings?severity=CRITICAL", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1

    # 3. Summary
    summary = client.get("/v1/cases/CASE-API-001/summary", headers=auth_headers).json()
    assert summary["chain_status"] == "INTACT"
    assert summary["total_findings"] == len(findings)

    # 4. Chain verification
    verify = client.get("/v1/evidence/verify/CASE-API-001", headers=auth_headers).json()
    assert verify["chain_status"] == "INTACT"

    # 5. Case listing
    listing = client.get("/v1/cases", headers=auth_headers).json()
    assert listing["total"] >= 1

    # 6. Export bundle
    bundle = client.get("/v1/cases/CASE-API-001/export", headers=auth_headers).json()
    assert bundle["verification"]["chain_status"] == "INTACT"


def test_async_intake_and_job_poll(client, auth_headers):
    resp = client.post(
        "/v1/cases/intake/async", json=_intake_payload(case_id="CASE-ASYNC-1"), headers=auth_headers
    )
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]
    for _ in range(100):
        job = client.get(f"/v1/jobs/{job_id}", headers=auth_headers).json()
        if job["status"] in ("COMPLETED", "FAILED"):
            break
    assert job["status"] == "COMPLETED"
    assert job["findings_count"] >= 1


def test_audit_endpoints(client, auth_headers):
    client.post(
        "/v1/cases/intake", json=_intake_payload(case_id="CASE-AUD-1"), headers=auth_headers
    )
    assert client.get("/v1/audit/verify", headers=auth_headers).json()["chain_status"] == "INTACT"
    recent = client.get("/v1/audit/recent?limit=5", headers=auth_headers).json()
    assert len(recent["entries"]) >= 1


def test_delete_requires_admin_and_works_in_dev(client, auth_headers, monkeypatch):
    # Dev mode: X-Agent-ID maps to analyst → delete forbidden
    client.post(
        "/v1/cases/intake", json=_intake_payload(case_id="CASE-DEL-1"), headers=auth_headers
    )
    resp = client.delete("/v1/cases/CASE-DEL-1", headers=auth_headers)
    assert resp.status_code == 403
    # Admin API key → allowed
    monkeypatch.setenv("NETRA_ADMIN_KEYS", "root:adminkey")
    resp = client.delete("/v1/cases/CASE-DEL-1", headers={"X-API-Key": "adminkey"})
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True


def test_token_flow(client, monkeypatch):
    monkeypatch.setenv("NETRA_API_KEYS", "op1:opkey")
    resp = client.post("/v1/auth/token", json={"api_key": "opkey"})
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    me = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["agent_id"] == "op1"
    bad = client.post("/v1/auth/token", json={"api_key": "nope"})
    assert bad.status_code == 401


def test_websocket_soc_stream(client):
    with client.websocket_connect("/ws/soc-dashboard") as ws:
        hello = ws.receive_json()
        assert hello["event_type"] == "CONNECTED"
        ws.send_text("ping")
        assert ws.receive_json()["status"] == "pong"


def test_pdf_report_generation(client, auth_headers):
    pytest.importorskip("fpdf")
    client.post(
        "/v1/cases/intake", json=_intake_payload(case_id="CASE-PDF-1"), headers=auth_headers
    )
    resp = client.get("/v1/cases/CASE-PDF-1/report/pdf", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"
