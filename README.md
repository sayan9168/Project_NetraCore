# 🛡️ Project Netra-Core
<!-- Professional Badges -->
<p align="center">
  <img src="https://img.shields.io/badge/Version-6.1.2--Production-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/Kubernetes-Helm-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white" alt="Kubernetes">
  <img src="https://img.shields.io/badge/Security-Tamper--Evident-red?style=for-the-badge" alt="Security">
  <img src="https://img.shields.io/github/license//?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/github/stars//?style=for-the-badge&color=gold" alt="Stars">
  <img src="https://img.shields.io/github/last-commit//?style=for-the-badge" alt="Last Commit">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/ISO-27001%20Compliant-4CAF50?style=flat-square" alt="ISO 27001">
  <img src="https://img.shields.io/badge/NIS2-Compliant-2196F3?style=flat-square" alt="NIS2">
  <img src="https://img.shields.io/badge/Court-Admissible-FF5722?style=flat-square" alt="Court Admissible">
  <img src="https://img.shields.io/badge/Zero-Trust-9C27B0?style=flat-square" alt="Zero Trust">
</p>


### Government Cyber-Defense & Forensic Engine

> **Classification:** RESTRICTED / LAW-ENFORCEMENT GRADE
> A unified, zero-trust, AI-assisted digital forensics and cyber-defense orchestration platform for state agencies.

![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Security](https://img.shields.io/badge/Security-Tamper--Evident-red.svg)

---

## 📋 Executive Summary

**Project Netra-Core** is a production-grade forensic orchestration engine that unifies four specialized analysis modules under a single asynchronous control plane. It is engineered exclusively for **defensive auditing, automated forensic analytics, and compliance assessment**. The platform contains **no offensive exploitation capabilities**.

Every case is gated by a **Zero-Trust Legal Warrant Enforcement** layer, and every finding is sealed inside a **tamper-evident HMAC-SHA256 cryptographic ledger**, making the evidence chain admissible under **ISO/IEC 27037** and **NIST SP 800-86** digital-evidence handling standards.

---

## 🏗️ System Architecture
─────────────────────────────────┐
│     Zero-Trust API Gateway      │
│  (Legal Warrant Enforcement)    │
└───────────────┬─────────────────┘
│
┌───────────────▼─────────────────┐
│      Async DAG Orchestrator     │
└──┬─────────┬─────────┬────────┬─┘
│         │         │        │
┌─────▼───┐ ┌───▼────┐ ┌──▼─────┐ ┌▼───────┐
│ MODULE A│ │MODULE B│ │MODULE C│ │MODULE D│
│ Android │ │ Stego/ │ │ Cloud  │ │ Legal  │
│ Triage  │ │ELA+CNN │ │ Audit  │ │  NLP   │
└────────┘ └───┬────┘ └──┬─────┘ └┬───────┘
│         │         │        │
┌─────▼─────────▼─────────▼────────▼───────┐
│     HMAC-SHA256 Evidence Ledger          │
│        (Tamper-Evident SQLite)           │
└──────────────────┬───────────────────────┘
│
┌────────────────────────┼────────────────────────┐
│                        │                        │
┌───────▼────────┐      ┌────────▼────────┐      ┌────────▼────────┐
│ WebSocket SOC  │      │  PDF Court-     │      │  JSONL Audit    │
│ Live Alerts    │      │  Report Engine  │      │  Chain-of-Custody│
└────────────────┘      └─────────────────┘      └─────────────────┘
---

## 🔬 Core Modules

| Module | Function | Engine |
|---|---|---|
| **A — Android Triage** | Defensive device forensics, hash verification, anti-forensic indicator detection | Async I/O |
| **B — Steganalysis** | Error-Level Analysis (ELA) + Neural CNN payload detection | OpenCV / PyTorch |
| **C — Cloud Auditor** | AWS Security-Group & IAM exposure scanning (0.0.0.0/0 detection) | Boto3 |
| **D — Legal NLP** | Semantic mapping of findings to **BNS 2023 / IT Act 2000** | Sentence-BERT / FTS5 |

---

## ⚡ Key Capabilities

- **Async DAG Orchestration** — parallel module execution with fault isolation.
- **Cryptographic Chain of Custody** — every record linked via `prev_hash → current_hash → HMAC signature`. Any database mutation breaks the chain and is flagged `TAMPERED / REJECTED`.
- **Zero-Trust Legal Gate** — requests without a valid warrant are rejected with `403`.
- **Real-Time SOC Alerting** — WebSocket broadcast of `CRITICAL/HIGH` findings.
- **Court-Admissible PDF Reports** — system-generated reports with a cryptographic appendix.
- **AI Legal Mapping** — semantic vector search over a statutory knowledge base.

---

## 📁 Repository Structure
Project_NetraCore/
├── src/
│   ├── api/main.py               # FastAPI Gateway + WebSocket SOC
│   ├── core/
│   │   ├── models.py             # Pydantic schemas
│   │   ├── orchestrator.py       # Async DAG engine
│   │   ├── crypto_seal.py        # HMAC-SHA256 ledger engine
│   │   ├── database.py           # Immutable evidence vault
│   │   ├── audit.py              # JSONL chain-of-custody logger
│   │   └── report_generator.py   # PDF court-report engine
│   └── modules/                  # A / B / C / D forensic engines
├── helm/netra-core/              # Kubernetes deployment charts
├── Dockerfile                    # Multi-stage secure build
├── docker-compose.yml            # API + pgvector + Redis
├── requirements-prod.txt         # Pinned production dependencies
├── seed_legal_db.py              # Statutory corpus seeder
├── dashboard.html                # Live SOC visual dashboard
├── soc_client.py                 # WebSocket alert listener
└── tamper_test.py                # Integrity verification harness
---

## 🚀 Deployment

### Option 1 — Edge Node (Termux / Field Device)
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements-prod.txt
PYTHONPATH=. python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

### Option 2 — Production (Docker)
```bash
docker compose up -d --build
```

### Option 3 — Enterprise (Kubernetes)
```bash
helm install netra-prod ./helm/netra-core -n cybersecurity --create-namespace
```

---

## 🔌 API Reference

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/v1/cases/intake` | Ingest case (warrant required) |
| `GET` | `/v1/cases/{id}/findings` | Retrieve stored findings |
| `GET` | `/v1/evidence/verify/{id}` | Verify cryptographic chain |
| `GET` | `/v1/cases/{id}/report/pdf` | Download court report |
| `WS` | `/ws/soc-dashboard` | Live threat stream |

**Sample Intake Payload:**
```json
{
  "case_id": "CASE-2026-ALPHA",
  "legal_authority": {
    "warrant_id": "W-99283-HC",
    "issued_by": "High Court Cyber Cell",
    "expires_at": "2026-12-31T23:59:59Z",
    "scope": { "full_access": true }
  },
  "target_type": "cloud",
  "evidence_uri": "aws://account-123456789/vpc-001",
  "priority": "CRITICAL"
}
```

---

## ⚖️ Legal & Ethical Disclaimer

This platform is a **defensive instrument**. It must only be operated under lawful authority, with valid judicial or administrative warrants, by authorized personnel. All legal mappings are **advisory** and require human legal review. The authors assume no liability for misuse contrary to applicable law.

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE).

## 👤 Author

**Sayan Mahata** — Principal Cybersecurity Architect
GitHub: [@sayan9168](https://github.com/sayan9168)
