# 🛡️ Project Netra-Core
<!-- Professional Badges -->
<p align="center">
  <img src="https://img.shields.io/badge/Version-6.2.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/Kubernetes-Helm-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white" alt="Kubernetes">
  <img src="https://img.shields.io/badge/Security-Tamper--Evident-red?style=for-the-badge" alt="Security">
  <img src="https://img.shields.io/github/license/sayan9168/Project_NetraCore?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/github/stars/sayan9168/Project_NetraCore?style=for-the-badge&color=gold" alt="Stars">
  <img src="https://img.shields.io/github/last-commit/sayan9168/Project_NetraCore?style=for-the-badge" alt="Last Commit">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/ISO-27001%20Compliant-4CAF50?style=flat-square" alt="ISO 27001">
  <img src="https://img.shields.io/badge/NIS2-Compliant-2196F3?style=flat-square" alt="NIS2">
  <img src="https://img.shields.io/badge/Court-Admissible-FF5722?style=flat-square" alt="Court Admissible">
  <img src="https://img.shields.io/badge/Zero-Trust-9C27B0?style=flat-square" alt="Zero Trust">
  <img src="https://img.shields.io/badge/Tests-47%20passing-brightgreen?style=flat-square" alt="Tests">
</p>

### Government Cyber-Defense & Forensic Engine

> **Classification:** RESTRICTED / LAW-ENFORCEMENT GRADE
> A unified, zero-trust, AI-assisted digital forensics and cyber-defense orchestration platform for state agencies.

---

## 📋 Executive Summary

**Project Netra-Core** is a production-grade forensic orchestration engine that unifies five specialized analysis modules under a single asynchronous control plane. It is engineered exclusively for **defensive auditing, automated forensic analytics, and compliance assessment**. The platform contains **no offensive exploitation capabilities**.

Every case is gated by a **Zero-Trust Legal Warrant Enforcement** layer (expiry + scope validation), and every finding is sealed inside a **tamper-evident HMAC-SHA256 cryptographic ledger**, making the evidence chain admissible under **ISO/IEC 27037** and **NIST SP 800-86** digital-evidence handling standards.

📚 **Full docs:** [MkDocs site](https://sayan9168.github.io/Project_NetraCore/) · `docs/` in this repo
📰 **Changelog:** [CHANGELOG.md](CHANGELOG.md)

---

## 🏗️ System Architecture

```
┌─────────────────────────────────┐
│     Zero-Trust API Gateway      │
│  (Auth/RBAC + Warrant Gate)     │
└───────────────┬─────────────────┘
                │
┌───────────────▼─────────────────┐
│      Async DAG Orchestrator     │
│  (routing · timeout · retries)  │
└──┬─────────┬─────────┬────────┬─┘
   │         │         │        │
┌──▼───┐ ┌───▼────┐ ┌──▼─────┐ ┌▼───────┐ ┌────────┐
│ MOD  │ │MOD B   │ │MOD C   │ │MOD D   │ │MOD E   │
│ A    │ │Stego/  │ │Cloud   │ │Legal   │ │Network │
│ Tri- │ │ELA+CNN │ │Audit   │ │NLP     │ │IOC     │
│ age  │ │        │ │        │ │        │ │Sweep   │
└──┬───┘ └───┬────┘ └──┬─────┘ └┬───────┘ └┬───────┘
   │         │         │        │          │
┌──▼─────────▼─────────▼────────▼──────────▼───────┐
│     HMAC-SHA256 Evidence Ledger                  │
│        (Tamper-Evident SQLite)                   │
└──────────────────┬───────────────────────────────┘
                   │
┌──────────────────┼────────────────────────┬───────────────────┐
│                  │                        │                   │
┌──────▼───────┐ ┌──▼──────────┐ ┌───────────▼────────┐ ┌────────▼───────┐
│ WebSocket SOC│ │ PDF Court   │ │ JSONL Audit        │ │ Prometheus     │
│ Live Alerts  │ │ Reports     │ │ Chain-of-Custody   │ │ /metrics       │
│              │ │ (+ RSA-4096 │ │                    │ │                │
│              │ │  signing)   │ │                    │ │                │
└──────────────┘ └─────────────┘ └────────────────────┘ └────────────────┘
```

---

## 🔬 Core Modules

| Module | Function | Engine |
|---|---|---|
| **A — Android Triage** | SHA-256 inventory, entropy heuristics, APK validation (read-only) | Stdlib |
| **B — Steganalysis** | Error-Level Analysis (ELA) + Neural CNN payload detection | OpenCV / PyTorch (optional) |
| **C — Cloud Auditor** | AWS Security-Group, S3, IAM & CloudTrail exposure scanning | Boto3 (optional) |
| **D — Legal NLP** | Semantic mapping of findings to **BNS 2023 / IT Act 2000** | Sentence-BERT / FTS5 |
| **E — Network IOC** 🆕 | IOC extraction + threat-intel matching (SSRF-safe) | Stdlib |

Every module degrades gracefully — the gateway boots and serves cases with **zero** ML/cloud dependencies installed.

---

## ⚡ Key Capabilities

- **Async DAG Orchestration** — per-target routing, per-module timeout + exponential-backoff retries, fault isolation.
- **Cryptographic Chain of Custody** — every record linked via `prev_hash → current_hash → HMAC signature`. Any database mutation breaks the chain and is flagged `TAMPERED / REJECTED`.
- **Zero-Trust Legal Gate** — expired warrants and out-of-scope targets rejected with `403` + reason; every check audit-logged.
- **Auth + RBAC** — API keys and expiring HMAC bearer tokens; `viewer / analyst / admin` roles.
- **Real-Time SOC Alerting** — WebSocket broadcast of `CRITICAL/HIGH` findings (token-authenticated when enforced).
- **Court-Admissible PDF Reports** — system-generated reports with cryptographic appendix, optionally **RSA-4096 signed**.
- **AI Legal Mapping** — semantic vector search over a statutory knowledge base (BNS 2023 / IT Act 2000).
- **Case Registry** — paginated listing, severity search, summaries, JSON evidence-bundle export.
- **Background Jobs** — async intake with job polling for long-running cases.
- **Operator CLI** — stdlib-only `netra_cli.py` for intake, verify, reports, audit, live stream.
- **Prometheus Metrics** — `/metrics` with case/finding/module/HTTP/auth/SOC series.

---

## 📁 Repository Structure

```
Project_NetraCore/
├── src/
│   ├── api/main.py               # FastAPI Gateway + WebSocket SOC
│   ├── api/deps.py               # Auth + RBAC dependencies
│   ├── core/
│   │   ├── config.py             # Centralized env-driven settings
│   │   ├── security.py           # API keys, HMAC tokens, warrant gate, RBAC
│   │   ├── models.py             # Pydantic schemas
│   │   ├── orchestrator.py       # Async DAG engine + job registry
│   │   ├── crypto_seal.py        # HMAC-SHA256 ledger engine
│   │   ├── database.py           # Evidence vault + case registry
│   │   ├── audit.py              # JSONL chain-of-custody logger
│   │   ├── cache.py              # Redis (fallback: in-memory TTL)
│   │   ├── metrics.py            # Prometheus metric registry
│   │   ├── middleware.py         # Request-ID, security headers, telemetry
│   │   ├── observability.py      # OpenTelemetry tracing (optional)
│   │   ├── pdf_signer.py         # RSA-4096 report signer
│   │   └── report_generator.py   # PDF court-report engine
│   └── modules/                  # A / B / C / D / E forensic engines
├── tests/                        # 47-test pytest suite
├── docs/                         # MkDocs site (API, modules, security, deploy)
├── helm/netra-core/              # Kubernetes deployment charts
├── docker/prometheus/            # Prometheus scrape config
├── Dockerfile                    # Multi-stage secure build
├── docker-compose.yml            # API + pgvector + Redis (+ Prometheus)
├── netra_cli.py                  # Operator CLI (stdlib-only)
├── dashboard.html                # Live SOC visual dashboard
├── requirements-prod.txt         # Pinned production dependencies
├── requirements-minimal.txt      # Edge/CI lightweight profile
├── requirements-dev.txt          # Test + lint tooling
├── seed_legal_db.py              # Statutory corpus seeder
├── soc_client.py                 # WebSocket alert listener
└── tamper_test.py                # Integrity verification harness
```

---

## 🚀 Deployment

### Option 1 — Edge Node (Termux / Field Device)
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements-minimal.txt
PYTHONPATH=. python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

### Option 2 — Production (Docker)
```bash
docker compose up -d --build
docker compose --profile monitoring up -d   # + Prometheus on :9090
```

### Option 3 — Enterprise (Kubernetes)
```bash
helm install netra-prod ./helm/netra-core -n cybersecurity --create-namespace
```

### Developers
```bash
make install-dev   # minimal runtime + pytest + ruff
make test          # 47-test suite
make lint          # ruff check
make dev           # auto-reload API on :8000
make demo          # end-to-end demo case (needs running server)
```

---

## 🔌 API Reference

Full reference: [docs/api/reference.md](docs/api/reference.md) · live: `/docs`

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/v1/auth/token` | Exchange API key → bearer token |
| `POST` | `/v1/cases/intake` | Ingest case (warrant required) |
| `POST` | `/v1/cases/intake/async` | Background intake → job id |
| `GET` | `/v1/jobs/{id}` | Poll background job |
| `GET` | `/v1/cases` | Paginated case registry |
| `GET` | `/v1/cases/{id}/findings` | Search + paginate findings |
| `GET` | `/v1/cases/{id}/summary` | Severity/module breakdown |
| `GET` | `/v1/cases/{id}/export` | JSON evidence bundle |
| `DELETE` | `/v1/cases/{id}` | Delete case (admin, audit-logged) |
| `GET` | `/v1/evidence/verify/{id}` | Verify cryptographic chain |
| `GET` | `/v1/cases/{id}/report/pdf` | Download court report |
| `GET` | `/v1/cases/{id}/report/signed` | RSA-4096 signed report |
| `GET` | `/v1/audit/verify` | Verify audit-log chain |
| `GET` | `/v1/stats` | Global counters |
| `GET` | `/metrics` | Prometheus exposition |
| `GET` | `/dashboard` | SOC dashboard |
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

**Operator CLI (no dependencies):**
```bash
python netra_cli.py intake --agent soc-op --case CASE-1 --target network \
  --evidence "beacon to 203.0.113.45" --warrant W-1 --issued-by "Cyber Cell" \
  --expires 2026-12-31T23:59:59Z --priority HIGH
python netra_cli.py verify CASE-1 && python netra_cli.py audit --verify
```

---

## ⚙️ Configuration

Everything is env-driven — see [config/environments/.env.example](config/environments/.env.example) and [docs/configuration.md](docs/configuration.md). Highlights for production:

```bash
NETRA_API_KEYS="analyst-01:<secret>"   # enables auth enforcement
NETRA_ADMIN_KEYS="admin-01:<secret>"
NETRA_TOKEN_SECRET="<32+ random bytes>"
REDIS_URL="redis://:pass@redis:6379/0"
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
