# 🛡️ Project Netra-Core

**Enterprise-Grade Government Cyber-Defense & Forensic Engine**

---

## 📋 Executive Summary

Project Netra-Core is a unified, zero-trust, AI-assisted digital forensics and cyber-defense orchestration platform engineered exclusively for **defensive auditing, automated forensic analytics, and compliance assessment**.

Every case is gated by a **Zero-Trust Legal Warrant Enforcement** layer, and every finding is sealed inside a **tamper-evident HMAC-SHA256 cryptographic ledger**, ensuring complete court admissibility.

## ⚡ Core Capabilities

- **Zero-Trust Legal Gate:** Rejects all requests without valid judicial warrants.
- **Async DAG Orchestration:** Parallel execution of 4 specialized forensic modules.
- **Cryptographic Chain of Custody:** HMAC-SHA256 Merkle-style hash chaining.
- **AI-Powered Legal NLP:** Maps technical findings to BNS 2023 and IT Act 2000.
- **Real-Time SOC Alerting:** WebSocket broadcasting for live dashboards.
- **Court-Admissible Reports:** Automated PDF generation with cryptographic appendix.

## 🚀 Quick Start (Termux Edge Deployment)

```bash
# Clone the repository
git clone https://github.com/sayan9168/Project_NetraCore.git
cd Project_NetraCore

# Setup virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements-prod.txt

# Start the server
PYTHONPATH=. uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

!!! warning "Legal Disclaimer"
    This platform is a defensive instrument. It must only be operated under lawful authority by authorized personnel.
