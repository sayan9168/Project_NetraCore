# 🏗️ System Architecture

Project Netra-Core utilizes an Asynchronous Directed Acyclic Graph (DAG) orchestration engine to process forensic evidence across multiple specialized modules simultaneously.

## Data Flow Pipeline

1. **Intake:** Zero-Trust API Gateway validates Legal Warrant.
2. **Orchestration:** Async DAG distributes tasks to Modules A, B, C, and D.
3. **Analysis:** Modules perform specialized forensics (Android, Image, Cloud, Legal).
4. **Sealing:** Findings are cryptographically sealed (HMAC-SHA256) and chained.
5. **Broadcasting:** Critical threats are pushed to SOC via WebSockets.
6. **Reporting:** Court-admissible PDF reports are generated on demand.

## Module Matrix

| Module | Function | Engine |
|---|---|---|
| **A** | Android Triage | Async I/O |
| **B** | Steganalysis & ELA | OpenCV / Pure Python |
| **C** | Cloud Config Auditor | Boto3 (AWS) |
| **D** | Legal NLP Mapping | SQLite FTS5 / BERT |
