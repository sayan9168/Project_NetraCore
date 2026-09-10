# API Reference

Base URL: `http://127.0.0.1:8000` · Interactive docs: `/docs` (Swagger) · `/redoc`

## Authentication

| Method | Header | Notes |
|---|---|---|
| Bearer token | `Authorization: Bearer <token>` | Issued by `POST /v1/auth/token` |
| API key | `X-API-Key: <secret>` | Configured via `NETRA_API_KEYS` |
| Dev header | `X-Agent-ID: <id>` | Only when auth is **not** enforced |

Roles: `viewer` (read) → `analyst` (intake, reports) → `admin` (delete).
`GET /`, `/health`, `/v2/health`, `/metrics`, `/dashboard` are public.

## System

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| `GET` | `/` | – | Service banner + feature list |
| `GET` | `/health` | – | Liveness probe |
| `GET` | `/v2/health` | – | Detailed health (version, modules, cache, uptime) |
| `GET` | `/metrics` | – | Prometheus exposition |
| `GET` | `/dashboard` | – | SOC dashboard (HTML) |
| `GET` | `/v1/stats` | viewer | Global case/finding/runtime counters |

## Auth

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/auth/token` | api-key body | Exchange API key → bearer token |
| `GET` | `/v1/auth/me` | any | Current identity + role |

## Cases

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/cases/intake` | analyst | Synchronous forensic intake → findings |
| `POST` | `/v1/cases/intake/async` | analyst | Background intake → `202` + job id |
| `GET` | `/v1/jobs/{job_id}` | viewer | Poll background job |
| `GET` | `/v1/cases?limit=&offset=&priority=&target_type=` | viewer | Paginated case registry |
| `GET` | `/v1/cases/{id}/summary` | viewer | Severity/module breakdown + chain status |
| `GET` | `/v1/cases/{id}/export` | viewer | Full evidence bundle (JSON) |
| `DELETE` | `/v1/cases/{id}` | **admin** | Delete case + findings (audit-logged) |

### Intake payload

```json
{
  "case_id": "CASE-2026-ALPHA",
  "legal_authority": {
    "warrant_id": "W-99283-HC",
    "issued_by": "High Court Cyber Cell",
    "expires_at": "2026-12-31T23:59:59Z",
    "scope": { "full_access": true }
  },
  "target_type": "network",
  "evidence_uri": "beacon to 203.0.113.45",
  "priority": "CRITICAL"
}
```

The warrant gate rejects (`403`) expired warrants and scopes that don't
authorize the requested `target_type` (unless `full_access: true`).

## Findings

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| `GET` | `/v1/cases/{id}/findings?severity=&module=&q=&limit=&offset=` | viewer | Search + paginate findings |

## Evidence & Reports

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| `GET` | `/v1/evidence/verify/{id}` | viewer | Hash-chain verification (`INTACT`/`TAMPERED`) |
| `GET` | `/v1/cases/{id}/report/pdf` | viewer | Court report (PDF download) |
| `GET` | `/v1/cases/{id}/report/signed` | analyst | RSA-4096 signed PDF |
| `GET` | `/v1/cases/{id}/report/signature` | viewer | Detached signature sidecar (JSON) |

## Audit

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| `GET` | `/v1/audit/verify?log_file=` | viewer | Hash-chain verification of audit log |
| `GET` | `/v1/audit/recent?limit=` | viewer | Recent audit entries |

## Real-time SOC stream

```
WS /ws/soc-dashboard[?token=<bearer>]
```

Server sends `CONNECTED` on join and `THREAT_DETECTED` for every
`CRITICAL`/`HIGH` finding. Send `ping` → receive `{"status": "pong"}`.
When auth is enforced, a valid `?token=` is required (close code `4401` otherwise).

## Errors

| Code | Meaning |
|---|---|
| `400` | Schema validation failed (see `detail`) |
| `401` | Missing/invalid credentials |
| `403` | Warrant rejected or insufficient role |
| `404` | Case / job / chain not found |
| `429` | Rate limit exceeded (SlowAPI) |
| `500` | `{"error_id": ...}` — quote it in SOC tickets |
