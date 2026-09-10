# Configuration

All settings are environment variables (see `config/environments/.env.example`).
Code reference: `src/core/config.py`.

## Identity & paths

| Variable | Default | Purpose |
|---|---|---|
| `ENV` | `development` | `production` hides exception details |
| `LOG_LEVEL` | `INFO` | Uvicorn/app log verbosity |
| `NETRA_VAULT_DB` | `data/netra_vault.db` | Evidence vault path |
| `NETRA_LEGAL_DB` | `data/legal_knowledge.db` | Statutes FTS5 DB |
| `NETRA_AUDIT_DIR` | `logs/audit` | JSONL audit directory |
| `NETRA_REPORT_DIR` | `data/reports` | Generated PDFs |
| `NETRA_THREAT_FEED` | `data/threat_feed.json` | Module E intel feed |

## Security

| Variable | Default | Purpose |
|---|---|---|
| `NETRA_API_KEYS` | *(empty = dev mode)* | Comma-separated secrets or `agent:secret` (analyst role) |
| `NETRA_ADMIN_KEYS` | *(empty)* | Same format, `admin` role |
| `NETRA_TOKEN_SECRET` | *(ephemeral)* | HMAC key for bearer tokens — **set in prod** |
| `NETRA_TOKEN_TTL` | `3600` | Token lifetime (seconds) |
| `NETRA_ENFORCE_WARRANT_EXPIRY` | `true` | Reject expired warrants |
| `NETRA_CORS_ORIGINS` | *(empty)* | Allowed origins, comma-separated |

## Orchestrator & evidence

| Variable | Default | Purpose |
|---|---|---|
| `NETRA_MODULE_TIMEOUT` | `120` | Per-module timeout (seconds) |
| `NETRA_MODULE_RETRIES` | `1` | Retries after failure/timeout |
| `NETRA_MAX_EVIDENCE_MB` | `8` | Module E file-read cap |

## Cache / observability / limits

| Variable | Default | Purpose |
|---|---|---|
| `REDIS_URL` | *(empty = memory cache)* | e.g. `redis://:pass@redis:6379/0` |
| `NETRA_CACHE_TTL` | `300` | Default cache TTL |
| `OTLP_ENDPOINT` | *(empty = console)* | OpenTelemetry collector |
| `AWS_AUDIT_ROLE_ARN` | *(empty = simulation)* | Module C cross-account role |
| `AWS_EXTERNAL_ID` | *(empty)* | AssumeRole external ID |
| `AWS_SCAN_REGIONS` | `us-east-1,ap-south-1` | Regions to audit |
| `NETRA_RL_INTAKE` | `30/minute` | Intake rate limit |
| `NETRA_RL_READ` | `60/minute` | Read rate limit |
| `NETRA_RL_REPORT` | `5/minute` | Report rate limit |
