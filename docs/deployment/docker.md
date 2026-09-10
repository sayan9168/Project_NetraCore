# Docker Deployment

## Quick start

```bash
docker compose up -d --build
# API → http://127.0.0.1:8000 · docs → /docs · dashboard → /dashboard
```

## Services

| Service | Image | Purpose |
|---|---|---|
| `netra-api` | built from `Dockerfile` | FastAPI gateway (health-checked) |
| `worker` | same image, ARQ entrypoint | Background PyTorch inference |
| `postgres` | `pgvector/pgvector:pg16` | Future vector store (reserved) |
| `redis` | `redis:7-alpine` | Shared cache + ARQ broker |
| `prometheus` | `prom/prometheus` | Metrics (opt-in profile) |

```bash
docker compose --profile monitoring up -d   # + Prometheus on :9090
```

## Production checklist

* Set secrets (never commit them):
  `NETRA_API_KEYS`, `NETRA_ADMIN_KEYS`, `NETRA_TOKEN_SECRET`.
* Mount persistent volumes for `data/` (vault, keys, reports) and `logs/`.
* Back up `data/.forensic_master_key` and `data/signing_keys/` in an HSM/KMS —
  losing them voids historical chain verification.
* Put the API behind TLS (ingress / reverse proxy); HSTS is automatic on HTTPS.
* Scrape `/metrics` from Prometheus; alert on `netra_api_errors_total`.
