# Changelog

All notable changes to Project Netra-Core. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [6.2.0] — 2026-09-10

### Added
- **Auth & RBAC**: API-key + stateless HMAC bearer-token auth
  (`POST /v1/auth/token`, `GET /v1/auth/me`) with `viewer/analyst/admin` roles.
- **Real warrant gate**: expiry + per-target scope enforcement on intake
  (`403` with reason, every check audit-logged).
- **Module E — Network/IOC forensics**: stdlib IOC extraction + local
  threat-intel matching, SSRF-safe by design; runs on every case.
- **Case registry API**: `GET /v1/cases` (paginated), `GET …/summary`,
  `GET …/export`, `DELETE` (admin), findings search (`severity/module/q`).
- **Async intake**: `POST /v1/cases/intake/async` → `202` + `GET /v1/jobs/{id}`.
- **RSA-signed court reports**: `GET …/report/signed` + `…/report/signature`.
- **Audit API**: `GET /v1/audit/verify`, `GET /v1/audit/recent`.
- **Observability**: Prometheus `/metrics` (in-process registry),
  `/v2/health` detail, request IDs, security headers, optional CORS.
- **Operator CLI** (`netra_cli.py`, stdlib-only): intake, findings, verify,
  reports, export, audit, live SOC stream.
- **SOC dashboard rewrite**: stats, intake form, case browser, chain verifier,
  live alert stream — served at `/dashboard`, zero CDN dependencies.
- **Module A real triage**: SHA-256 inventory, entropy heuristics,
  double-extension + APK validation (read-only).
- **Tests**: 47-test pytest suite (crypto, audit, vault, modules,
  orchestrator, API incl. WebSocket + PDF).
- **Tooling**: `pyproject.toml`, `Makefile`, `.pre-commit-config.yaml`,
  `.editorconfig`, `requirements-dev.txt`, ruff-clean codebase.
- **CI**: dedicated test + lint jobs ahead of security scans.
- **Docs**: full MkDocs tree (API, modules, configuration, CLI, security,
  deployment) + `CHANGELOG.md`.
- **Infra**: fixed `docker-compose.yml` structure, container healthchecks,
  Prometheus profile, Helm `NetworkPolicy` + `NOTES.txt`.

### Fixed
- `docker-compose.yml`: `worker` service was outside the `services:` block.
- PDF generator crashed on non-latin-1 finding text — now transliterated.
- `datetime.utcnow()` deprecations across report/signer/models.
- Audit chain forked on process restart — tip is now recovered from disk.
- `boto3` was a hard import — Module C degrades to simulation without it.
- README badges pointed at `//?` placeholders.

### Changed
- Orchestrator is now a real staged DAG (per-target routing, per-module
  timeout + exponential-backoff retries, severity metrics).
- Evidence vault: thread-safe writes, `cases` registry table, search/stats/export.
- `GET /v1/cases/{id}/findings` now returns paginated `{items,total,…}`.

## [6.1.2] — earlier

- FastAPI gateway with SlowAPI rate limiting, WebSocket SOC alerts,
  HMAC-SHA256 evidence ledger, FTS5 legal NLP, PDF court reports,
  Docker + Helm + Termux deployment targets.
