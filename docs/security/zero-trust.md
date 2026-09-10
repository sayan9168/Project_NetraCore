# Zero-Trust Model

Netra-Core never trusts network position. Every mutating request must prove
**who** is calling (authentication) and **under what legal authority**
(warrant gate).

## 1. Authentication

```
Bearer token (HMAC-signed, expiring)  ─┐
X-API-Key (constant-time compare)      ─┼─→ AuthContext(agent_id, role)
X-Agent-ID (dev mode only)             ─┘
```

* Auth is **enforced** the moment `NETRA_API_KEYS` / `NETRA_ADMIN_KEYS` is set.
* Without keys the gateway runs in dev mode (`X-Agent-ID` → `analyst`).
* Tokens are stateless HMAC-SHA256 (`payload.signature`), TTL via `NETRA_TOKEN_TTL`.
* Every auth failure increments `netra_auth_failures_total`.

## 2. RBAC

| Role | Capabilities |
|---|---|
| `viewer` | Read findings, verify chains, export bundles, download PDFs |
| `analyst` | + intake cases, signed reports |
| `admin` | + delete cases |

## 3. Warrant gate (`403` on failure)

1. `warrant_id` present
2. `expires_at` in the future (toggle: `NETRA_ENFORCE_WARRANT_EXPIRY`)
3. `scope.full_access == true` **or** a target-specific flag:

| Target | Accepted scope flags |
|---|---|
| `android` | `android_logical_acquisition`, `mobile_forensics` |
| `cloud` | `cloud_audit`, `aws_audit` |
| `media` | `media_forensics`, `image_analysis` |
| `network` | `network_forensics`, `traffic_analysis` |

Every check is written to the immutable audit log (`WARRANT_CHECK` with
`SUCCESS`/`DENIED`), including the human-readable reason.

## 4. Transport & headers

* `SecurityHeadersMiddleware`: `nosniff`, `DENY` framing, restrictive CSP,
  `Permissions-Policy`, HSTS on HTTPS.
* Optional CORS allow-list via `NETRA_CORS_ORIGINS`.
* `X-Request-ID` on every response for SOC ticket correlation.
