# Kubernetes (Helm)

```bash
helm install netra-prod ./helm/netra-core -n cybersecurity --create-namespace
```

## What's included

* `deployment.yaml` — 3 replicas, readiness/liveness on `/health`
* `hpa.yaml` — CPU-based autoscaling
* `networkpolicy.yaml` — default-deny ingress except the API port
* `NOTES.txt` — post-install connection instructions

## Recommended overrides

```yaml
image:
  tag: "6.2.0"
env:
  - name: NETRA_API_KEYS
    valueFrom: { secretKeyRef: { name: netra-auth, key: api-keys } }
  - name: REDIS_URL
    value: "redis://:pass@redis:6379/0"
persistence:
  enabled: true            # vault + audit logs must survive rescheduling
```

Store `NETRA_TOKEN_SECRET`, API keys and the forensic master key in sealed
secrets / external-secrets. Run Vault backups to WORM storage for
chain-of-custody retention.
