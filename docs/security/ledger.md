# Cryptographic Ledger

## Evidence vault (`data/netra_vault.db`)

Every finding is sealed into a **hash chain**:

```
prev_hash ─┐
payload ───┼─→ SHA256(prev_hash ‖ payload) = current_hash
HMAC(master_key, current_hash)             = signature
```

* `verify_chain(case_id)` recomputes every link with **constant-time**
  comparison — any `UPDATE`/`DELETE` flips the case to `TAMPERED / REJECTED`.
* Master key: 256-bit random at `data/.forensic_master_key` (`0600`).
* Writes are mutex-serialized; rows are `INSERT OR IGNORE` (idempotent).
* Ordering is by `rowid` (insertion order), never wall-clock.

Try it: `python tamper_test.py` flips severities in-place and proves
detection, or `GET /v1/evidence/verify/{case_id}`.

## Audit log (`logs/audit/audit_*.jsonl`)

Append-only JSONL with the same chaining discipline (`GENESIS` tip per day).
The logger **recovers the tip from disk** on restart so chains never fork.
Verify with `GET /v1/audit/verify` or `python netra_cli.py audit --verify`.

## Signed court reports

`GET /v1/cases/{id}/report/signed` produces:

1. The PDF report (findings + cryptographic appendix),
2. An RSA-4096 + PSS + SHA-256 signature,
3. A detached `.sig` sidecar (JSON) retrievable via `/report/signature`.

Keys live at `data/signing_keys/` (`0600` private). Verification needs only
the public key + SHA-256 of the PDF.
