# Forensic Modules

The orchestrator routes each case through a DAG: stage-1 modules run
concurrently (fault-isolated, per-module timeout + retry), then Module D
maps everything to statutes.

| Target | Stage 1 | Stage 2 |
|---|---|---|
| `android` | A + E | D |
| `cloud` | C + E | D |
| `media` | B + E | D |
| `network` | E + C | D |

## A — Android / File Triage (read-only)

SHA-256 inventory of local evidence (recursive, 500-file / 32 MB caps),
per-file Shannon entropy (packing heuristic), hidden/anti-forensic name
detection, double-extension masquerading, APK container validation
(`AndroidManifest.xml` + DEX). Never executes device commands; remote URIs
produce a descriptor-mode finding.

## B — Steganalysis (ELA + CNN)

JPEG byte-structure analysis (entropy, quantization tables, zero-runs) with
optional PyTorch neural scoring. `FULL` when torch is installed, pure-Python
`FALLBACK` otherwise.

## C — Cloud Auditor (AWS, read-only)

STS `AssumeRole` cross-account scanning (with `ExternalID`): public security
groups on sensitive ports, public S3 ACLs, unused IAM keys, CloudTrail gaps.
Without `AWS_AUDIT_ROLE_ARN` (or without `boto3`) it emits a documented
simulation finding instead of failing.

## D — Legal NLP

Sentence-BERT semantic search over BNS 2023 / IT Act 2000 with SQLite FTS5
fallback. See [Legal NLP](security/legal-nlp.md).

## E — Network & IOC Forensics (new)

Stdlib-only sweep that runs on **every** case:

* Extracts IPv4, domains, URLs, emails, MD5/SHA-1/SHA-256, ports.
* Enriches: private/reserved vs public, high-abuse TLDs, DGA-lexical
  heuristics, Tor-exit sample list.
* Matches against `data/threat_feed.json` → `CRITICAL` on hits.
* **Never fetches remote URLs** (SSRF-safe); remote evidence is parsed as text.
* Size-capped local file reads (`NETRA_MAX_EVIDENCE_MB`).

Replace the bundled demo feed with your TAXII/STIX export in production.
