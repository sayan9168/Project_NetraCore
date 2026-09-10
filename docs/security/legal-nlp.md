# Legal NLP (BNS 2023 / IT Act 2000)

Module D maps forensic findings to statutes **advisory-only** — every mapping
requires human legal review before court submission.

## Modes

| Mode | Engine | When |
|---|---|---|
| `FULL` | Sentence-BERT (`all-MiniLM-L6-v2`) cosine search | `sentence-transformers` installed |
| `FALLBACK_FTS5` | SQLite FTS5 BM25 keyword search | Always available |

## Corpus

Seeded by `seed_legal_db.py` into `data/legal_knowledge.db` (`statutes_fts`):

* IT Act 2000 — §43 (damage), §43A (data protection negligence), §65
  (source tampering), §66 (computer offences), §72A (privacy breach)
* BNS 2023 — §336(3) (electronic forgery), §340 (reputation forgery),
  §351(4) (anonymous intimidation)

Extend by inserting rows into the FTS5 table and rebuilding vectors
(restart Module D). Finding `raw_data` always records which mode and query
produced the mapping, keeping the advice auditable.
