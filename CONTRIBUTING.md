# Contributing to Project Netra-Core

Thank you for considering a contribution to a law-enforcement-grade platform.

## Ground Rules

1. **Defensive-only mandate.** Contributions introducing offensive exploitation,
   unauthorized-access tooling, or covert-surveillance capabilities will be rejected.
2. All code must be **type-hinted**, **async-safe**, and **fully documented**.
3. Cryptographic primitives must never be modified without an architect review.

## Workflow

1. Fork the repository and create a feature branch: `git checkout -b feat/<topic>`.
2. Follow the commit convention: `feat:`, `fix:`, `docs:`, `sec:`, `test:`.
3. Ensure `tamper_test.py` passes (chain must remain INTACT).
4. Open a Pull Request using the provided template.

## Code Review Criteria

- Zero-Trust warrant enforcement preserved.
- No secrets, keys, or evidence committed.
- Backward-compatible API surface.
- Production Docker build succeeds.
