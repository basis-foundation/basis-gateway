## Summary

_Describe what this PR changes and why._

---

## Checklist

**Step 1 — Identify affected surfaces**

Check every surface this PR touches:

- [ ] Authentication or token verification logic (`src/basis_gateway/auth/`)
- [ ] Identity normalization or subject mapping (`src/basis_gateway/auth/subject_mapper.py`)
- [ ] Audit event emission or gateway event vocabulary (`src/basis_gateway/audit/`)
- [ ] Readiness component registration or behavior (`src/basis_gateway/readiness.py`)
- [ ] API request/response schemas (`src/basis_gateway/api/schemas.py`)
- [ ] Environment variable configuration (`src/basis_gateway/config.py`)
- [ ] Correlation ID handling (`src/basis_gateway/middleware/`)
- [ ] Public documentation (`README.md`, `docs/`)
- [ ] None of the above — this PR does not touch any of these surfaces

**Step 2 — Classify the change**

- [ ] Additive only (new behavior, new config option, new audit event — existing callers unaffected)
- [ ] Breaking (changes API contract, removes config support, alters audit event shape, changes authentication behavior)
- [ ] Not applicable (docs, tests, refactor only)

---

## If the change affects authentication or audit behavior

- [ ] New or changed behavior is covered by tests
- [ ] Audit event emission for affected paths verified (all pre-evaluation failure paths must emit a gateway event)
- [ ] Security model assumptions in `SECURITY.md` and `docs/release-readiness.md` still hold

---

## If the change modifies `basis-core` integration

- [ ] Change uses only the stable public API (`basis-core/docs/public-api.md`)
- [ ] No direct imports from `basis_core` internals

---

## Tests

_Describe what tests cover this change, or explain why no new tests are needed._

- [ ] `pytest` passes locally
- [ ] `ruff check` passes
- [ ] `ruff format --check` passes
- [ ] `mypy src` passes
