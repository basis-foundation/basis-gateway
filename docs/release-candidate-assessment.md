# basis-gateway v0.1.0 Release Candidate Assessment

**Assessment date:** 2026-06-08
**Assessed by:** Release readiness review (docs/release-checklist.md)
**Verdict: RELEASE CANDIDATE — approved for v0.1.0 public release**

---

## Question: Can basis-gateway be released publicly as v0.1.0?

**Yes, with the conditions documented below.**

`basis-gateway` is ready for public release as v0.1.0. The core authorization path is complete, correct, and tested. The architectural invariants are consistently implemented and verified. All release blockers identified during this review have been resolved.

This is a pre-production proof of concept. The release is appropriate for integration testing, development evaluation, and early ecosystem adoption. It is not suitable for deployment as a production security control without additional hardening, testing, and operational work. This is stated explicitly in `SECURITY.md` and `docs/release-readiness.md`.

---

## Release blocker resolution

The following blockers were identified during the v0.1 release readiness review. All are resolved.

| Blocker | Severity | Status |
|---|---|---|
| `LICENSE` missing — repository was legally "all rights reserved" | Critical | **Resolved**: Apache 2.0 added, matching `basis-architecture` |
| `SECURITY.md` missing — no vulnerability reporting path | Critical | **Resolved**: `SECURITY.md` created; covers security model, reporting path, known limitations |
| `.github/` missing — no CI, PR template, or issue templates | Moderate | **Resolved**: CI workflow, PR template, bug/feature issue templates created |
| Phase language in source and docs | Low | **Resolved**: all "Phase N" references removed from user-facing files and source docstrings |

---

## Evidence by review area

### Repository structure

Pass. Standard repository artifacts are present: `LICENSE` (Apache 2.0), `SECURITY.md`, `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `.env.example`, `.gitignore`. `.github/` contains CI, PR template, and issue templates. The `pytest-cache-files-tqyy692p/` artifact is empty and gitignored.

### Documentation

Pass. `README.md` accurately describes what is implemented: the feature list, setup instructions, environment variable reference, API examples, evaluation flow, and architecture position. Examples have been verified against the test suite (`correlation_id` always present; `policy_version` omitted when not configured per `exclude_none=True`). Phase language removed. All relative links verified.

`docs/release-readiness.md` accurately describes scope, out-of-scope items, and known limitations.

`docs/audit-model.md` documents all gateway-level events, the correlation ID flow, and the resolved/open question status. The pre-evaluation audit coverage open question is marked *(resolved)* with the latent `RequestValidationError` gap documented.

`docs/audit-failure-escalation.md` covers the Model B/C design, failure scenarios, and security analysis.

### Security

Pass (with documented limitations).

Authentication path: token verification covers RS256/RS384/RS512/ES256/ES384/ES512; `alg=none` rejected unconditionally at the PyJWT layer. Verified in `auth/oidc.py`.

Identity normalization: `subject_id` and `subject_roles` are rejected from the request body at schema level (`EvaluateRequest`). Subject identity derives exclusively from verified JWT claims. Verified in `api/schemas.py` and `api/routes.py`.

Audit coverage: all 11 reachable pre-evaluation exit paths in `evaluate()` are preceded by `emit_gateway_event`. The one latent gap (`RequestValidationError` handler in `main.py`) is unreachable for the current route signature and is documented in `docs/audit-model.md` §9.

No secrets committed: `.env.example` uses placeholder values only. Raw tokens do not appear in logs or audit records. Verified in `auth/oidc.py` and `audit/gateway_events.py`.

Known security limitations (documented in `SECURITY.md` and `docs/release-readiness.md`):
- Log-backed audit only; no durable storage or tamper-evidence
- In-process JWKS cache; no revocation support
- Single-instance only; multi-instance untested
- `RequestValidationError` handler latent audit gap (currently unreachable)

### Dependencies

Pass. All runtime dependencies at or above minimum versions in `pyproject.toml`. Installed versions are well above minimums:

| Package | Minimum | Installed |
|---|---|---|
| fastapi | 0.111.0 | 0.136.3 |
| pydantic | 2.7.0 | 2.13.4 |
| pydantic-settings | 2.3.0 | 2.14.1 |
| PyJWT[crypto] | 2.8.0 | 2.13.0 |
| httpx | 0.27.0 | 0.28.1 |
| uvicorn | 0.29.0 | 0.49.0 |
| cryptography | 42.0.0 | 46.0.6 |

No known CVEs identified at current versions.

### Test suite

283 tests. All pass. No live IdP required. See Task 21 / validation run for current results.

### API contract

`EvaluateResponse`: `correlation_id` always present (set from `request.state.correlation_id`, never None); `policy_version` omitted when `POLICY_VERSION` not configured (verified by `test_policy_version_null_when_not_configured` and `exclude_none=True`). README examples updated to reflect actual behavior.

`GET /ready` component list matches `readiness.py` registrations and README documentation.

`X-Correlation-ID` header present on all response paths via `CorrelationMiddleware`.

### Architecture invariants

All four invariants confirmed for v0.1:

1. **Kernel evaluates. Gateway enforces. Audit records evidence.** The gateway does not reinterpret, supplement, or override `basis-core` decisions. Verified in `api/routes.py` and `core/evaluator.py`.

2. **Subject identity from token only.** `EvaluateRequest` rejects `subject_id` and `subject_roles` in the request body. Verified in `api/schemas.py`.

3. **Fail closed on every error path.** Unexpected evaluation errors produce DENY; audit write failures do not alter authorization decisions. Verified in `api/routes.py` and `audit/writer.py`.

4. **Correlation IDs are gateway-generated.** `CorrelationMiddleware` generates the ID unconditionally; caller-supplied `X-Correlation-ID` headers are ignored. Verified in `middleware/correlation.py`.

---

## Conditions for release

The following should be confirmed before tagging v0.1.0:

1. **`pyproject.toml` version field** — verify it reads `0.1.0` or update it to match the release tag.
2. **Validation suite** — `pytest`, `ruff check`, `ruff format --check`, `mypy src` all pass on the release commit.
3. **GitHub repository visibility** — confirm the repository is ready to be made public.
4. **`basis-core` public availability** — confirm the `basis-core` sibling repository is public and tagged at `v0.1.0` before promoting `basis-gateway` publicly; the setup instructions reference the sibling checkout path.

---

## What this release is not

This release is not:

- Production-ready for deployment in OT environments as a security control
- A complete BASIS ecosystem deployment (no `basis-console`, no `basis-adapters`, no persistent audit storage)
- A stable API with long-term compatibility guarantees (pre-1.0)

These constraints are documented in `SECURITY.md`, `docs/release-readiness.md`, and the v0.1.0 release notes.

---

## Related

- [`docs/release-checklist.md`](release-checklist.md) — checklist used to produce this assessment
- [`docs/releases/v0.1.0.md`](releases/v0.1.0.md) — release notes
- [`docs/release-readiness.md`](release-readiness.md) — scope, limitations, and architecture invariants
- [`CHANGELOG.md`](../CHANGELOG.md) — changelog entry
- [`SECURITY.md`](../SECURITY.md) — security policy and known limitations
