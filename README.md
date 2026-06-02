# basis-gateway

`basis-gateway` is the authentication, identity normalization, and HTTP enforcement boundary for the BASIS ecosystem. It sits between external callers and `basis-core`. It does not evaluate policy — it delegates every authorization decision to `basis-core` via the stable public API and enforces the result at the HTTP boundary.

This is a private implementation repository. The service is not production-ready.

---

## Current implementation status

### Phase 1 — Service skeleton ✓
- `GET /health` — liveness probe
- `GET /ready` — readiness probe (returns 200 after startup, 503 if not ready)
- `src/basis_gateway/config.py` — environment-variable-driven configuration with validation
- `src/basis_gateway/readiness.py` — thread-safe readiness state set during lifespan startup
- 18 tests covering health, readiness, and configuration

### Phase 2 — OIDC verifier and subject mapper ✓
- `src/basis_gateway/auth/oidc.py` — Bearer token extraction, OIDC discovery, JWKS fetch/cache, JWT verification (RS256/RS384/RS512/ES256/ES384/ES512; `alg=none` rejected)
- `src/basis_gateway/auth/subject_mapper.py` — maps verified claims to `NormalizedSubject` and `IdentityContext`; no deprecated `subject_from_jwt` from `basis-core`
- `src/basis_gateway/auth/errors.py` — typed auth error hierarchy
- OIDC config fields added: `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URI`, `JWKS_CACHE_TTL_SECONDS`
- 49 new tests (67 total); local generated RSA keys, mock JWKS server — **no live IdP required**

### Not yet implemented
- `POST /v1/evaluate` — authorization endpoint (Phase 3)
- `basis-core` `EnforcementPoint` integration (Phase 3)
- Audit writer (Phase 3)

## What this repository currently contains

Phases 1 and 2 are complete. The service has a runnable FastAPI foundation, strict OIDC token verification, and deterministic subject normalization. `POST /v1/evaluate` and `basis-core` integration are Phase 3.

- `src/basis_gateway/` — Python package with FastAPI app, config, readiness, auth, subject mapper
- `GET /health` — liveness probe; returns `{"status": "ok", "service": "basis-gateway"}`
- `GET /ready` — readiness probe; returns `200` after startup, `503` if not ready
- `src/basis_gateway/auth/oidc.py` — OIDC verifier (discovery, JWKS cache, JWT verification)
- `src/basis_gateway/auth/subject_mapper.py` — claim-to-subject normalization
- `tests/` — 67 tests; no live IdP required
- `pyproject.toml` — project config, ruff, mypy (strict), pytest

---

## What is intentionally out of scope

The following will be added in later phases:

- `basis-core` `EnforcementPoint` integration (`core/evaluator.py`) — Phase 3
- `POST /v1/evaluate` authorization endpoint — Phase 3
- Audit writer implementation — Phase 3
- Docker, docker-compose, Kubernetes manifests
- GitHub Actions or CI configuration
- Protocol adapters
- `basis-console` integration
- Deployment tooling of any kind

---

## Local setup

**Requirements:** Python 3.10+

```bash
git clone <repo>
cd basis-gateway
pip install -e ".[dev]"
```

Run the service locally. No live IdP is required for Phase 1/2 tests:

```bash
uvicorn basis_gateway.main:app --reload
```

The service starts on `http://localhost:8000` by default. Environment variables:

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8000` | Bind port |
| `LOG_LEVEL` | `INFO` | Python log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `ENVIRONMENT` | `local` | Deployment environment (`local`, `development`, `staging`, `production`) |
| `SERVICE_NAME` | `basis-gateway` | Service identifier in health/ready responses |
| `OIDC_ISSUER` | _(none)_ | Token issuer URL; used for discovery and `iss` validation. Required in Phase 3. |
| `OIDC_AUDIENCE` | _(none)_ | Expected `aud` claim. If unset, audience is not validated. |
| `OIDC_JWKS_URI` | _(none)_ | Override JWKS endpoint; skips OIDC discovery when set. |
| `JWKS_CACHE_TTL_SECONDS` | `300` | JWKS in-memory cache TTL in seconds. |

---

## Commands

```bash
# Run tests
python -m pytest

# Lint
ruff check .

# Format check
ruff format --check .

# Type check (mypy cache must be on a writable filesystem)
mypy src --cache-dir /tmp/mypy-cache-basis-gateway
```

Optional Makefile targets (if you add a `Makefile`):

```bash
make test
make lint
make typecheck
```

---

## Related documents

- [`docs/basis-gateway-v0.1-plan.md`](docs/basis-gateway-v0.1-plan.md) — v0.1 implementation plan; full scope including JWT/OIDC, basis-core integration, and evaluate endpoint
- [`basis-architecture/docs/architecture/basis-gateway.md`](../basis-architecture/docs/architecture/basis-gateway.md) — architectural boundaries, trust model, invariants, and component responsibilities
- [`basis-core/docs/public-api.md`](../basis-core/docs/public-api.md) — the stable public API this gateway will call into (`EnforcementPoint`, `DecisionRequest`, `Subject`, `AuditWriter`, etc.)

---

## Architecture position

```
basis-console  (calls gateway APIs)
      ↓
basis-gateway  ←── basis-adapters (normalize and submit requests)
      ↓
basis-core     (evaluates; returns DecisionResponse)
```

`basis-gateway` authenticates callers, normalizes identity context, constructs kernel-compatible decision requests, invokes `basis-core`, enforces the returned decision, and emits audit evidence. It does not evaluate policy.

---

## Next implementation phase

**Phase 3: basis-core integration and evaluate endpoint**

1. Add `core/evaluator.py` — initialize `EnforcementPoint` during lifespan, wrap `evaluate()` call
2. Add `audit/writer.py` — `AuditWriter` implementation (initially `LogAuditWriter`)
3. Add `POST /v1/evaluate` — full request lifecycle: auth → normalize → evaluate → enforce → audit
4. Add `test_evaluate.py` and `test_fail_closed.py`
5. Wire OIDC verifier into the request path; require `OIDC_ISSUER` at startup
6. Update `/ready` to check JWKS reachability and `EnforcementPoint` initialization
