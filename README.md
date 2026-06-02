# basis-gateway

`basis-gateway` is the authentication, identity normalization, and HTTP enforcement boundary for the BASIS ecosystem. It sits between external callers and `basis-core`. It does not evaluate policy — it delegates every authorization decision to `basis-core` via the stable public API and enforces the result at the HTTP boundary.

This is a private implementation repository. The service is not production-ready.

---

## What this repository currently contains

**Phase 1 skeleton only.** This commit establishes the runnable service foundation:

- `src/basis_gateway/` — Python package with FastAPI application, configuration loading, and readiness state
- `GET /health` — liveness probe; returns `{"status": "ok", "service": "basis-gateway"}`
- `GET /ready` — readiness probe; returns `200` after successful startup, `503` if not ready
- `src/basis_gateway/config.py` — environment-variable-driven configuration with validation
- `src/basis_gateway/readiness.py` — thread-safe readiness state set during lifespan startup
- `tests/` — 18 tests covering health, readiness, and configuration
- `pyproject.toml` — project config, ruff, mypy (strict), pytest

---

## What is intentionally out of scope in this skeleton

The following will be added in later phases and must not be added here:

- JWT/OIDC token verification (`auth/oidc.py`)
- Subject and identity normalization (`auth/subject_mapper.py`)
- `basis-core` `EnforcementPoint` integration (`core/evaluator.py`)
- `POST /v1/evaluate` authorization endpoint
- Audit writer implementation
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

Run the service locally (no external dependencies required for the skeleton):

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
| `SERVICE_NAME` | `basis-gateway` | Service identifier included in health/ready responses |

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

**Phase 2: OIDC verifier and subject mapper**

1. Add `auth/oidc.py` — JWT signature verification, JWKS fetch and caching, issuer/audience validation
2. Add `auth/subject_mapper.py` — map verified claims to `basis-core` `Subject` and `IdentityContext` (without using the deprecated `subject_from_jwt`)
3. Update `/ready` to check JWKS reachability
4. Add `test_auth.py` and `test_subject_mapper.py`

**Phase 3: basis-core integration and evaluate endpoint**

1. Add `core/evaluator.py` — `EnforcementPoint` initialization and wrapper
2. Add `audit/writer.py` — `AuditWriter` implementation (initially `LogAuditWriter`)
3. Add `POST /v1/evaluate` — full request lifecycle: auth → normalize → evaluate → enforce → audit
4. Add `test_evaluate.py` and `test_fail_closed.py`
