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

### Phase 3 — basis-core integration and `/v1/evaluate` ✓
- `POST /v1/evaluate` — full authorization lifecycle; subject from JWT, not request body
- `src/basis_gateway/core/evaluator.py` — `GatewayEvaluator` wrapping `basis-core` `EnforcementPoint`; demo RBAC policy for v0.1
- `src/basis_gateway/audit/writer.py` — `GatewayAuditWriter` delegating to `LogAuditWriter`; write failures logged, never propagated
- `basis-core` integrated as package dependency; `EnforcementPoint` initialized at lifespan startup
- 35 new tests (102 total): evaluate, fail-closed, audit

### Still out of scope
- Production policy loading (v0.1 uses a demo `RolePolicyRule`)
- Persistent audit storage beyond log output
- `POST /v1/batch/evaluate`
- mTLS, rate limiting, admin API

## What this repository currently contains

Phases 1–3 are complete. The service starts, authenticates callers via OIDC JWT, normalizes identity, evaluates authorization requests against `basis-core`, and returns enforced decisions with audit emission.

- `GET /health` — liveness probe; always 200 when the process is running
- `GET /ready` — readiness probe; 200 when config + evaluator are initialized
- `POST /v1/evaluate` — authorization evaluation (see usage below)
- `src/basis_gateway/auth/` — OIDC verifier, subject mapper, error types
- `src/basis_gateway/core/evaluator.py` — `GatewayEvaluator` wrapping `basis-core` `EnforcementPoint`
- `src/basis_gateway/audit/writer.py` — `GatewayAuditWriter`
- `tests/` — 102 tests; no live IdP required
- `pyproject.toml` — project config, ruff, mypy (strict), pytest

---

## POST /v1/evaluate

Requires a valid Bearer token in the `Authorization` header. Subject identity is derived from the token — do not provide `subject_id` or `subject_roles` in the body.

```bash
curl -X POST http://localhost:8000/v1/evaluate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "read:sensor:telemetry",
    "resource_id": "sensor:ahu-1"
  }'
```

**Response (ALLOW):**
```json
{"request_id": "...", "outcome": "allow", "reason": "...", "policy_version": null}
```

**Response (DENY or NOT_APPLICABLE):** HTTP 403 with `"outcome": "deny"` or `"outcome": "not_applicable"`.

The `X-Correlation-ID` header is always present in the response.

**v0.1 policy note:** The service uses a built-in demo `RolePolicyRule`. Roles come from the `realm_access.roles` or `roles` JWT claim. This is a temporary placeholder — a real policy configuration mechanism is planned for a future phase.

---

## What is intentionally out of scope

The following will be added in later phases:

- Production policy loading (demo RBAC rule only in v0.1)
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
| `OIDC_ISSUER` | _(none)_ | Token issuer URL; used for discovery and `iss` validation. Without this, `/v1/evaluate` rejects all requests. |
| `OIDC_AUDIENCE` | _(none)_ | Expected `aud` claim. If unset, audience is not validated. |
| `OIDC_JWKS_URI` | _(none)_ | Override JWKS endpoint; skips OIDC discovery when set. |
| `JWKS_CACHE_TTL_SECONDS` | `300` | JWKS in-memory cache TTL in seconds. |
| `POLICY_VERSION` | _(none)_ | Version string included in evaluation responses and audit records. |

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

**Phase 4: production hardening**

1. Policy configuration mechanism — replace the v0.1 demo `RolePolicyRule` with a real policy loading path (file-based, env-driven, or configurable)
2. `OIDC_ISSUER` required at startup when `POST /v1/evaluate` is active (currently optional; service degrades gracefully)
3. `/ready` OIDC component — check JWKS reachability as a readiness condition
4. Observability — structured logging with request/correlation IDs, metrics hooks for audit failure count and evaluation latency
5. `POST /v1/batch/evaluate` — batch evaluation endpoint (out of scope for v0.1)
6. Subject type inference — use claim-based heuristics to populate `SubjectType` beyond `HUMAN`
