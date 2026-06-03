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
- `src/basis_gateway/core/evaluator.py` — `GatewayEvaluator` wrapping `basis-core` `EnforcementPoint`
- `src/basis_gateway/audit/writer.py` — `GatewayAuditWriter` delegating to `LogAuditWriter`; write failures logged, never propagated
- `basis-core` integrated as package dependency; `EnforcementPoint` initialized at lifespan startup
- 35 new tests (102 total): evaluate, fail-closed, audit

### Phase 4 — Policy loading and readiness hardening ✓
- `src/basis_gateway/policy/loader.py` — `load_policy_engine()` reads a JSON policy file at startup; raises `PolicyLoadError` on missing file, invalid JSON, or schema errors
- Policy required at startup when `OIDC_ISSUER` is set; startup fails predictably with a clear error when `POLICY_PATH` is absent
- `/ready` now returns per-component readiness state: `configuration_loaded`, `oidc_configured`, `jwks_available`, `policy_loaded`, `evaluator_initialized`
- Demo `RolePolicyRule` removed from the runtime path; `policies/default.json` is the checked-in example policy
- 34 new tests (136 total): policy loader, readiness components, startup integration

### Phase 5 — Example policy and runtime documentation ✓
- `policies/default.json` — checked-in example policy covering all standard basis-core actions
- `.env.example` — documented environment variable reference with placeholder values
- README updated to reflect Phase 4/5 runtime shape

---

## What the gateway requires

When evaluation is enabled (i.e., `OIDC_ISSUER` is set), the gateway requires all of the following before it will serve authorization requests:

- **OIDC issuer** — `OIDC_ISSUER` must be set to a reachable issuer URL. The gateway uses OIDC discovery to locate the JWKS endpoint and validate `iss` claims.
- **JWKS availability** — the JWKS endpoint discovered from the issuer must be reachable at startup.
- **Policy file** — `POLICY_PATH` must point to a valid JSON policy file. The file is loaded once at startup.
- **Evaluator initialization** — the `EnforcementPoint` must be successfully constructed from the loaded policy.

If any of these fail, the service starts but `/ready` returns `503` until all components are initialized. This is intentional fail-closed behavior: a misconfigured gateway will not serve requests rather than silently denying them with a generic error.

When `OIDC_ISSUER` is not set, the gateway starts without OIDC or policy initialization. `/v1/evaluate` rejects all requests with `401 Authentication not configured`. This is the default local-dev mode and is not suitable for production.

---

## Local setup

**Requirements:** Python 3.10+

```bash
git clone <repo>
cd basis-gateway
pip install -e ".[dev]"
```

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
# Edit .env with your OIDC issuer and other settings
```

Start the service:

```bash
uvicorn basis_gateway.main:app --reload
```

The service starts on `http://localhost:8000` by default.

---

## Minimum local configuration (evaluation enabled)

```bash
OIDC_ISSUER=https://your-idp.example.com/realms/your-realm
OIDC_AUDIENCE=basis-gateway
POLICY_PATH=policies/default.json
```

With these three variables set, the gateway will:
1. Discover the JWKS endpoint from the issuer
2. Load `policies/default.json`
3. Initialize the evaluator
4. Mark all readiness components ready

See `.env.example` for the full list of supported variables.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8000` | Bind port |
| `LOG_LEVEL` | `INFO` | Python log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `ENVIRONMENT` | `local` | Deployment environment (`local`, `development`, `staging`, `production`) |
| `SERVICE_NAME` | `basis-gateway` | Service identifier in health/ready responses |
| `OIDC_ISSUER` | _(none)_ | Token issuer URL; required to enable `/v1/evaluate`. Used for OIDC discovery and `iss` validation. |
| `OIDC_AUDIENCE` | _(none)_ | Expected `aud` claim. If unset, audience is not validated. |
| `OIDC_JWKS_URI` | _(none)_ | Override JWKS endpoint; skips OIDC discovery when set. |
| `JWKS_CACHE_TTL_SECONDS` | `300` | JWKS in-memory cache TTL in seconds. |
| `POLICY_PATH` | _(none)_ | Path to JSON policy file. Required when `OIDC_ISSUER` is set. |
| `POLICY_VERSION` | _(none)_ | Version string included in evaluation responses and audit records. |

---

## GET /ready

Returns `200` when all required components are initialized. Returns `503` when any required component is not ready.

**Ready response (200):**
```json
{
  "status": "ready",
  "service": "basis-gateway",
  "components": {
    "configuration_loaded": true,
    "oidc_configured": true,
    "jwks_available": true,
    "policy_loaded": true,
    "evaluator_initialized": true
  }
}
```

**Not-ready response (503):**
```json
{
  "status": "not_ready",
  "service": "basis-gateway",
  "components": {
    "configuration_loaded": true,
    "oidc_configured": false
  },
  "reason": "OIDC verifier initialization failed: ..."
}
```

The `reason` field describes the first failed component. The `components` dict shows which components have been reached.

---

## POST /v1/evaluate

Requires a valid Bearer token in the `Authorization` header. Subject identity is derived from the token — do not provide `subject_id` or `subject_roles` in the body.

```bash
curl -X POST http://localhost:8000/v1/evaluate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "read:sensor:telemetry",
    "resource_id": "sensor:ahu-1",
    "context": {}
  }'
```

**Optional fields:**
- `request_id` — caller-supplied request ID; a UUID is generated if omitted
- `resource_id` — resource identifier for the action; omit if not applicable
- `context` — string key/value pairs passed through to the policy rule

**Response (ALLOW, 200):**
```json
{
  "request_id": "a1b2c3d4-...",
  "outcome": "allow",
  "reason": "Subject holds a role permitted for 'read:sensor:telemetry'.",
  "policy_version": null
}
```

**Response (DENY, 403):**
```json
{
  "request_id": "a1b2c3d4-...",
  "outcome": "deny",
  "reason": "Action 'read:sensor:telemetry' requires one of ['admin', 'operator', 'viewer']; subject holds ['guest'].",
  "policy_version": null
}
```

The `X-Correlation-ID` response header is always set to a gateway-generated UUID.

> **Note:** A valid OIDC token from the configured issuer is required. The examples above will return `401` without a real token signed by the configured IdP.

---

## Policy file format

The gateway loads a single JSON policy file at startup. The file must contain a `rules` array with at least one rule. Each rule specifies a `role_table` mapping action strings to permitted role names.

```json
{
  "rules": [
    {
      "rule_name": "my-rbac",
      "role_table": {
        "read:sensor:telemetry": ["viewer", "operator", "admin"],
        "write:hvac:setpoint":   ["operator", "admin"]
      }
    }
  ]
}
```

Action strings must match the action constants defined in `basis-core`. See `policies/default.json` for a complete example covering all standard actions.

**Policy loading behavior:**
- The policy file is loaded once at startup. There is no dynamic reload.
- If the file is missing or invalid, startup continues but the service does not become ready (`/ready` returns `503`).
- When `OIDC_ISSUER` is set and `POLICY_PATH` is absent, startup fails immediately with a clear error message.
- There is no policy authoring API. Edit the JSON file and restart the service.

---

## What is intentionally out of scope

The following are not implemented and will not be added without a new phase decision:

- Policy authoring UI or API
- Dynamic policy reload without restart
- Policy versioning or deployment pipeline
- Policy storage service or database
- Docker, docker-compose, Kubernetes manifests
- GitHub Actions or CI configuration
- Protocol adapters
- `basis-console` integration
- Metrics and distributed tracing
- Distributed policy synchronization
- OPA, Cedar, or other external policy engines

---

## Commands

```bash
# Run tests
python -m pytest

# Lint
ruff check .

# Format check
ruff format --check .

# Type check
mypy src --cache-dir /tmp/mypy-cache-basis-gateway
```

---

## Repository layout

```
src/basis_gateway/
  api/          — routes, request/response schemas
  auth/         — OIDC verifier, subject mapper, error types
  audit/        — audit writer (delegates to basis-core LogAuditWriter)
  core/         — GatewayEvaluator wrapping basis-core EnforcementPoint
  policy/       — policy loader (reads JSON, constructs PolicyEngine)
  config.py     — environment-variable configuration
  main.py       — FastAPI app, lifespan startup/shutdown
  readiness.py  — per-component readiness tracker

policies/
  default.json  — example policy covering all standard basis-core actions

tests/          — 139 tests; no live IdP required
.env.example    — documented environment variable reference
```

---

## Related documents

- [`docs/basis-gateway-v0.1-plan.md`](docs/basis-gateway-v0.1-plan.md) — v0.1 implementation plan
- [`basis-architecture/docs/architecture/basis-gateway.md`](../basis-architecture/docs/architecture/basis-gateway.md) — architectural boundaries, trust model, invariants, and component responsibilities
- [`basis-core/docs/public-api.md`](../basis-core/docs/public-api.md) — the stable public API this gateway calls into

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
