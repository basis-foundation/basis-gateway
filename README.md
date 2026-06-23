# basis-gateway

`basis-gateway` is the authentication, identity normalization, and HTTP enforcement boundary for the BASIS ecosystem. It sits between external callers and `basis-core`. It does not evaluate policy — it delegates every authorization decision to `basis-core` via the stable public API and enforces the result at the HTTP boundary.

This repository contains the reference implementation of basis-gateway.

The project is released as v0.1.0 and is intended for evaluation, experimentation, and community feedback. Production adoption should be preceded by environment-specific validation and security review.

---

## What's implemented

- **OIDC/JWT authentication** — Bearer token verification (RS256/RS384/RS512/ES256/ES384/ES512); `alg=none` rejected; JWKS cached with configurable TTL; OIDC discovery or explicit JWKS URI override
- **Identity normalization** — verified JWT claims mapped to `NormalizedSubject` and `IdentityContext`; subject identity never accepted from the request body
- **Policy loading** — JSON policy file loaded at startup; service will not become ready if missing or invalid
- **Authorization evaluation** — `POST /v1/evaluate` delegates to `basis-core` `EnforcementPoint`; gateway enforces the returned decision at the HTTP boundary
- **Audit evidence** — gateway-level `AuditEvent` records emitted for every outcome, including pre-evaluation failures; all events carry the same `correlation_id` as the response header
- **Correlation IDs** — UUIDv4 generated per request by middleware; included in every response header and all audit records; caller-supplied `X-Correlation-ID` headers are ignored
- **Per-component readiness** — `/ready` reports `configuration_loaded`, `oidc_configured`, `jwks_available`, `policy_loaded`, `audit_writer`, `evaluator_initialized`
- **Audit failure escalation** — configurable degradation threshold; optional strict fail-closed mode blocks evaluation when the audit pipeline is unhealthy
- **Fail-closed on every error path** — unexpected errors deny rather than permit

Tests run without a live IdP. See `tests/` for the current test count.

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

### Sibling repository layout

`basis-gateway` depends on the BASIS `basis-core` library. This is **not** the unrelated public
PyPI package named `basis-core` — it is the sibling repository in the same checkout tree.

Both repositories must be checked out as siblings:

```
REPOS/
  basis-core/      ← the BASIS basis-core repo
  basis-gateway/   ← this repo
```

### Install order

Always install `basis-core` first so that `pip` resolves it from the local editable install
rather than attempting to download the wrong package from PyPI.

```bash
cd ~/REPOS/basis-gateway

python3.10 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip setuptools wheel

pip install -e ../basis-core
pip install -e ".[dev]"
```

### Verify the correct package is installed

```bash
python -c "import basis_core; print(basis_core.__file__)"
```

Expected output (path will vary by username):

```
/Users/<you>/REPOS/basis-core/src/basis_core/__init__.py
```

If the path points into `.venv/lib/.../site-packages/basis_core/` without referencing the
local sibling checkout, the wrong package was installed. See [Troubleshooting](#troubleshooting)
below.

### Continue setup

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
| `AUDIT_FAILURE_THRESHOLD` | `10` | Consecutive audit write failures before `audit_writer` readiness degrades. Must be ≥ 1. See [Audit failure escalation](#audit-failure-escalation). |
| `AUDIT_FAIL_CLOSED` | `false` | When `true`, a degraded audit writer causes `/v1/evaluate` to return `503`. Default `false` degrades readiness only. |

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

When a policy is configured, `/ready` also tracks the `audit_writer` component. If consecutive audit write failures cross `AUDIT_FAILURE_THRESHOLD`, `audit_writer` is marked not-ready and `/ready` returns 503. Readiness restores automatically after the first successful write.

---

## Audit failure escalation

`GatewayAuditWriter` tracks consecutive audit write failures. When the count reaches `AUDIT_FAILURE_THRESHOLD` (default: 10), the gateway marks the `audit_writer` readiness component not-ready and `/ready` returns 503. This signals to orchestrators and operators that the audit pipeline requires attention.

**Recovery** is automatic: the first successful write after degradation resets the consecutive counter and restores readiness. No process restart is required.

**Default behavior (Model B — readiness degradation):** `/v1/evaluate` continues to serve authorization requests even when the audit writer is degraded. Appropriate for OT environments (hospitals, industrial facilities, commercial buildings) where authorization availability is a safety requirement.

**Strict fail-closed mode (Model C — `AUDIT_FAIL_CLOSED=true`):** when enabled, a degraded audit writer additionally causes `/v1/evaluate` to return `503`. No evaluation proceeds until the audit pipeline recovers. Appropriate for strict-compliance deployments where an unrecorded authorization decision is a regulatory violation.

> **Important**: neither mode can cause the kernel to produce an ALLOW decision it would not otherwise have produced. Audit failure never grants access.

See `docs/audit-failure-escalation.md` for the complete architecture decision, failure scenarios, and security analysis.

---

## Evaluation flow

Every authorized request follows this path:

```
Bearer token in Authorization header
        ↓
JWT verification (signature, issuer, audience, algorithm)
        ↓
Identity normalization → NormalizedSubject (subject_id, roles)
        ↓
DecisionRequest → basis-core EnforcementPoint
        ↓
DecisionResponse (ALLOW / DENY / NOT_APPLICABLE)
        ↓
HTTP 200 or 403 returned to caller
        ↓
AuditEvent written (correlation_id links all records)
```

Gateway-level `AuditEvent` records are also emitted for failures that occur before the kernel is reached (authentication failures, validation errors, evaluator unavailable). All records share the same `correlation_id` as the `X-Correlation-ID` response header.

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
- `resource_type` — domain for an adapter-normalized (bare-verb) action and/or the type for a local `resource_id`; see [Action composition](#action-composition) and [Resource identifier composition](#resource-identifier-composition) below
- `resource_id` — resource identifier for the action; a local id (e.g. `rooftop-1`) is composed with `resource_type` into a typed `ahu:rooftop-1`, an already-typed id is passed through; omit if not applicable
- `context` — string key/value pairs passed through to the policy rule

### Action composition

`basis-core` evaluates **composite** action strings in the `{verb}:{domain}[:{object}]` form (e.g. `read:ahu`). `basis-adapters`, however, normalize a protocol operation into a **bare verb** (`read`) plus a separate `resource_type` (`ahu`). The gateway is the runtime boundary that reconciles the two, so `/v1/evaluate` accepts **both** request styles:

**1. Direct, kernel-compatible (composite action):**

```json
{ "action": "read:ahu", "resource_id": "ahu:rooftop-1" }
```

The action is passed through to `basis-core` unchanged.

**2. Adapter-normalized (bare verb + `resource_type`):**

```json
{ "action": "read", "resource_type": "ahu", "resource_id": "rooftop-1" }
```

The gateway composes `action` and `resource_type` into `read:ahu`, and the local `resource_id` and `resource_type` into the typed `ahu:rooftop-1`, before evaluation.

Rules:

- `resource_type` is **optional** for a composite action and **required** for a bare verb.
- A bare verb without `resource_type` is rejected (`400 validation_failed`) — the gateway will not silently submit an action the kernel cannot evaluate.
- Supplying both a composite action **and** a `resource_type` is ambiguous and rejected (`400 validation_failed`).

This is the only thing the gateway does to the action: it **assembles** a kernel-compatible request. It does not evaluate authorization, define or extend the action vocabulary, or parse any protocol. Adapters remain protocol-normalization libraries; `basis-core` remains the authorization kernel and the authority that validates the action.

**Composition evidence.** When the gateway composes a bare action, it records evidence in the evaluation context under the reserved `basis_gateway.*` namespace, so the composition is visible to policies and audit and is never silently applied:

```json
{
  "basis_gateway.action_composed": "true",
  "basis_gateway.original_action": "read",
  "basis_gateway.resource_type": "ahu",
  "basis_gateway.composed_action": "read:ahu"
}
```

Callers must not supply `basis_gateway.*` context keys themselves; a request that does is rejected (`400 validation_failed`) so composition evidence cannot be forged. Composite (pass-through) requests receive no such evidence.

### Resource identifier composition

The companion to action composition. `basis-core` identifies a resource with a **typed** `{type}:{qualifier}` string (e.g. `ahu:rooftop-1`). Adapters, however, emit a **local** `resource_id` (e.g. `rooftop-1`) alongside the same `resource_type` they carry for the action. The gateway composes the two, so `/v1/evaluate` accepts both styles:

**1. Direct, kernel-compatible (typed `resource_id`):**

```json
{ "action": "read:ahu", "resource_id": "ahu:rooftop-1" }
```

The `resource_id` is passed through to `basis-core` unchanged.

**2. Adapter-normalized (local `resource_id` + `resource_type`):**

```json
{ "action": "read", "resource_type": "ahu", "resource_id": "rooftop-1" }
```

The gateway composes `resource_type` and `resource_id` into `ahu:rooftop-1` before evaluation.

Rules:

- A local `resource_id` (no `:`) is composed with `resource_type` into the typed `{resource_type}:{resource_id}`.
- An already-typed `resource_id` (contains a `:`) with **no** `resource_type` is passed through unchanged.
- Supplying a `resource_type` alongside an **already-typed** `resource_id` is rejected (`400 validation_failed`) — the gateway must not accept two sources of resource-type truth, even when the prefix matches.
- A **local** `resource_id` with **no** `resource_type` is rejected (`400 validation_failed`) — the gateway cannot construct a canonical identifier from a local id alone.
- A `resource_type` with **no** `resource_id` is **not** a resource error: it is a resource-independent (or domain-level) request and composes no `resource_id`. The `resource_type` may still drive action composition.

A resource-independent request (no `resource_type`, no `resource_id`) — e.g. `{ "action": "read:audit:log" }` — passes through unchanged.

**Composition evidence.** When the gateway composes a local `resource_id`, it records evidence under the reserved `basis_gateway.*` namespace:

```json
{
  "basis_gateway.resource_composed": "true",
  "basis_gateway.original_resource_id": "rooftop-1",
  "basis_gateway.resource_type": "ahu",
  "basis_gateway.composed_resource_id": "ahu:rooftop-1"
}
```

As with action composition, callers must not supply `basis_gateway.*` context keys; pass-through and resource-independent requests receive no resource-composition evidence.

**Response (ALLOW, 200):**
```json
{
  "request_id": "a1b2c3d4-...",
  "outcome": "allow",
  "reason": "Subject holds a role permitted for 'read:sensor:telemetry'.",
  "correlation_id": "c9d8e7f6-..."
}
```

**Response (DENY, 403):**
```json
{
  "request_id": "a1b2c3d4-...",
  "outcome": "deny",
  "reason": "Action 'read:sensor:telemetry' requires one of ['admin', 'operator', 'viewer']; subject holds ['guest'].",
  "correlation_id": "c9d8e7f6-..."
}
```

`policy_version` is included in the response body when `POLICY_VERSION` is configured; it is omitted when not set. `correlation_id` is always present and matches the `X-Correlation-ID` response header.

The `X-Correlation-ID` response header is set on all gateway responses. It contains a
gateway-generated UUIDv4. Caller-supplied `X-Correlation-ID` request headers are ignored
and not used as the authoritative correlation ID.

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

The following are not implemented and will not be added without a deliberate scope decision:

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

## Troubleshooting

### `pip install -e ".[dev]"` tries to download `basis-core` from PyPI

**Symptom:** `pip` fetches or attempts to fetch a `basis-core` package from PyPI during
`pip install -e ".[dev]"`. You may also see unexpected compile errors for `numpy`, `pandas`,
or `pyarrow` — those are pulled in by the unrelated PyPI package, not this project.

**Cause:** The local BASIS `basis-core` repository was not installed before running
`pip install -e ".[dev]"`.

**Fix:** Recreate the virtual environment and install in the correct order:

```bash
deactivate
rm -rf .venv

python3.10 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip setuptools wheel
pip install -e ../basis-core
pip install -e ".[dev]"
```

Then verify:

```bash
python -c "import basis_core; print(basis_core.__file__)"
```

The path must reference `../basis-core/src/basis_core/__init__.py`, not `.venv/site-packages`.

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

tests/          — see pytest output for current count; no live IdP required
.env.example    — documented environment variable reference
```

---

## Related documents

- [`docs/release-readiness.md`](docs/release-readiness.md) — v0.1 scope, known limitations, out-of-scope items, architecture invariants confirmed
- [`docs/release-candidate-assessment.md`](docs/release-candidate-assessment.md) — v0.1 release candidate assessment and verdict
- [`docs/releases/v0.1.0.md`](docs/releases/v0.1.0.md) — v0.1.0 release notes
- [`docs/release-checklist.md`](docs/release-checklist.md) — release checklist for v0.1 and future releases
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — startup failures, readiness diagnostics, OIDC/JWKS issues, policy errors, audit writer degradation, strict fail-closed behavior
- [`docs/audit-model.md`](docs/audit-model.md) — audit boundary, correlation ID flow, identity evidence, failure behavior, known limitations
- [`docs/audit-failure-escalation.md`](docs/audit-failure-escalation.md) — audit failure escalation architecture, failure scenarios, security analysis, and Model B/C trade-offs
- [`.env.example`](.env.example) — annotated environment variable reference with placeholder values
- [`docs/implementation/basis-gateway-v0.1-plan.md`](docs/implementation/basis-gateway-v0.1-plan.md) — v0.1 implementation plan
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
