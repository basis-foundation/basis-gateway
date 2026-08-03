# basis-gateway

`basis-gateway` is the authenticated HTTP enforcement boundary for BASIS. It authenticates callers, normalizes identity, classifies trusted operation producers, composes governed operations and resources, invokes `basis-core`, enforces the returned disposition, records gateway and kernel evidence, and exposes health/readiness. It sits between external callers and `basis-core`.

**`basis-gateway` is not the policy engine.** It does not evaluate policy, define authorization semantics, or decide what is allowed — it delegates every authorization decision to `basis-core` via the stable public API and enforces the result at the HTTP boundary.

This repository contains the reference implementation of basis-gateway.

The v0.1 evaluation path (`POST /v1/evaluate`) is released as v0.1.0 and is intended for evaluation, experimentation, and community feedback. The operation-aware evaluation path (`POST /v1/evaluate/operation-aware`) is implemented and feature-flagged, disabled by default (see [Endpoints](#endpoints) below). Production adoption of either path should be preceded by environment-specific validation and security review.

---

## What's implemented

- **Runtime auth-mode selection** — `AUTH_MODE=oidc` (default) or `AUTH_MODE=basis_local_token` selects which verifier authenticates Bearer tokens on both evaluation endpoints; explicit configuration only, no fallback between modes; see [`docs/basis-local-token-trust.md`](docs/basis-local-token-trust.md#runtime-wiring-choosing-a-verifier-at-request-time)
- **OIDC/JWT authentication** — Bearer token verification (RS256/RS384/RS512/ES256/ES384/ES512); `alg=none` rejected; JWKS cached with configurable TTL; OIDC discovery or explicit JWKS URI override
- **BASIS-local token trust verifier** — verifies signed BASIS-local identity tokens issued by `basis-identity` (signature, issuer, audience, algorithm, timing, required identity claims); establishes identity trust only; wired into request authentication when `AUTH_MODE=basis_local_token`; does not import `basis-identity` or `basis-core`; see [`docs/basis-local-token-trust.md`](docs/basis-local-token-trust.md)
- **Identity normalization** — verified JWT claims mapped to `NormalizedSubject` and `IdentityContext`; subject identity never accepted from the request body
- **Policy loading** — JSON policy file loaded at startup; service will not become ready if missing or invalid
- **Authorization evaluation** — `POST /v1/evaluate` delegates to `basis-core` `EnforcementPoint`; gateway enforces the returned decision at the HTTP boundary
- **Operation-aware evaluation (feature-flagged, disabled by default)** — `POST /v1/evaluate/operation-aware` delegates to `basis-core`'s public `OperationAwareEnforcementPoint`; adds trusted operation-producer classification, richer operational context (location, device, protocol/safety/environment/risk context, identity/adapter evidence references), a startup semantic preflight, and exact evaluation-status/outcome/failure-reason-to-HTTP classification. See [`docs/operation-aware-endpoint.md`](docs/operation-aware-endpoint.md)
- **Audit evidence** — gateway-level `AuditEvent` records are emitted for every outcome on both endpoints, including pre-evaluation failures. For completed operation-aware evaluations, the durable outer record stores the contract-shaped `GatewayAuditEvent` and the complete kernel-produced `AuditEvidence` as sibling artifacts, linked by `audit_evidence_id`. All events carry the same `correlation_id` as the response header.
- **Correlation IDs** — UUIDv4 generated per request by middleware; included in every response header and all audit records; caller-supplied `X-Correlation-ID` headers are ignored
- **Per-component readiness** — `/ready` reports `configuration_loaded`, `oidc_configured`, `jwks_available`, `policy_loaded`, `audit_writer`, `evaluator_initialized`, and (when `OPERATION_AWARE_ENABLED=true`) `operation_aware_mode_enabled`, `operation_aware_bundle_loaded`, `operation_aware_evaluator_initialized`, `operation_aware_policy_semantically_valid`. See [`docs/readiness.md`](docs/readiness.md)
- **Audit failure escalation** — configurable degradation threshold; optional strict fail-closed mode blocks evaluation on both endpoints when the audit pipeline is unhealthy
- **Fail-closed on every error path** — unexpected errors deny rather than permit

Tests run without a live IdP. See `tests/` for the current test count.

---

## Endpoints

| Endpoint | Status | Notes |
|---|---|---|
| `POST /v1/evaluate` | Current, v0.1 | Always registered. Unaffected by the operation-aware path. |
| `POST /v1/evaluate/operation-aware` | Current, additive | Registered only when `OPERATION_AWARE_ENABLED=true` (default: `false`). See [`docs/operation-aware-endpoint.md`](docs/operation-aware-endpoint.md). |

- `/v1/evaluate` is the existing v0.1 path and requires no configuration change to keep working exactly as it does today.
- `/v1/evaluate/operation-aware` is additive: it does not replace, share a route with, or change the behavior of `/v1/evaluate`.
- Operation-aware mode is **disabled by default**. A deployment that does not set `OPERATION_AWARE_ENABLED=true` observes zero behavior change.
- Enabling operation-aware mode does not disable or deprecate `/v1/evaluate` — both endpoints may be enabled and served at the same time, on the same running instance, sharing the same authentication configuration and audit writer.
- Route registration for the operation-aware endpoint depends only on `OPERATION_AWARE_ENABLED` at startup; a later startup failure (bad bundle, failed preflight) leaves the route registered but returns a governed `503`, never a `404`.

---

## Conceptual example

Every request, on either endpoint, follows the same shape:

```text
authenticated subject                (Bearer token verified by AUTH_MODE's verifier)
        ↓
action/resource request               (caller/adapter-supplied, e.g. action="read", resource_type="ahu")
        ↓
gateway composition                   (bare verb + resource_type → canonical "read:ahu"; on the
                                        operation-aware path, also: producer-trust classification,
                                        provenance-gated context composition)
        ↓
core decision                         (basis-core EnforcementPoint / OperationAwareEnforcementPoint —
                                        the sole authority on ALLOW/DENY/NOT_APPLICABLE)
        ↓
gateway enforcement                   (HTTP status derived from the kernel result; never guessed)
        ↓
evidence                              (gateway + kernel audit records, correlation_id shared throughout)
```

This is a conceptual walkthrough, not a runnable demo environment — a bounded, reproducible demonstration is tracked separately (see [Roadmap](#roadmap)). See [POST /v1/evaluate](#post-v1evaluate) below for a working `curl` example against the v0.1 path, and [`docs/operation-aware-endpoint.md`](docs/operation-aware-endpoint.md) for request/response examples on the operation-aware path.

---

## Security boundaries

- **Trusted operation-producer status is configured explicitly** (`OPERATION_PRODUCER_SUBJECT_IDS`) — it is never inferred, self-asserted, or granted implicitly.
- **Roles do not grant producer trust.** Only exact subject-ID allowlist membership does.
- **Producer matching is exact and case-sensitive.** No wildcard, prefix, or case-insensitive matching exists.
- **Untrusted callers cannot assert producer-only context.** A caller not classified as a trusted operation producer that supplies any producer-only field (`operation_intent`, `location`, `device`, `protocol_context`, `safety_context`, `environment_context`, `risk_context`, `identity_evidence_reference`, `adapter_evidence_reference`) is rejected (`400`) before the kernel is ever invoked.
- **Kernel outcomes are not rewritten by the gateway.** `evaluation_status`, `outcome`, `failure_reason`, and `disposition` are preserved exactly as `basis-core` returns them.
- **`NOT_APPLICABLE` remains distinct from denial** in the response body and in audit evidence — only the gateway's separately-derived HTTP status collapses `deny`/`not_applicable` to the same code (`403`).
- **Failed evaluation retains a null outcome.** A `failed` `evaluation_status` never carries a substantive `outcome`, and a `completed` one is never missing one.
- **Audit write failure does not retroactively change the current decision.** A response already computed is returned to the caller regardless of whether its audit record was successfully written.
- **Strict audit fail-closed mode (`AUDIT_FAIL_CLOSED=true`) can block later evaluation** when the audit writer remains degraded — it cannot alter a decision already made, only suspend future ones until the audit pipeline recovers.

---

## Current limitations

- No policy hot reload — both the v0.1 role-table policy and the operation-aware `PolicyBundle` are loaded once at startup; changes require a restart.
- No remote policy distribution — policy and bundle files are loaded from a local filesystem path.
- No durable, database-backed audit store — audit events are written through `LogAuditWriter` (process log) only.
- No audit query API.
- No cryptographic audit signing.
- No tamper-evident audit chain.
- No adapter execution confirmation — the gateway proves an authorization decision, an enforcement disposition, and an HTTP result; it does not prove that a physical device executed the operation.
- No device-state verification.
- No background policy revalidation — the operation-aware startup semantic preflight runs once, at startup.
- No built-in multi-tenancy.
- No hosted-service control plane.
- No bounded, reproducible operation-aware demonstration yet (tracked as a future PR — see [Roadmap](#roadmap)).

---

## What the gateway requires

Which verifier the gateway requires depends on `AUTH_MODE` (default: `oidc`):

**`AUTH_MODE=oidc` (default) — evaluation enabled when `OIDC_ISSUER` is set:**

- **OIDC issuer** — `OIDC_ISSUER` must be set to a reachable issuer URL. The gateway uses OIDC discovery to locate the JWKS endpoint and validate `iss` claims.
- **JWKS availability** — the JWKS endpoint discovered from the issuer must be reachable at startup.
- **Policy file** — `POLICY_PATH` must point to a valid JSON policy file. The file is loaded once at startup.
- **Evaluator initialization** — the `EnforcementPoint` must be successfully constructed from the loaded policy.

**`AUTH_MODE=basis_local_token` — evaluation enabled by selecting this mode:**

- **BASIS-local token trust** — `BASIS_LOCAL_TOKEN_ISSUER`, `BASIS_LOCAL_TOKEN_AUDIENCE`, and `BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON` must all be set and valid (no `alg=none` or symmetric algorithm, no private-key-shaped material). See [`docs/basis-local-token-trust.md`](docs/basis-local-token-trust.md#configuring-basis-local-token-trust).
- **Policy file** and **evaluator initialization** — same requirements as `oidc` mode.
- `OIDC_ISSUER` and the other `OIDC_*` variables are not required and are not validated in this mode.

If any required component fails, the service starts but `/ready` returns `503` until all components are initialized. This is intentional fail-closed behavior: a misconfigured gateway will not serve requests rather than silently denying them with a generic error.

When neither mode's requirements are met (e.g. `AUTH_MODE=oidc` with `OIDC_ISSUER` unset), the gateway starts without verifier or policy initialization. `/v1/evaluate` rejects all requests with `401 Authentication not configured`. This is the default local-dev mode and is not suitable for production.

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

## Quick configuration overview

The minimum configuration needed for each concern:

| Concern | Minimum variables |
|---|---|
| Authentication (`oidc`, default) | `OIDC_ISSUER` (also enables `/v1/evaluate`) |
| Authentication (`basis_local_token`) | `AUTH_MODE=basis_local_token`, `BASIS_LOCAL_TOKEN_ISSUER`, `BASIS_LOCAL_TOKEN_AUDIENCE`, `BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON` |
| v0.1 evaluation | `POLICY_PATH` |
| Operation-aware evaluation | `OPERATION_AWARE_ENABLED=true`, `OPERATION_AWARE_POLICY_BUNDLE_PATH` |
| Producer trust (operation-aware only) | `OPERATION_PRODUCER_SUBJECT_IDS` (default empty — no caller is ever trusted) |
| Audit behavior | `AUDIT_FAILURE_THRESHOLD` (default `10`), `AUDIT_FAIL_CLOSED` (default `false`) |

See [`docs/configuration.md`](docs/configuration.md) for the full environment-variable reference (every variable, its default, and its source in `GatewayConfig`), and [`.env.example`](.env.example) for an annotated template.

---

## GET /ready

Returns `200` when all required components are initialized. Returns `503` when any required component is not ready. Only the components for the configured `AUTH_MODE` are ever registered: `oidc_configured`/`jwks_available` in `oidc` mode, `basis_local_token_configured` in `basis_local_token` mode — the inactive mode's component is never registered and so never blocks readiness. When `OPERATION_AWARE_ENABLED=true`, four additional components (`operation_aware_mode_enabled`, `operation_aware_bundle_loaded`, `operation_aware_evaluator_initialized`, `operation_aware_policy_semantically_valid`) are also registered and must all be ready. See [`docs/readiness.md`](docs/readiness.md) for the full component reference and failure matrix.

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

`GatewayAuditWriter` tracks consecutive audit write failures. It is a single, shared instance used by both `/v1/evaluate` and `/v1/evaluate/operation-aware` — there is one failure count and one degraded/recovered state, not two. When the count reaches `AUDIT_FAILURE_THRESHOLD` (default: 10), the gateway marks the `audit_writer` readiness component not-ready and `/ready` returns 503. This signals to orchestrators and operators that the audit pipeline requires attention.

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
Verification per AUTH_MODE (signature, issuer, audience, algorithm) —
oidc verifier or BASIS-local token verifier, never both, never inferred
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

## POST /v1/evaluate/operation-aware

Feature-flagged (`OPERATION_AWARE_ENABLED=true`), additive alternative that delegates to `basis-core`'s public `OperationAwareEnforcementPoint` instead of the v0.1 `EnforcementPoint`. Uses the same Bearer-token authentication as `/v1/evaluate`. Adds trusted operation-producer classification, richer optional operational context, and exact evaluation-status/outcome/failure-reason-to-HTTP classification (`200`/`400`/`403`/`500`/`503`).

See [`docs/operation-aware-endpoint.md`](docs/operation-aware-endpoint.md) for the full request/response reference, the action/resource grammar, producer-only field list, the semantic outcome matrix, and worked examples (allow, deny, default-deny, not-applicable, failed evaluation, untrusted-producer rejection, evaluator-unavailable).

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
- Metrics and distributed tracing
- Distributed policy synchronization
- OPA, Cedar, or other external policy engines

Operation-aware `basis-console` UI integration is not implemented in this repository. It is
planned as follow-on work in the `basis-console` repository, where Training mode and Operator
mode will consume the gateway APIs without changing gateway authorization semantics.
`basis-console` owns the user experience; `basis-gateway` remains the truth-producing
authorization and enforcement boundary. Neither console mode creates an alternate authorization
path: Training mode must not bypass authentication or authorization, and Operator mode must not
redefine kernel outcomes.

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
  auth/         — OIDC verifier, BASIS-local token verifier, runtime auth-mode
                  selection (auth/runtime.py), subject mapper, error types
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

- [`docs/configuration.md`](docs/configuration.md) — full environment-variable reference, sourced from `GatewayConfig`
- [`docs/operation-aware-endpoint.md`](docs/operation-aware-endpoint.md) — operation-aware endpoint reference: request/response shape, action/resource grammar, producer trust, outcome matrix, examples
- [`docs/readiness.md`](docs/readiness.md) — `/health` and `/ready`, all readiness components, the operation-aware failure matrix, operator troubleshooting
- [`docs/release-readiness.md`](docs/release-readiness.md) — v0.1 scope, known limitations, out-of-scope items, architecture invariants confirmed
- [`docs/release-readiness/operation-aware-gateway-readiness-review.md`](docs/release-readiness/operation-aware-gateway-readiness-review.md) — operation-aware gateway release-readiness review
- [`docs/release-candidate-assessment.md`](docs/release-candidate-assessment.md) — v0.1 release candidate assessment and verdict
- [`docs/releases/v0.1.0.md`](docs/releases/v0.1.0.md) — v0.1.0 release notes
- [`docs/release-checklist.md`](docs/release-checklist.md) — release checklist for v0.1 and future releases
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — startup failures, readiness diagnostics, OIDC/JWKS issues, policy errors, audit writer degradation, strict fail-closed behavior
- [`docs/audit-model.md`](docs/audit-model.md) — audit boundary, correlation ID flow, identity evidence, failure behavior, known limitations, operation-aware sibling-artifact model
- [`docs/audit-failure-escalation.md`](docs/audit-failure-escalation.md) — audit failure escalation architecture, failure scenarios, security analysis, and Model B/C trade-offs
- [`docs/basis-local-token-trust.md`](docs/basis-local-token-trust.md) — BASIS-local token trust contract, verifier behavior, and relationship to OIDC authentication
- [`.env.example`](.env.example) — annotated environment variable reference with placeholder values
- [`docs/implementation/basis-gateway-v0.1-plan.md`](docs/implementation/basis-gateway-v0.1-plan.md) — v0.1 implementation plan
- [`docs/implementation/operation-aware-gateway-integration-plan.md`](docs/implementation/operation-aware-gateway-integration-plan.md) — operation-aware integration plan (PRs 1–9 implemented; PR 10, this documentation pass, current; PR 11 demonstration pending)
- [`basis-architecture/docs/architecture/basis-gateway.md`](../basis-architecture/docs/architecture/basis-gateway.md) — architectural boundaries, trust model, invariants, and component responsibilities
- [`basis-core/docs/public-api.md`](../basis-core/docs/public-api.md) — the stable public API this gateway calls into

---

## Roadmap

- **Operation-aware gateway integration** — Status: **Implemented, feature-flagged** (`OPERATION_AWARE_ENABLED`, default `false`). See [`docs/implementation/operation-aware-gateway-integration-plan.md`](docs/implementation/operation-aware-gateway-integration-plan.md) for the full architecture and PR sequence adopting `basis-core` v0.2.1's operation-aware surface. `/v1/evaluate` is unaffected.
- **Bounded end-to-end demonstration (PR 11)** — Status: **Pending**. A documented, reproducible walkthrough covering allow/deny/default-deny/not-applicable/producer-rejection scenarios against the real gateway-to-kernel path. Not yet implemented. This is `basis-gateway` work — no console involvement.
- **Operation-aware `basis-console` integration** — Status: **Follow-on work in `basis-console`**. Training mode should explain identity, producer trust, composition, provenance, kernel outcome, gateway disposition, readiness, and evidence. Operator mode should present concise operational results and actionable failure information. Both modes must consume the same governed gateway behavior; neither creates an authorization bypass.

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
