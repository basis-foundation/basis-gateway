# Readiness and Liveness

`basis-gateway` exposes two operational endpoints:

```text
GET /health   — liveness
GET /ready    — readiness
```

This document describes both, the complete set of readiness components (v0.1 and
operation-aware), the failure matrix for the operation-aware stages, and operator
troubleshooting guidance.

---

## GET /health

- **Liveness only.** Confirms the process is running and able to respond to HTTP requests.
- **Does not imply evaluator readiness.** A `200` from `/health` says nothing about whether
  `/v1/evaluate` or `/v1/evaluate/operation-aware` can actually serve a request.
- **Remains available after a startup dependency failure.** Even when configuration, policy
  loading, authentication initialization, or operation-aware bundle processing fails, the
  process is still alive and `/health` still returns `200`. Use `/ready` to check whether the
  service can actually serve requests.

```json
{"status": "ok", "service": "basis-gateway"}
```

---

## GET /ready

- Reports every **registered** readiness component. A component that was never registered (an
  inactive auth mode's component, or any operation-aware component when
  `OPERATION_AWARE_ENABLED` is not set) does not block readiness — its absence is not a failure.
- Returns `200` only when **every registered** component is ready.
- Returns `503` when any registered component is not ready, along with `reason` (the first
  failing component's reason) and `reasons` (every failing component's reason).
- Disabled optional capabilities never register a blocking component. Enabling operation-aware
  mode is the only thing that adds the four components below; leaving it disabled changes
  nothing about `/ready`'s existing behavior.

### v0.1 and shared components

| Component | Meaning | Registered when |
|---|---|---|
| `configuration_loaded` | Environment variables parsed and validated successfully | Always |
| `oidc_configured` | OIDC verifier initialized | `AUTH_MODE=oidc` (default) |
| `jwks_available` | JWKS endpoint reachable and keys loaded | `AUTH_MODE=oidc` (default) |
| `basis_local_token_configured` | BASIS-local token trust configuration validated | `AUTH_MODE=basis_local_token` |
| `policy_loaded` | v0.1 role-table policy file loaded and parsed | `POLICY_PATH` set |
| `audit_writer` | Shared `GatewayAuditWriter` initialized and not degraded | `POLICY_PATH` set, or `OPERATION_AWARE_ENABLED=true` |
| `evaluator_initialized` | v0.1 `EnforcementPoint` constructed | `POLICY_PATH` set |

### Operation-aware components

Registered **only** when `OPERATION_AWARE_ENABLED=true`. A deployment that does not enable the
feature sees no readiness behavior change at all — none of the four components below are
registered, and they cannot block `/ready`.

| Component | Meaning | Registration condition | Ready transition | Representative failure stage |
|---|---|---|---|---|
| `operation_aware_mode_enabled` | The feature flag itself is set | `OPERATION_AWARE_ENABLED=true` | Marked ready immediately at startup, before any fallible step runs | Never fails on its own — informational only; it never implies the other three are ready |
| `operation_aware_bundle_loaded` | The operation-aware `PolicyBundle` was structurally loaded | `OPERATION_AWARE_ENABLED=true` | After `OPERATION_AWARE_POLICY_BUNDLE_PATH` is validated present and the file is successfully parsed into a structurally valid `PolicyBundle` | Missing path, missing file, malformed JSON, or a structurally invalid bundle (e.g. a required field missing) |
| `operation_aware_evaluator_initialized` | The operation-aware evaluator was constructed from the loaded bundle | `OPERATION_AWARE_ENABLED=true` | After `OperationAwareEnforcementPoint.for_bundle()` succeeds | Construction failure (not a realistic failure mode for an already-structurally-valid bundle — see the integration plan's PR 8 notes — but attributed here if it ever occurs) |
| `operation_aware_policy_semantically_valid` | The constructed evaluator passed the startup semantic preflight | `OPERATION_AWARE_ENABLED=true` | After a synthetic, reserved evaluation request completes (any outcome — allow, deny, or not-applicable — counts as a pass) through the real evaluator | Duplicate rule IDs, an unsupported condition operator, or any other semantic policy defect |

`operation_aware_policy_semantically_valid` is what closes the specific failure mode this
component exists to prevent: a bundle can be structurally loaded and the evaluator can be
constructed while the bundle is still semantically broken. Without this fourth, independent
component, `/ready` could report ready while every real evaluation call would fail with
`policy_validation_failure`.

**Sample `/ready` response, operation-aware enabled and fully ready:**

```json
{
  "status": "ready",
  "service": "basis-gateway",
  "components": {
    "configuration_loaded": true,
    "oidc_configured": true,
    "jwks_available": true,
    "policy_loaded": true,
    "audit_writer": true,
    "evaluator_initialized": true,
    "operation_aware_mode_enabled": true,
    "operation_aware_bundle_loaded": true,
    "operation_aware_evaluator_initialized": true,
    "operation_aware_policy_semantically_valid": true
  }
}
```

---

## Failure matrix

| Scenario | `operation_aware_mode_enabled` | `operation_aware_bundle_loaded` | `operation_aware_evaluator_initialized` | `operation_aware_policy_semantically_valid` |
|---|---:|---:|---:|---:|
| Disabled (`OPERATION_AWARE_ENABLED` unset/`false`) | absent | absent | absent | absent |
| Success | ready | ready | ready | ready |
| Bundle failure (missing path/file, malformed JSON, structurally invalid) | ready | not ready | not ready | not ready |
| Construction failure | ready | ready | not ready | not ready |
| Semantic failure (duplicate rule IDs, unsupported operator) | ready | ready | ready | not ready |
| Earlier auth/v0.1-policy failure (a prior startup stage failed before operation-aware processing ever ran) | ready | pending | pending | pending |

The last row matters operationally: if authentication configuration or v0.1 policy loading fails
*before* the operation-aware bundle-processing stage runs, the three fallible operation-aware
components are left in an honest **pending** state ("not yet reached") — never fabricated as a
bundle or semantic failure that was never actually evaluated. `operation_aware_mode_enabled`
itself is registered early enough (immediately after configuration loads) that it survives any
later stage's failure.

In every not-ready scenario, `/health` continues to return `200` (the process is alive) while
`/ready` returns `503`.

---

## Operator troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| Route returns `404` | Feature disabled | `OPERATION_AWARE_ENABLED` |
| Route returns `503` | Evaluator unavailable or startup failure | `/ready` components |
| `operation_aware_bundle_loaded` not ready | Missing, malformed, or structurally invalid bundle | Configured path and bundle contents |
| `operation_aware_policy_semantically_valid` not ready | Duplicate rule IDs, unsupported operator, other semantic policy failure | Startup logs and policy bundle |
| Producer-only context rejected (`400`) | Subject not in the configured producer allowlist | Exact `OPERATION_PRODUCER_SUBJECT_IDS` value — matching is exact and case-sensitive |
| `audit_writer` not ready | Sink write failures reached `AUDIT_FAILURE_THRESHOLD` | Audit logs and `/ready` |
| Strict mode (`AUDIT_FAIL_CLOSED=true`) returns `503` | Degraded writer's recovery probe failed | Audit sink availability |
| `not_applicable` returns `403` | Bundle scope excludes the request; the gateway still enforces denial | Response `outcome` (should read `"not_applicable"`, not `"deny"`) and `disposition` |

Startup logs record each component's milestone at `INFO` and each failure at `ERROR`, with the
failing component name in brackets, e.g.:

```text
ERROR ... Operation-aware startup semantic preflight failed [operation_aware_policy_semantically_valid]: ...
```

Readiness reasons are safe to surface to operators — they never include raw policy content,
condition values, bundle text, tokens, or private/public key material.

---

## Related documents

- [`docs/configuration.md`](configuration.md) — environment-variable reference
- [`docs/operation-aware-endpoint.md`](operation-aware-endpoint.md) — endpoint request/response reference
- [`docs/audit-failure-escalation.md`](audit-failure-escalation.md) — `audit_writer` degradation and recovery
- [`docs/troubleshooting.md`](troubleshooting.md) — v0.1 startup and operational troubleshooting
