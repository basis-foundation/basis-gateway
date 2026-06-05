# basis-gateway v0.1 Implementation Plan

**Status**: Implemented  
**Date**: 2026-06-02  
**Scope**: First buildable milestone of `basis-gateway`

> **Note:** This document records the design decisions made before implementation. It is preserved as a historical reference. Where the implementation diverged from the original plan, notes are included inline. For the current runtime behavior see [`README.md`](../../README.md) and [`docs/audit-model.md`](../audit-model.md).

---

## 1. Purpose

`basis-gateway` is the authentication, identity normalization, and HTTP enforcement boundary for the BASIS ecosystem. It sits between external callers and `basis-core`. It does not evaluate policy. It delegates every authorization decision to `basis-core` via the stable public API and enforces the result at the HTTP boundary.

This document translates the established `basis-gateway` architecture into the smallest runnable v0.1 milestone.

---

## 2. v0.1 Goal

Produce a Python service that:

- Accepts HTTP requests at a small, defined API surface.
- Verifies JWT/OIDC tokens from a configurable issuer.
- Normalizes verified claims into `basis-core` domain types.
- Constructs a `DecisionRequest` and calls `EnforcementPoint.evaluate()`.
- Returns a decision response and emits an audit event for every evaluated request.
- Fails closed on all error paths.

The goal is to prove the boundary is sound before adding scope. No production hardening, no deployment packaging, no additional endpoints.

---

## 3. Runtime Recommendation

**Python** is the recommended runtime for v0.1.

`basis-core` is Python. In-process import eliminates inter-process complexity — no RPC layer, no serialization boundary, no version skew between kernel and gateway. The kernel's public API is callable directly. Python also allows using `basis-core`'s Pydantic models for request and response validation without duplication.

If future requirements justify it (edge deployment, packaging constraints, performance-sensitive hot paths), Go remains a viable candidate for a later version. That decision should follow demonstrated need, not anticipate it.

---

## 4. Repository Structure

```
basis-gateway/
  src/
    basis_gateway/
      __init__.py
      main.py              # application entrypoint, lifespan setup
      config.py            # configuration loading and validation
      errors.py            # error types and HTTP error handlers
      api/
        routes.py          # route registration
        schemas.py         # request/response Pydantic models
      auth/
        oidc.py            # JWT verification, JWKS fetch and cache
        subject_mapper.py  # claim normalization → Subject + IdentityContext
      core/
        evaluator.py       # EnforcementPoint wrapper, startup initialization
      audit/
        writer.py          # AuditWriter implementation for v0.1
  tests/
    conftest.py
    test_health.py
    test_ready.py
    test_evaluate.py
    test_auth.py
    test_subject_mapper.py
    test_fail_closed.py
  pyproject.toml
  README.md
```

`basis-gateway` is a separate repository from `basis-core`. It imports `basis-core` as a package dependency. It does not vendor or copy kernel source.

---

## 5. API Surface

Three endpoints only.

### `GET /health`

Process liveness. Returns `200 OK` if the gateway process is running and the application is serving requests. No dependency checks. Suitable for process supervisors and load balancer probes.

### `GET /ready`

Readiness. Returns `200 OK` only when all of the following are true:

- Configuration has been loaded and validated.
- `basis-core` `EnforcementPoint` has been initialized with at least one policy rule.
- OIDC/JWKS configuration is present and the JWKS endpoint has been successfully contacted at least once (or JWKS is statically configured).

Returns `503 Service Unavailable` if any dependency is unavailable or uninitialized.

### `POST /v1/evaluate`

Accepts an authorization evaluation request. Full lifecycle described in §6.

Request body (JSON):

```json
{
  "request_id": "<optional caller-provided UUID>",
  "action": "<action-name>",
  "resource_id": "<optional resource identifier>",
  "context": {}
}
```

> **Implementation note:** `subject_id` and `subject_roles` are not accepted in the request body. The `EvaluateRequest` schema rejects any request containing those fields with a 400 error. Subject identity is derived exclusively from the verified Bearer token.

Response body (JSON):

```json
{
  "request_id": "<echoed>",
  "outcome": "ALLOW | DENY | NOT_APPLICABLE",
  "reason": "<string>",
  "policy_version": "<string | null>"
}
```

`NOT_APPLICABLE` is treated as `DENY` at the HTTP boundary (see §10).

---

## 6. Request Lifecycle

```
HTTP request arrives
  ↓
Extract Authorization header
  → Missing or malformed → 401
  ↓
Verify JWT signature, expiry, issuer, audience
  → Verification failure → 401
  ↓
Normalize verified claims → Subject + IdentityContext
  ↓
Parse and validate request body → DecisionRequest
  → Validation failure → 400
  ↓
Call EnforcementPoint.evaluate(request, subject, identity_context, correlation_id)
  → Kernel exception (EnforcementPoint never raises; returns DENY) → 403
  ↓
Emit AuditEvent (via AuditWriter)
  → Write failure: log operational error, do not suppress
  ↓
Map outcome to HTTP response:
  ALLOW          → 200
  DENY           → 403
  NOT_APPLICABLE → 403
  ↓
Return response
```

> **Implementation note:** The gateway generates `correlation_id` unconditionally (UUID v4) at ingress via `CorrelationMiddleware`. Caller-supplied `X-Request-ID` or `X-Correlation-ID` headers are not trusted as the authoritative correlation ID. The gateway-generated ID is attached to `request.state.correlation_id`, passed into the kernel call, and returned in the `X-Correlation-ID` response header on every response.

---

## 7. Authentication and Identity Normalization

### JWT/OIDC verification

The gateway accepts a Bearer token in the `Authorization` header.

Verification steps, in order:

1. Extract the token from `Authorization: Bearer <token>`.
2. Decode the header to read `kid` (key identifier).
3. Fetch the signing key from the JWKS endpoint. Use the cached key if `kid` is known; fetch fresh JWKS if `kid` is unknown. Treat a persistent JWKS fetch failure as a configuration error that blocks readiness.
4. Verify the token signature using the resolved key.
5. Verify `exp` (token is not expired).
6. Verify `iss` (issuer matches configured `OIDC_ISSUER`).
7. If `OIDC_AUDIENCE` is configured, verify `aud` contains the expected value.

Any verification failure returns `401`. No claim values are used before verification completes.

**JWKS caching**: Cache the JWKS response in memory. Refresh on unknown `kid`. Honor `Cache-Control` or use a configurable TTL (default: 5 minutes). Do not make a JWKS request per evaluation request.

**Provider agnosticism**: The verifier accepts any OIDC-compliant issuer. Keycloak is the reference IdP for testing. No Keycloak-specific code paths. JWKS URI is resolved from `<OIDC_ISSUER>/.well-known/openid-configuration` at startup, or overridden via `OIDC_JWKS_URI`.

### Subject normalization

After verification, map JWT claims to `basis-core` domain types. This is the responsibility described in ADR-0005: JWT normalization belongs at the gateway, not in the kernel.

`subject_from_jwt` in `basis_core.domain` is deprecated and must not be used here. Implement normalization in `auth/subject_mapper.py`.

Mapping:

| JWT claim | basis-core field |
|---|---|
| `sub` | `Subject.id` |
| `preferred_username` or `sub` | `Subject.name` |
| `realm_access.roles` or `roles` | `Subject.roles` |
| `email`, `given_name`, etc. | `Subject.attrs` (pass-through) |
| Configurable claim | `SubjectType` selection |

Construct `IdentityContext` from the verified token with `issuer`, `subject_id`, and any additional context fields relevant to policy evaluation.

The subject mapper is the only location in the gateway that knows about specific claim names. It should be configurable or replaceable for non-Keycloak claim structures without modifying the rest of the request pipeline.

---

## 8. basis-core Integration

### Initialization

At startup (lifespan event), construct and hold an `EnforcementPoint` instance:

```python
from basis_core.enforcement import EnforcementPoint
from basis_core.policy import PolicyEngine
from basis_core.audit import AuditWriter

engine = PolicyEngine(rules=[...])  # rules loaded from configuration
audit_writer = GatewayAuditWriter()
enforcement_point = EnforcementPoint(engine=engine, audit_writer=audit_writer)
```

The `EnforcementPoint` is a singleton for the process lifetime. It is not reconstructed per request.

### Evaluation

```python
from basis_core.decisions import DecisionRequest, DecisionOutcome

response = enforcement_point.evaluate(
    request=decision_request,      # DecisionRequest constructed from normalized body
    subject=subject,               # Subject from subject_mapper
    identity_context=identity_ctx, # IdentityContext from subject_mapper
    correlation_id=correlation_id, # gateway-generated UUID v4 from CorrelationMiddleware
)
```

`EnforcementPoint.evaluate()` never raises. It returns a `DecisionResponse` with `outcome=DENY` and an appropriate `failure_reason` on all internal error paths.

### Outcome mapping

| `DecisionOutcome` | HTTP status |
|---|---|
| `ALLOW` | 200 |
| `DENY` | 403 |
| `NOT_APPLICABLE` | 403 |

`NOT_APPLICABLE` is treated as denied at the HTTP boundary. The response body may include `outcome: NOT_APPLICABLE` to distinguish it from an explicit `DENY`, but no authorization is granted.

### Kernel internals

Do not expose `basis-core` stack traces, rule names, or internal state in HTTP responses. Sanitize error responses. The `DecisionResponse.reason` field may be forwarded as-is — it is produced by the kernel and is safe to return.

---

## 9. Audit Behavior

Every call to `EnforcementPoint.evaluate()` produces an `AuditEvent` via the `AuditWriter` passed at construction. The gateway does not need to construct `AuditEvent` objects itself — the `EnforcementPoint` handles that internally.

The gateway's `AuditWriter` implementation (`audit/writer.py`) must:

- Implement `write(event: AuditEvent) -> None`.
- Not raise on write failure (per the `AuditWriter` contract).
- Log write failures as operational errors via the Python logger.
- Not silently discard failures.

For v0.1, the `LogAuditWriter` from `basis_core.audit` is acceptable as the default implementation. If a structured audit sink is needed, implement a thin wrapper in `audit/writer.py`.

The `AuditEvent` fields populated by `EnforcementPoint` include `request_id`, `correlation_id` (if passed), `subject_id`, `subject_type`, `subject_roles`, `action`, `resource_id`, `outcome`, `timestamp`, and `trace` (when available). The gateway passes `correlation_id` at the `evaluate()` call site.

> **Implementation note:** The gateway also emits gateway-level `AuditEvent` records directly (via `basis_gateway.audit.gateway_events`) for outcomes that occur before the kernel is reached — authentication failures, validation failures, evaluator unavailability, and fail-closed evaluation exceptions. These use `event_type: SYSTEM_EVENT` and a stable action vocabulary. See `docs/audit-model.md` Section 4.5 for the full inventory.

> **Open question (partially resolved):** Audit write failure behavior is now defined: `GatewayAuditWriter` catches all write exceptions, increments `failed_write_count`, and logs them as `ERROR`. Decisions are never altered. Whether `failed_write_count` should trigger readiness degradation after N failures remains unresolved — tracked as an open question in `docs/audit-model.md` Section 9.

---

## 10. Failure Semantics

No authorization is granted during error conditions. The gateway fails closed on every unhandled path.

| Condition | HTTP response |
|---|---|
| Missing `Authorization` header | 401 |
| Malformed `Authorization` header | 401 |
| Invalid token signature | 401 |
| Expired token | 401 |
| Issuer mismatch | 401 |
| Audience mismatch (if configured) | 401 |
| JWKS fetch failure at request time | 401 (treat as unverifiable) |
| Malformed request body | 400 |
| Schema / field validation failure | 400 |
| `basis-core` returns `DENY` | 403 |
| `basis-core` returns `NOT_APPLICABLE` | 403 |
| `basis-core` returns `DENY` with `failure_reason` set | 403 (log the `failure_reason`) |
| Audit write failure | Log error; increment `failed_write_count`; do not alter HTTP response |
| Subject normalization failure | 401 or 400 depending on cause; fail closed |
| Unexpected gateway exception | 500 with no authorization granted |

Response bodies for 4xx/5xx errors must not include stack traces, internal type names, or kernel internals.

---

## 11. Configuration Model

Configuration is loaded from environment variables. No configuration file format is required for v0.1.

| Variable | Required | Description |
|---|---|---|
| `OIDC_ISSUER` | Yes | Token issuer URL. Used for issuer validation and JWKS discovery. |
| `OIDC_AUDIENCE` | No | Expected `aud` claim value. If unset, audience is not validated. |
| `OIDC_JWKS_URI` | No | Override for JWKS endpoint. Defaults to `<OIDC_ISSUER>/.well-known/openid-configuration` resolution. |
| `JWKS_CACHE_TTL_SECONDS` | No | JWKS cache TTL. Default: 300. |
| `POLICY_VERSION` | No | Version string passed to `EnforcementPoint`. Included in responses and audit records. |
| `LOG_LEVEL` | No | Python log level. Default: `INFO`. |
| `HOST` | No | Bind address. Default: `0.0.0.0`. |
| `PORT` | No | Bind port. Default: `8000`. |

Configuration is validated at startup. Missing required variables abort startup with a clear error message. The gateway does not start in a degraded state.

---

## 12. Testing Requirements

Tests are organized by concern. `pytest` is the test runner.

### Required test coverage

**`test_health.py`**
- `GET /health` returns 200 when the process is running.

**`test_ready.py`**
- `GET /ready` returns 200 when all dependencies are initialized.
- `GET /ready` returns 503 when `EnforcementPoint` is not initialized.
- `GET /ready` returns 503 when JWKS is not reachable and not cached.

**`test_evaluate.py`**
- Successful evaluation with `ALLOW` returns 200.
- Evaluation with `DENY` returns 403.
- Evaluation with `NOT_APPLICABLE` returns 403.
- Request body with missing required fields returns 400.
- Request body with invalid field types returns 400.

**`test_auth.py`**
- Missing `Authorization` header returns 401.
- Malformed `Authorization` header returns 401.
- Token with invalid signature returns 401.
- Expired token returns 401.
- Token with wrong issuer returns 401.
- Token with wrong audience returns 401 (when audience is configured).
- Valid token proceeds to evaluation.

**`test_subject_mapper.py`**
- Standard OIDC claims are normalized to correct `Subject` fields.
- Missing optional claims produce safe defaults.
- `subject_from_jwt` from `basis_core.domain` is not called (deprecated function must not appear in gateway code).

**`test_fail_closed.py`**
- Kernel exception (simulated) causes 403, not 200.
- Unexpected gateway exception returns 500 with no authorization.
- No code path grants authorization on exception.

### Additional recommendations

- Use `pytest-asyncio` if the HTTP framework is async.
- Use a stub `AuditWriter` in tests to capture emitted events and assert audit emission.
- Test that audit events are emitted for both ALLOW and DENY outcomes.
- Write at least one contract test that calls `EnforcementPoint` with a real `basis-core` import to verify the integration is not mocked end-to-end.

---

## 13. Explicitly Out of Scope for v0.1

The following are not part of this milestone:

- `basis-console` — operator UI
- `basis-adapters` — protocol normalization layer
- Policy authoring, policy lifecycle management, or policy versioning service
- Batch evaluation or bulk decision endpoints
- mTLS or client certificate authentication
- API key authentication
- Rate limiting or request throttling
- Kubernetes manifests or Helm charts
- Cloud deployment modules or infrastructure-as-code
- SIEM integration
- Distributed policy synchronization
- Multi-tenant authorization features
- WebSocket or streaming endpoints
- OpenAPI specification (may be auto-generated by framework but is not a deliverable)
- Docker images or container build tooling
- Persistent audit storage backends (beyond logging)

Adding any of the above during v0.1 implementation is out of scope regardless of how the motivation is framed.

---

## 14. Open Questions

> **Note:** Most v0.1 open questions have been resolved during implementation. They are preserved here for historical context.

**Audit write failure disposition** *(partially resolved)* — Behavior is now defined: `GatewayAuditWriter` catches all write exceptions, increments `failed_write_count`, and logs at `ERROR`. Decisions are never altered. Remaining open: whether `failed_write_count` should trigger readiness state degradation. Tracked in `docs/audit-model.md` Section 9.

**Subject normalization claim mapping** *(resolved)* — Implemented as code-driven mapping in `auth/subject_mapper.py`: checks `realm_access.roles` first (Keycloak), falls back to a top-level `roles` claim. No configuration-driven expression language.

**`NOT_APPLICABLE` response body** *(resolved)* — `outcome` value from `basis-core` is passed through in the response body; HTTP status code is 403 in all non-ALLOW cases.

**Policy rule loading** *(resolved)* — Policies are loaded from a JSON file at startup via `POLICY_PATH`. The file format is `{"rules": [{...}]}`. Loading is handled by `policy/loader.py`; startup fails if the file is missing or invalid.

---

## 15. Recommended First Implementation Tasks

Tasks are ordered to build a running skeleton before adding security-sensitive components.

1. **Create the repository skeleton.** Initialize `basis-gateway/` with `src/basis_gateway/`, `tests/`, and the directory structure in §4. Commit an empty package.

2. **Add package configuration and test tooling.** Write `pyproject.toml` with `basis-core` as a dependency, `pytest`, `pytest-asyncio`, `ruff`, and `mypy`. Confirm `pytest` runs against an empty test suite.

3. **Add FastAPI and the minimal HTTP runtime.** FastAPI is recommended: it provides async request handling, Pydantic-native request/response validation, and automatic schema generation without requiring a separate WSGI/ASGI server configuration. Add `main.py` with a minimal `FastAPI` application and a lifespan context manager for startup/shutdown hooks.

4. **Add `/health` and `/ready`.** Implement both endpoints. `/ready` checks a module-level flag set during lifespan initialization. Write `test_health.py` and `test_ready.py`.

5. **Add configuration loading.** Implement `config.py` using Pydantic `BaseSettings` (or `pydantic-settings`). Load and validate required variables at startup. Abort with a clear message if required variables are missing.

6. **Add the OIDC verifier.** Implement `auth/oidc.py`: JWKS fetch, caching, and token verification. Write `test_auth.py` using a test JWT signed with a known key and a stub JWKS server (e.g., `pytest-httpserver` or a simple fixture).

7. **Add the subject mapper.** Implement `auth/subject_mapper.py`: map verified claims to `Subject` and `IdentityContext`. Write `test_subject_mapper.py`.

8. **Add the basis-core evaluator wrapper.** Implement `core/evaluator.py`: initialize `EnforcementPoint` during lifespan, expose an `evaluate()` wrapper that constructs the kernel call and maps the response. Write a fixture that provides a real `EnforcementPoint` with a minimal policy rule.

9. **Add `POST /v1/evaluate`.** Wire the OIDC verifier, subject mapper, and evaluator wrapper into the full request lifecycle. Write `test_evaluate.py`.

10. **Add the audit writer.** Implement `audit/writer.py` (or configure `LogAuditWriter`). Assert in tests that audit events are emitted.

11. **Add fail-closed tests.** Write `test_fail_closed.py`. Inject a stub policy rule that raises an exception. Assert that the response is 403 and no authorization is granted. Assert the 500 path on unexpected gateway exceptions.

12. **Add a README quickstart.** Document how to install dependencies, set required environment variables, and run the gateway locally against a test issuer (Keycloak or a mock OIDC server).

---

## 17. Phase 4 Success Criteria

Phase 4 is the first hardening pass after the v0.1 feature baseline (Phases 1–3). It replaces temporary v0.1 placeholders with production-ready counterparts and tightens readiness and startup behavior.

Phase 4 is complete when all of the following are true.

**Policy configuration**

- Policies can be loaded from a configuration source — a file, environment-derived rule definitions, or another mechanism decided during Phase 4 design — at gateway startup.
- The demo `RolePolicyRule` (`gateway-demo-rbac`) defined in `core/evaluator.py` is removed from the runtime evaluation path. It may remain accessible for tests or local development, but it must not be the default policy loaded in production or staging environments.
- A startup failure in policy loading is treated as a fatal error: the gateway must not mark itself ready and must not serve `/v1/evaluate` requests if the policy engine cannot be initialized from configuration.

**Readiness hardening**

`GET /ready` returns 200 only when all of the following conditions hold:

- Application configuration has been loaded and validated.
- OIDC configuration is present: `OIDC_ISSUER` is set and the JWKS endpoint has been successfully contacted at least once since startup (or an explicit `OIDC_JWKS_URI` override has been verified reachable).
- The `EnforcementPoint` has been initialized with at least one registered policy rule loaded from configuration.
- Policy loading has completed without error.

`GET /ready` returns 503 if any of the above conditions is not met, with a `reason` field identifying which component is not ready.

**Startup failure semantics**

When `/v1/evaluate` would be active (i.e. `OIDC_ISSUER` is configured or evaluation is explicitly enabled), gateway startup must fail predictably — not silently degrade — if:

- Required OIDC configuration is absent.
- The JWKS endpoint is unreachable and no cached keys are available.
- Policy configuration is missing or cannot be parsed.
- The `PolicyEngine` is constructed with zero rules.

The v0.1 behaviour of starting with a warning and serving `/health` while `/v1/evaluate` rejects all requests is acceptable only when evaluation is explicitly not enabled.

**Fail-closed preservation**

All fail-closed guarantees established in Phases 1–3 must be preserved without regression:

- OIDC verifier failure → 401, no evaluation.
- JWKS unavailability → 401, no evaluation.
- Policy loading failure → 503 from `/ready`; no evaluation served.
- `EnforcementPoint` error → 403, fail closed.
- Audit write failure → decision stands; failure logged; no 500 returned to caller.
- Unexpected gateway exception → 500, no authorization granted.

**Compatibility**

- All existing Phase 1–3 behavior remains compatible. No breaking changes to `/health`, `/ready`, or `/v1/evaluate` request/response contracts.
- All existing tests (Phases 1–3) continue to pass without modification.

**Test coverage**

New tests must cover:

- Policy loading from configuration (valid config loads → correct rules active).
- Policy loading failure (missing or malformed config → startup failure, `/ready` returns 503).
- `/ready` with each dependency in a not-ready state (OIDC unreachable, evaluator not initialized, policy not loaded) — each case returns 503 with an informative `reason`.
- Gateway startup with `OIDC_ISSUER` set and JWKS unreachable → startup fails or degrades to not-ready with a clear error.
- Fail-closed behavior for all Phase 4 error conditions listed above.

**Explicit non-goals for Phase 4**

The following must not be introduced in Phase 4, regardless of how the motivation is framed:

- `basis-console` integration
- `basis-adapters` integration
- Docker, docker-compose, or Kubernetes manifests
- Persistent audit storage (beyond `LogAuditWriter`)
- Distributed policy synchronization
- Metrics or structured observability endpoints (deferred to a dedicated observability phase)
- Commercial BASAuth features
- Rate limiting, mTLS, or API key authentication
- `POST /v1/batch/evaluate`

**Tracked separately**

Exposing `policy_version` through the `basis-core` public API — so the gateway does not need to access `EnforcementPoint._policy_version` via `getattr` — is a `basis-core` concern. It should be tracked as a `basis-core` issue: *"Expose policy version through basis-core public API."* Phase 4 may depend on the resolution of this issue but does not own it.

---

## 16. Definition of Done

v0.1 is complete when all of the following are true:

- The gateway starts locally with a valid configuration.
- `GET /health` returns 200.
- `GET /ready` returns 200 after successful initialization and 503 before it.
- `POST /v1/evaluate` accepts requests with a valid Bearer token.
- JWT/OIDC verification works against a configurable issuer (tested against Keycloak or a mock OIDC server).
- Verified claims are normalized into `Subject` and `IdentityContext` without calling the deprecated `subject_from_jwt`.
- `EnforcementPoint.evaluate()` is called for every valid request.
- `ALLOW` returns 200; `DENY` and `NOT_APPLICABLE` return 403.
- Authentication failures, malformed requests, kernel errors, and unexpected exceptions all fail closed.
- An audit event is emitted for every evaluated request.
- `basis-core` internals (stack traces, rule names, internal types) are not exposed in HTTP responses.
- All tests listed in §12 pass.
- `ruff` reports no linting errors.
- `mypy` (strict mode) reports no type errors.
- The README documents how to run the gateway locally.
