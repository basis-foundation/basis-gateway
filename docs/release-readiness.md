# basis-gateway v0.1 Release Readiness

This document summarizes what is and is not included in the v0.1 release of `basis-gateway`.

---

## What v0.1 includes

**Authentication and identity**
- OIDC/JWT verification: RS256, RS384, RS512, ES256, ES384, ES512; `alg=none` rejected unconditionally
- OIDC discovery (`{issuer}/.well-known/openid-configuration`) with optional JWKS URI override
- In-memory JWKS cache with configurable TTL (`JWKS_CACHE_TTL_SECONDS`)
- Subject normalization from verified claims: `sub`, `preferred_username`, roles (`realm_access.roles` or `roles`), and standard attributes

**Policy and evaluation**
- JSON policy file loaded once at startup (`POLICY_PATH`); service will not become ready if missing or invalid
- Authorization evaluation via `POST /v1/evaluate`; delegates to `basis-core` `EnforcementPoint`; gateway enforces the returned decision
- Optional policy version provenance (`POLICY_VERSION`) included in responses and audit records

**Audit evidence**
- Kernel decision events (`AuditEvent`) written by `basis-core` `EnforcementPoint` for every evaluation (ALLOW, DENY, ERROR)
- Gateway-level events for all pre-evaluation failure paths: authentication failure, request validation failure, evaluator unavailability, and fail-closed evaluation exceptions
- Pre-evaluation receipt event (`gateway.evaluation_requested`) emitted after authentication and before kernel invocation

**Correlation IDs**
- UUIDv4 generated per request by `CorrelationMiddleware` before any route handler runs
- `X-Correlation-ID` response header on all responses (200, 400, 401, 403, 500, 503)
- Same correlation ID in response body, response header, and all audit records for that request
- Caller-supplied `X-Correlation-ID` headers are ignored; the gateway is authoritative

**Audit failure escalation**
- `GatewayAuditWriter` tracks consecutive write failures
- Readiness degradation (Model B default) when failures reach `AUDIT_FAILURE_THRESHOLD` (default: 10)
- Optional strict fail-closed mode (`AUDIT_FAIL_CLOSED=true`): degraded audit additionally suspends `/v1/evaluate`
- Automatic recovery: first successful write after degradation restores readiness without restart
- Fail-closed probe mechanism prevents recovery deadlock in strict mode

**Operational readiness**
- Per-component readiness probe (`GET /ready`): `configuration_loaded`, `oidc_configured`, `jwks_available`, `policy_loaded`, `audit_writer`, `evaluator_initialized`
- Liveness probe (`GET /health`) always responds while the process is running
- Consistent JSON error responses with stable `error` codes and `correlation_id` on all failure paths
- Structured startup logs with component-level diagnostics

---

## What is intentionally out of scope

The following are not included in v0.1 and will not be added without a deliberate scope decision:

- Persistent audit storage (current backend: `LogAuditWriter` to process log only)
- Metrics, Prometheus, OpenTelemetry, or distributed tracing
- SIEM integration or external log forwarding
- `basis-console` integration (operator interface; future ecosystem component)
- `basis-adapters` integration (protocol normalization; future ecosystem component)
- Dynamic policy reload without restart
- Policy authoring API or UI
- Policy versioning, deployment pipeline, or version-to-artifact linkage
- Docker, docker-compose, or Kubernetes manifests
- GitHub Actions or CI configuration
- Horizontal scaling or multi-instance coordination
- Audit immutability or retention policy enforcement
- Rate limiting, request size limits, or DDoS mitigations

---

## Known limitations

- **Single policy file, static load**: the policy is loaded once at startup from a JSON file. Changes require a process restart. There is no dynamic reload or hot-swap path.
- **In-process JWKS cache**: JWKS keys are cached in process memory. Multiple instances do not share the cache; each instance fetches and caches independently.
- **Role claim conventions**: subject normalization supports Keycloak-style `realm_access.roles` and flat `roles` claims. Other IdP claim structures may require a code change to `subject_mapper.py`.
- **Log-backed audit only**: all audit events are written to the Python process log via `LogAuditWriter`. There is no durable storage, no guaranteed delivery, and no audit query interface.
- **`RequestValidationError` handler lacks audit event**: the FastAPI-level `RequestValidationError` handler in `main.py` returns a `validation_failed` 400 without emitting an audit event. This handler is currently unreachable for `POST /v1/evaluate` given the route's parameter signature, but is a latent gap if the route signature changes. See `docs/audit-model.md` §9.
- **Single-instance only**: audit failure escalation threshold behavior, JWKS caching, and readiness state are all in-process. Multi-instance deployments are untested and unsupported.

---

## Future ecosystem components

**`basis-console`** — the planned operator and administrator interface. It will call gateway APIs for policy inspection, audit log queries, and operational management. Not implemented in v0.1. The gateway API surface is designed to support this integration without changes.

**`basis-adapters`** — the planned protocol normalization layer. Adapters translate protocol-specific operations (BACnet, Modbus, etc.) into `DecisionRequest` objects and route them through the gateway. Not implemented in v0.1. The preferred deployment model routes adapter requests through the gateway; direct `basis-core` invocation is also supported for constrained embedded deployments.

---

## Architecture invariants confirmed for v0.1

- **Kernel evaluates. Gateway enforces. Audit records evidence.** `basis-core` `EnforcementPoint` owns evaluation semantics. The gateway does not reinterpret, supplement, or override kernel decisions.
- **Subject identity from token only.** The `EvaluateRequest` schema rejects `subject_id` or `subject_roles` in the request body. Identity is derived exclusively from the verified Bearer token.
- **Fail closed on every error path.** Unexpected evaluation errors produce DENY, not ALLOW. Audit write failures do not alter authorization decisions.
- **Correlation IDs are gateway-generated.** Caller-supplied `X-Correlation-ID` headers are never used as the authoritative ID. This prevents external parties from influencing the audit trail.

---

## Related documents

- [`README.md`](../README.md) — setup, configuration, API reference, quick start
- [`docs/audit-model.md`](audit-model.md) — audit architecture, event inventory, correlation flow
- [`docs/audit-failure-escalation.md`](audit-failure-escalation.md) — escalation model design, Model B/C trade-offs, recovery behavior
- [`docs/troubleshooting.md`](troubleshooting.md) — startup failures, readiness diagnostics, recovery procedures
- [`basis-architecture/docs/architecture/basis-gateway.md`](../../basis-architecture/docs/architecture/basis-gateway.md) — architectural boundaries, trust model, and invariants
