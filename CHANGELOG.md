# Changelog

All notable changes to `basis-gateway` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.0] — 2026-06-08

Initial public release of `basis-gateway`.

### Added

- OIDC/JWT authentication: RS256/RS384/RS512/ES256/ES384/ES512; `alg=none` rejected unconditionally
- OIDC discovery with optional explicit JWKS URI override (`OIDC_JWKS_URI`)
- In-memory JWKS cache with configurable TTL (`JWKS_CACHE_TTL_SECONDS`)
- Subject normalization from verified JWT claims: `sub`, `preferred_username`, Keycloak-style `realm_access.roles` or flat `roles`
- `POST /v1/evaluate` — delegates to `basis-core` `EnforcementPoint`; enforces returned decision at HTTP boundary
- JSON policy file loaded at startup (`POLICY_PATH`); service will not become ready if missing or invalid
- Optional policy version provenance in responses and audit records (`POLICY_VERSION`)
- Kernel decision audit events (`AuditEvent`) written by `basis-core` for every evaluation (ALLOW, DENY, ERROR)
- Gateway-level audit events for all pre-evaluation failure paths: authentication failure, request validation failure, evaluator unavailability, fail-closed evaluation exceptions
- Pre-evaluation receipt event (`gateway.evaluation_requested`) emitted before kernel invocation
- `X-Correlation-ID` response header on all responses; UUIDv4 generated per request; caller-supplied values ignored
- Per-component readiness probe (`GET /ready`): `configuration_loaded`, `oidc_configured`, `jwks_available`, `policy_loaded`, `audit_writer`, `evaluator_initialized`
- Liveness probe (`GET /health`)
- Audit failure escalation: `GatewayAuditWriter` tracks consecutive write failures; readiness degradation (Model B) at configurable threshold (`AUDIT_FAILURE_THRESHOLD`)
- Optional strict fail-closed mode (`AUDIT_FAIL_CLOSED=true`): degraded audit additionally suspends `/v1/evaluate`
- Automatic audit recovery: first successful write after degradation restores readiness without restart
- Fail-closed probe mechanism prevents recovery deadlock in strict mode
- Consistent JSON error responses with stable `error` codes on all failure paths
- `CorrelationMiddleware`: UUIDv4 generated before any route handler; present on all responses including 400, 401, 500, 503

### Known limitations

See [`docs/release-readiness.md`](docs/release-readiness.md) for the full list.

- Policy file loaded once at startup; no dynamic reload
- Log-backed audit only (`LogAuditWriter`); no durable storage
- In-process JWKS cache; no cross-instance sharing
- Single-instance only; multi-instance deployments untested
- Role claim normalization supports Keycloak-style and flat `roles` claims; other IdP structures may require code changes
