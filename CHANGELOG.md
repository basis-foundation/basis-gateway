# Changelog

All notable changes to `basis-gateway` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added

- **Operation-aware gateway integration** (feature-gated, disabled by default via `OPERATION_AWARE_ENABLED=false`): a new, additive `POST /v1/evaluate/operation-aware` endpoint delegating to `basis-core`'s public `OperationAwareEnforcementPoint`. Summary of the completed capability — see [`docs/operation-aware-endpoint.md`](docs/operation-aware-endpoint.md), [`docs/configuration.md`](docs/configuration.md), and [`docs/implementation/operation-aware-gateway-integration-plan.md`](docs/implementation/operation-aware-gateway-integration-plan.md) for full detail:
  - Normalized operation-aware request model (`OperationAwareEvaluateRequest`) reusing the existing action/resource composition boundary, with an empty-only `context` field (the public kernel request has no free-form context field to map a caller-supplied one onto).
  - Operation-producer trust classification (`OPERATION_PRODUCER_SUBJECT_IDS`, exact-match, case-sensitive; empty by default — no caller is a trusted producer without explicit configuration) and provenance-gated composition: an ordinary authenticated caller supplying any producer-only field (`operation_intent`, `location`, `device`, `protocol_context`, `safety_context`, `environment_context`, `risk_context`, `identity_evidence_reference`, `adapter_evidence_reference`) is rejected (`400`) before the kernel is invoked.
  - Public `basis-core` v0.2.1 integration only (`OperationAwareEnforcementPoint.for_bundle()`); no import of internal `basis_core.evaluation.*` symbols.
  - A startup semantic preflight that closes the "structurally loaded but semantically broken bundle" gap: any completed synthetic-request result proves the bundle passed semantic validation before the service becomes ready.
  - Canonical, exhaustive HTTP status classification from the kernel's `evaluation_status`/`outcome`/`failure_reason`: `200` (allow), `403` (deny/not-applicable), `400` (`invalid_request`/`unsupported_schema_version`), `503` (`invalid_policy_bundle`/`policy_validation_failure`/evaluator unavailable), `500` (`condition_evaluation_error`/`internal_evaluation_error`/unexpected exception). `NOT_APPLICABLE` is never rewritten to `"deny"` in the response body.
  - Gateway and kernel audit evidence: a contract-shaped `GatewayAuditEvent` recorded *beside* (never nested inside) the kernel's complete, unmodified `AuditEvidence` in the same durable record, linked by `gateway_audit_event.audit_evidence_id == audit_evidence.evidence_id`.
  - The audit writer (`GatewayAuditWriter`) and its failure-escalation/fail-closed behavior are shared, unchanged, across both evaluation endpoints — one writer, one degraded/recovered state.
  - Four stage-specific readiness components (`operation_aware_mode_enabled`, `operation_aware_bundle_loaded`, `operation_aware_evaluator_initialized`, `operation_aware_policy_semantically_valid`), registered only when the feature is enabled. See [`docs/readiness.md`](docs/readiness.md).
  - A canonical and adversarial conformance test suite exercising the real gateway-to-kernel path (allow, explicit deny, default deny, not-applicable, and the reachable governed failure categories).
- **Action composition boundary** (`basis_gateway.core.actions`): `POST /v1/evaluate` now accepts adapter-normalized requests (bare verb `action` plus `resource_type`, e.g. `action="read"`, `resource_type="ahu"`) and composes them into the kernel-compatible composite action (`read:ahu`) before evaluation. Direct composite requests (`action="read:ahu"`) are unchanged and pass through.
- `resource_type` field on `EvaluateRequest` (optional for composite actions, required for bare verbs).
- Composition evidence recorded under the reserved `basis_gateway.*` context namespace (`action_composed`, `original_action`, `resource_type`, `composed_action`) whenever the gateway composes an action.

### Changed

- Ambiguous or incomposable requests are rejected with `400 validation_failed`: a bare verb without `resource_type`, a composite action with a `resource_type`, an invalid action/`resource_type` segment, or a caller-supplied `basis_gateway.*` context key (which would forge composition evidence).

### Compatibility

- `POST /v1/evaluate` remains supported, unchanged, and byte-for-byte unaffected by the operation-aware addition — no shared route, request/response model, or authorization behavior change.
- Operation-aware mode is disabled by default (`OPERATION_AWARE_ENABLED=false`). No migration is forced; a deployment that does not set this flag observes zero behavior change.
- Both evaluation paths may be enabled and served simultaneously on the same running instance, sharing the same authentication configuration and audit writer.

### Notes

- The gateway composes action strings as part of request assembly only. It does not evaluate authorization, define or extend the action vocabulary, or parse protocols. `basis-core` remains the authorization kernel and the authority that validates the action; adapters remain protocol-normalization libraries. This applies identically to the operation-aware path.
- Known operator-relevant limitations of the operation-aware path (no policy hot reload, no durable audit store, no adapter execution confirmation, no PR 11 bounded demonstration yet, and others): see the [README](README.md#current-limitations).

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
