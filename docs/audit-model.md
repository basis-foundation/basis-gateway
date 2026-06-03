# basis-gateway Audit Model

This document describes how `basis-gateway` participates in audit evidence generation.
It is accurate to the current implementation and deliberately notes where behavior is
ambiguous or incomplete.

---

## 1. Purpose

`basis-gateway` is the HTTP enforcement boundary. It authenticates callers, normalizes
identity, invokes `basis-core` for authorization decisions, and enforces the result at
the HTTP layer.

The gateway is responsible for contributing the following evidence around each request:

- Authenticated caller identity (normalized from verified JWT claims)
- HTTP request metadata (action, resource ID, caller-supplied context)
- Correlation ID (gateway-generated; returned to the caller and recorded in the audit event)
- Authorization decision result (ALLOW, DENY, or error outcome)
- Enforcement outcome (HTTP status code applied at the boundary)

The gateway does not own the decision semantics, the audit event schema, or the audit
persistence mechanism. Those belong to `basis-core`.

---

## 2. Audit Boundary

```
basis-core     owns canonical decision semantics, AuditEvent schema, EnforcementPoint
basis-gateway  owns HTTP enforcement evidence: identity normalization, correlation ID,
               HTTP outcome mapping, and GatewayAuditWriter configuration
audit writer   records the resulting AuditEvent to the configured backend
```

The guiding principle:

> **Kernel evaluates. Gateway enforces. Audit records evidence.**

`basis-gateway` does not produce `AuditEvent` objects directly. It provides a correctly
configured `AuditWriter` to the `EnforcementPoint` at startup. The `EnforcementPoint`
constructs and writes the `AuditEvent` after every evaluation, including failed evaluations.

---

## 3. Correlation ID Flow

Every request to `POST /v1/evaluate` follows this correlation path:

1. The request enters the gateway.
2. The gateway generates a new `correlation_id` (UUID v4) unconditionally at the start
   of the handler. There is no mechanism for callers to supply a correlation ID.
3. `request_id` is resolved: if the caller supplied `request_id` in the request body,
   that value is used; otherwise `correlation_id` is used as the `request_id` as well.
4. Both `request_id` and `correlation_id` are passed into `GatewayEvaluator.evaluate()`,
   and from there into `EnforcementPoint.evaluate()`.
5. `EnforcementPoint` writes an `AuditEvent` with both fields populated.
6. The gateway returns `X-Correlation-ID: <correlation_id>` in the HTTP response.

The `X-Correlation-ID` header is set only on responses that reach step 8 of the
evaluation handler (successful decision path). Responses that fail at earlier stages
— authentication failure (401), bad request (400), evaluator unavailable (503) —
do **not** currently include `X-Correlation-ID`. This is an open implementation concern;
see Section 9.

---

## 4. Authentication and Identity Evidence

Subject identity is derived exclusively from verified JWT claims. The gateway enforces
this invariant at the HTTP layer: the `EvaluateRequest` schema rejects any request body
containing `subject_id` or `subject_roles` with a 400 error before any identity
resolution occurs.

The authentication and identity normalization path:

1. Bearer token is extracted from the `Authorization` header.
2. JWT is verified against the configured OIDC issuer and JWKS endpoint.
3. Verified claims are passed to `map_claims()`, which produces a `NormalizedSubject`
   containing `subject_id`, `name`, `roles`, and string-typed attributes.
4. A `basis-core` `Subject` and `IdentityContext` are constructed from the normalized
   subject and the raw token (for timestamp extraction).
5. Both are passed into `EnforcementPoint.evaluate()`, which includes them verbatim in
   the resulting `AuditEvent`.

The raw token is passed to `IdentityContext` for timestamp extraction (`iat`, `exp`)
but is never logged, included in responses, or included in audit records.

Audit evidence reflects the **normalized identity** — the subject as the gateway
understood it after JWT verification — not any identity asserted in the request body.

---

## 5. Decision and Enforcement Evidence

The gateway maps `basis-core` decision outcomes to HTTP status codes as follows:

| `basis-core` outcome | HTTP status | Notes |
|---|---|---|
| `ALLOW` | 200 | Normal allow path |
| `DENY` | 403 | Normal deny path |
| `NOT_APPLICABLE` | 403 | Mapped to DENY by `EnforcementPoint`; no rule covered the action |
| Policy evaluation error | 403 | `EnforcementPoint` fails closed; `failure_reason` in audit detail |
| Internal enforcement error | 403 | `EnforcementPoint` catch-all; `failure_reason` in audit detail |
| Authentication failure | 401 | Gateway returns before `EnforcementPoint` is called |
| Evaluator not initialized | 503 | Gateway returns before `EnforcementPoint` is called |
| Malformed request | 400 | Gateway returns before `EnforcementPoint` is called |

The gateway does not reinterpret policy decisions. It applies the outcome returned by
`basis-core` directly. If `basis-core` returns DENY for any reason — including a
policy evaluation error or an internal failure — the gateway enforces 403.

`AuditOutcome` in the emitted event:

| `DecisionOutcome` | `AuditOutcome` | Notes |
|---|---|---|
| `ALLOW` | `ALLOWED` | |
| `DENY` (normal) | `DENIED` | |
| `DENY` (from policy error or internal error) | `ERROR` | `detail.failure_reason` is set |

For authentication failures, malformed requests, and evaluator unavailability, no
`AuditEvent` is written because the `EnforcementPoint` is never reached. This is an
open implementation concern; see Section 9.

---

## 6. Audit Failure Behavior

The gateway wraps `basis-core`'s `LogAuditWriter` in a `GatewayAuditWriter`.
`GatewayAuditWriter.write()` has the following behavior on failure:

- Exceptions from the inner writer are caught and never propagated.
- A failed write is logged as `ERROR` via the standard Python logger.
- A monotonic `failed_write_count` counter is incremented on each failure.
- The authorization decision is **not reversed or altered**.
- The HTTP response is **not affected**.

`EnforcementPoint._write_audit()` has its own outer exception handler. If
`GatewayAuditWriter.write()` raises despite its own guard, the `EnforcementPoint`
catches the exception and logs it. The decision is still returned to the caller.

**Current guarantee**: audit write failures are visible in logs and in
`failed_write_count`, but they do not affect authorization outcomes. Access is
never granted or denied based on whether the audit write succeeded.

**Ambiguity**: there is no alerting threshold on `failed_write_count` in the current
implementation. Whether sustained audit write failures should escalate to a readiness
state change (i.e., `/ready` returning 503 after N failures) is an open question; see
Section 9.

---

## 7. Example Audit Evidence Shape

The following is a representative example of the `AuditEvent` that `basis-core` emits
for a successful authorization decision through the gateway. Field names match the
current `basis-core` `AuditEvent` schema (`schema_version: "1.0"`).

```json
{
  "event_id": "a7f3c2d1-...",
  "event_type": "authorization_decision",
  "timestamp": "2026-06-03T14:22:00.000000+00:00",
  "schema_version": "1.0",

  "request_id": "b1e2f3a4-...",
  "decision_id": "b1e2f3a4-...",
  "correlation_id": "c9d8e7f6-...",

  "subject_id": "user:alice",
  "subject_name": "alice",
  "subject_type": "human",
  "subject_roles": ["operator"],

  "action": "read:sensor:telemetry",
  "resource_id": "sensor:ahu-1",
  "resource_type": null,

  "outcome": "ALLOWED",
  "reason": "Subject holds a role permitted for 'read:sensor:telemetry'.",
  "evaluated_by": "gateway-rbac",
  "policy_version": null,
  "matched_rules": ["gateway-rbac"],

  "trace": {
    "final_outcome": "ALLOW",
    "evaluated_rules": [
      {
        "rule_name": "gateway-rbac",
        "outcome": "ALLOW",
        "reason": "Subject holds a role permitted for 'read:sensor:telemetry'."
      }
    ],
    "short_circuited": false
  },

  "detail": {}
}
```

For a DENY, `outcome` becomes `"DENIED"` and `matched_rules` lists the rule that
produced the denial. For an enforcement error, `outcome` becomes `"ERROR"` and
`detail.failure_reason` is set to `"policy_error"` or `"internal_error"`.

The `AuditEvent` schema is defined and owned by `basis-core`. The gateway does not
define or extend it. Field names and `schema_version` should be treated as stable
once in production use.

---

## 8. Non-Goals

`basis-gateway` does not provide and will not provide in the current phase:

- Persistent audit storage (events are written to the process log only)
- SIEM integration or log forwarding
- Distributed tracing or OpenTelemetry instrumentation
- Audit search UI or query API
- Audit retention policy or TTL enforcement
- Audit immutability guarantees
- Audit analytics or aggregation
- Policy history or policy version provenance
- Structured audit event schema versioning beyond what `basis-core` provides

These are future concerns that belong to dedicated phases or to a higher-level
architecture decision.

---

## 9. Open Questions and Follow-up Issues

The following are known gaps or unresolved questions in the current audit model.
They are out of scope for this branch and should be tracked separately.

**Correlation ID on non-evaluation responses**
`X-Correlation-ID` is only returned on responses that complete the full evaluation path
(step 8 of the handler). Responses returning 400, 401, or 503 before the `EnforcementPoint`
is reached do not include `X-Correlation-ID`. Whether these responses should always include
a correlation ID for traceability is unresolved.

**No audit events for pre-evaluation failures**
Authentication failures (401), malformed request (400), and evaluator unavailable (503)
do not produce `AuditEvent` records because the `EnforcementPoint` is never called.
Whether the gateway should write gateway-specific audit evidence for authentication
failures — independent of `basis-core` — needs alignment with `basis-architecture`.

**Audit failure escalation threshold**
`GatewayAuditWriter.failed_write_count` tracks failures but does not trigger any
operational response. Whether sustained audit write failures should affect readiness
state (e.g., mark `evaluator_initialized` not-ready after N failures) is unresolved.

**Audit correlation model alignment with `basis-architecture`**
The gateway generates its own `correlation_id` and does not propagate one from callers.
The broader correlation model — how audit events from the gateway, `basis-core`, and any
adapters are correlated in a distributed trace — has not been specified.

**Persistent audit storage**
The current backend is `LogAuditWriter` (structured JSON to the process log). Persistent
audit storage and the handoff from log-based to durable storage are out of scope.

**Policy version provenance**
`policy_version` is an optional string set at startup via `POLICY_VERSION`. There is no
mechanism linking it to a specific policy file hash, deployment artifact, or version
control reference. Formalizing policy version provenance is a future concern.
