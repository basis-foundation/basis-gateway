# Operation-Aware Endpoint Reference

`POST /v1/evaluate/operation-aware` — feature-gated, additive operation-aware evaluation.
Delegates to `basis-core`'s public `OperationAwareEnforcementPoint` instead of the v0.1
`EnforcementPoint`. See
[`docs/implementation/operation-aware-gateway-integration-plan.md`](implementation/operation-aware-gateway-integration-plan.md)
for the full architecture this endpoint implements.

This document describes **current, shipped behavior only**. Where a capability is not yet
implemented, it is labeled explicitly.

---

## Route and feature gate

```text
POST /v1/evaluate/operation-aware
```

This route exists only when:

```text
OPERATION_AWARE_ENABLED=true
```

- **When disabled** (unset or `false`, the default): the route is not registered at all. A
  request to it receives the framework's ordinary `404` — not a gated `404` produced by
  application code.
- **When enabled but startup later fails** (bad bundle, failed semantic preflight): the route
  **remains registered**. The handler returns a governed failure response (`503`, via
  `evaluator_unavailable`) rather than `404`. See [`docs/readiness.md`](readiness.md) for the
  startup stages that can fail.
- This endpoint does not replace, share a route with, or change the behavior of
  `POST /v1/evaluate`. Both may be registered and served simultaneously on the same instance.

---

## Authentication

Uses the same runtime authentication system as `POST /v1/evaluate` —
`basis_gateway.auth.runtime.authenticate()`, dispatching on `AUTH_MODE` (`oidc` default, or
`basis_local_token`), with no fallback between modes. See
[`docs/configuration.md`](configuration.md#authentication) for configuration and
[`docs/basis-local-token-trust.md`](basis-local-token-trust.md) for the BASIS-local token
verifier. This document does not describe token *issuance* — the gateway is a verifier, not an
issuer, for either mode.

A missing or invalid Bearer token returns `401` before any request-body-derived logic runs, and
before the caller's operation-producer trust is classified.

---

## Request shape

Every field on `OperationAwareEvaluateRequest`. The model uses `extra="forbid"` — any field not
listed below is rejected (`400`), never silently accepted or dropped.

### Caller-allowed fields

These may be supplied by any authenticated caller, regardless of operation-producer trust status.

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | `string \| null` | No | Caller-supplied request identifier. If omitted, the gateway defaults it to the generated `correlation_id`. |
| `action` | `string` | **Yes** | A composite action (`{verb}:{domain}`, e.g. `"read:ahu"`) or a bare verb (e.g. `"read"`) to be composed with `resource_type`. Must not be empty. |
| `resource_type` | `string \| null` | No | Domain for a bare-verb action and/or the type for a local `resource_id`. See [Action grammar](#action-grammar) / [Resource grammar](#resource-grammar). |
| `resource_id` | `string \| null` | No | Resource identifier — local (composed with `resource_type`) or already typed. |
| `context` | `object` (`dict[str, string]`) | No | **Empty-only** on this endpoint. Defaults to `{}`. A non-empty value is rejected (`400`) — the public `OperationAwareDecisionRequest` has no free-form context field to map it onto; use the dedicated typed fields below instead. |

### Trusted-producer-only fields

Every field below may be supplied **only** by a caller the gateway has classified as a trusted
operation producer (`OPERATION_PRODUCER_SUBJECT_IDS`; see
[Producer-only context](#producer-only-context) below). An ordinary authenticated caller that is
not so classified and supplies any of these fields is rejected with `400` before the kernel is
ever invoked. All are optional; the gateway never derives or composes them — each is either
present exactly as the trusted producer supplied it, or absent.

| Field | Type |
|---|---|
| `operation_intent` | `OperationIntent` (`"read_only"` \| `"state_changing"` \| `"control_affecting"`) |
| `location` | `OperationAwareLocation` |
| `device` | `OperationAwareDevice` |
| `protocol_context` | `OperationAwareProtocolContext` |
| `safety_context` | `OperationAwareSafetyContext` |
| `environment_context` | `OperationAwareEnvironmentContext` |
| `risk_context` | `OperationAwareRiskContext` |
| `identity_evidence_reference` | `IdentityEvidenceReference` |
| `adapter_evidence_reference` | `AdapterEvidenceReference` |

### Gateway-owned fields — rejected, not accepted

The following are never accepted as request fields. Because the model uses `extra="forbid"`,
supplying any of them fails validation with `400` exactly like any other unrecognized field —
they are not silently stripped:

`subject_id`, `subject_roles`, `subject_attrs`, `identity_source`, `authority_mode`,
`evaluation_time`, `correlation_id`, `evaluation_status`, `outcome`, `failure_reason`,
`disposition`, policy-bundle identity fields (`bundle_id`, `bundle_version`, ...),
`is_trusted_operation_producer`/`producer_trust_classification`, and `expected_policy_version`.

`expected_policy_version` in particular is **omitted from this rollout's accepted input surface
entirely** — a caller that supplies it receives the same rejection any other unrecognized field
would, not silent acceptance-and-discard. Defining comparison/mismatch behavior for it is
**Future** — not implemented.

### Absence is preserved

An omitted optional field stays `None` on the composed kernel request — the gateway never
manufactures an empty-but-present object for `location`, `safety_context`, or any other optional
category. "Field absent" and "field present but empty" (e.g. `safety_context: {}`) remain
distinguishable states, because a future policy condition may depend on that distinction.

---

## Action grammar

Identical grammar to `POST /v1/evaluate` (`basis_gateway.core.actions.compose_action`), reused
unchanged:

- **Composite, kernel-compatible**: `{"action": "read:ahu"}` — passed through unchanged.
- **Bare verb + `resource_type`**: `{"action": "read", "resource_type": "ahu"}` — composed by the
  gateway into `"read:ahu"` before evaluation.
- `resource_type` is optional for a composite action, required for a bare verb. A bare verb
  without `resource_type` is rejected (`400`).
- Supplying both a composite action **and** a `resource_type` is ambiguous and rejected (`400`)
  — this is the "invalid double composition" case.

---

## Resource grammar

Identical grammar to `POST /v1/evaluate` (`basis_gateway.core.resources.compose_resource_id`),
reused unchanged:

- **Typed, kernel-compatible**: `{"resource_id": "ahu:rooftop-1"}` — passed through unchanged.
- **Local id + `resource_type`**: `{"resource_type": "ahu", "resource_id": "rooftop-1"}` —
  composed by the gateway into `"ahu:rooftop-1"`.
- A `resource_type` with **no** `resource_id` is not an error — it is a resource-independent
  (domain-level) request.
- A local `resource_id` with **no** `resource_type` is rejected (`400`) — the gateway cannot
  construct a canonical identifier from a local id alone.
- An already-typed `resource_id` supplied alongside a `resource_type` is rejected (`400`) — the
  gateway will not accept two sources of resource-type truth.

---

## Producer-only context

The complete, real, merged field list a trusted operation producer may supply
(`basis_gateway.core.operation_aware_composition.OPERATION_PRODUCER_ONLY_FIELDS`):

```text
operation_intent
location
device
protocol_context
safety_context
environment_context
risk_context
identity_evidence_reference
adapter_evidence_reference
```

Trusted-producer status is derived **only** from `OPERATION_PRODUCER_SUBJECT_IDS`, checked
against the already-authenticated subject's verified `subject_id` — exact match, case-sensitive.
No role, attribute, network source, or caller-supplied claim widens this. See
[`docs/configuration.md`](configuration.md#operation-aware-authorization).

**Every field a trusted producer supplies is classified as `trusted_producer_asserted` in
gateway-owned provenance — never promoted to `verified`.** The gateway cannot independently
confirm the truth of a producer's claim (it has no device-state or protocol-parsing capability);
it can only confirm that the caller asserting the claim is one the deployment has explicitly
configured to trust. This distinction is preserved in the gateway's audit evidence (see
[`docs/audit-model.md`](audit-model.md)).

---

## Response shape

Every field on `OperationAwareEvaluateResponse`. Fields with a `null`/absent value are omitted
from the JSON body (the gateway serializes with `exclude_none=True`).

| Field | Type | Always present? | Notes |
|---|---|---|---|
| `request_id` | `string` | Yes | |
| `correlation_id` | `string \| null` | Usually | Matches the `X-Correlation-ID` response header. |
| `evaluation_status` | `string` (`"completed"` \| `"failed"`) | Yes | |
| `outcome` | `string \| null` (`"allow"` \| `"deny"` \| `"not_applicable"`) | Only when `evaluation_status="completed"` | `null`/absent when `failed`. |
| `failure_reason` | `string \| null` | Only when `evaluation_status="failed"` | One of six governed values (see [Semantic outcome matrix](#semantic-outcome-matrix)). `null`/absent when `completed`. |
| `bundle_id` | `string \| null` | When available | Identity of the loaded `PolicyBundle`. |
| `bundle_version` | `string \| null` | When available | |
| `trace_id` | `string \| null` | When available | Gateway-generated per evaluation call. |
| `reason_code` | `string \| null` | When the kernel populated one | Never gateway-synthesized. |
| `explanation` | `string \| null` | When the kernel populated one | Never gateway-synthesized prose. |
| `disposition` | `string` (`"allow"` \| `"deny"`) | Yes | Kernel-computed, never gateway-recomputed. |
| `evaluation_trace` | `object \| null` | No, always `null` today | Only ever populated if a future caller of the internal evaluator wrapper requests trace embedding; this endpoint's own call site does not request it. |

Every value is copied verbatim from the kernel's `OperationAwareEnforcementResult` — none is
recomputed, reinterpreted, or gateway-synthesized.

---

## Semantic outcome matrix

| Evaluation state | Outcome | Gateway disposition | Typical HTTP behavior |
|---|---|---|---|
| `completed` | `allow` | `allow` | success (`200`) |
| `completed` | `deny` | `deny` | forbidden (`403`) |
| `completed` | `not_applicable` | `deny` | forbidden (`403`) — outcome stays `"not_applicable"` in the body; only the HTTP status collapses it with `deny` |
| `failed` | _(null)_ | `deny` | governed client/server failure — **not** a single fixed status; see below |

Not all failures map to one HTTP status. The exact mapping, from
`basis_gateway.api.operation_aware_classification`:

| `failure_reason` | HTTP status |
|---|---:|
| `invalid_request` | `400` |
| `unsupported_schema_version` | `400` |
| `invalid_policy_bundle` | `503` |
| `policy_validation_failure` | `503` |
| `condition_evaluation_error` | `500` |
| `internal_evaluation_error` | `500` |

`503` for `invalid_policy_bundle`/`policy_validation_failure` reflects a dependency-integrity
anomaly (the loaded bundle already passed the startup semantic preflight — see
[`docs/readiness.md`](readiness.md) — so a per-request failure of this kind after that indicates
the service's policy dependency is not in the state the preflight certified), not an ordinary
request-shaped problem. `500` for `condition_evaluation_error`/`internal_evaluation_error`
reflects a per-request, evaluation-time failure, consistent with `POST /v1/evaluate`'s existing
`evaluation_failed_closed` convention.

Two additional, pre-kernel gateway conditions are not part of this table because the kernel never
ran:

| Condition | HTTP status |
|---|---:|
| Evaluator unavailable (not yet constructed, or startup incomplete) | `503` |
| Unexpected exception crossing the evaluator boundary | `500` |

---

## Example requests and responses

All identifiers below are synthetic. `$TOKEN` is a placeholder for a real Bearer token — never a
literal secret. For a runnable, bounded, offline demonstration of these exact scenarios against
the real gateway-to-kernel path, see [`demo/operation-aware/`](../demo/operation-aware/README.md).

### Allow

```bash
curl -X POST http://localhost:8000/v1/evaluate/operation-aware \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action": "read:ahu", "resource_id": "ahu:rooftop-1"}'
```

`200`:

```json
{
  "request_id": "c9d8e7f6-0000-0000-0000-000000000000",
  "correlation_id": "c9d8e7f6-0000-0000-0000-000000000000",
  "evaluation_status": "completed",
  "outcome": "allow",
  "bundle_id": "site-a-bundle",
  "bundle_version": "1.0.0",
  "trace_id": "b1e2f3a4-0000-0000-0000-000000000000",
  "disposition": "allow"
}
```

### Explicit deny

Request body, against a bundle with a `deny` rule matching `write:ahu`:

```json
{"action": "write:ahu", "resource_id": "ahu:rooftop-1"}
```

`403`:

```json
{
  "request_id": "c9d8e7f6-0000-0000-0000-000000000001",
  "correlation_id": "c9d8e7f6-0000-0000-0000-000000000001",
  "evaluation_status": "completed",
  "outcome": "deny",
  "bundle_id": "site-a-bundle",
  "bundle_version": "1.0.0",
  "trace_id": "b1e2f3a4-0000-0000-0000-000000000001",
  "disposition": "deny"
}
```

### Default deny

Request body, against a bundle with no rule (`allow` or `deny`) matching `execute:override`:

```json
{"action": "execute:override", "resource_id": "ahu:rooftop-1"}
```

`403` — same shape as explicit deny; the response body does not distinguish "no rule matched"
from "a deny rule matched" (both are `outcome: "deny"`). Which case occurred is visible in the
kernel's matched-rule audit evidence, not in this response body.

```json
{
  "request_id": "c9d8e7f6-0000-0000-0000-000000000002",
  "correlation_id": "c9d8e7f6-0000-0000-0000-000000000002",
  "evaluation_status": "completed",
  "outcome": "deny",
  "bundle_id": "site-a-bundle",
  "bundle_version": "1.0.0",
  "trace_id": "b1e2f3a4-0000-0000-0000-000000000002",
  "disposition": "deny"
}
```

### Not applicable

Request body, against a bundle whose `scope` excludes `read:other_domain` entirely:

```json
{"action": "read:other_domain"}
```

`403` — note `outcome` is `"not_applicable"`, never rewritten to `"deny"`, even though the HTTP
status is the same `403` as an explicit or default deny:

```json
{
  "request_id": "c9d8e7f6-0000-0000-0000-000000000003",
  "correlation_id": "c9d8e7f6-0000-0000-0000-000000000003",
  "evaluation_status": "completed",
  "outcome": "not_applicable",
  "bundle_id": "site-a-bundle",
  "bundle_version": "1.0.0",
  "trace_id": "b1e2f3a4-0000-0000-0000-000000000003",
  "disposition": "deny"
}
```

### Failed evaluation

A per-request `policy_validation_failure` (a dependency-integrity anomaly — see the outcome
matrix above).

`503`:

```json
{
  "request_id": "c9d8e7f6-0000-0000-0000-000000000004",
  "correlation_id": "c9d8e7f6-0000-0000-0000-000000000004",
  "evaluation_status": "failed",
  "failure_reason": "policy_validation_failure",
  "disposition": "deny"
}
```

### Untrusted-producer context rejected

An ordinary authenticated caller (not in `OPERATION_PRODUCER_SUBJECT_IDS`) supplies a
producer-only field:

```bash
curl -X POST http://localhost:8000/v1/evaluate/operation-aware \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action": "read:ahu", "operation_intent": "read_only"}'
```

`400` — the kernel is never invoked; this is a gateway-owned, pre-kernel rejection, so the
response is a generic `ErrorResponse`, not an `OperationAwareEvaluateResponse`:

```json
{
  "error": "validation_failed",
  "message": "caller is not a classified operation producer and may not supply operation-producer-only field(s): operation_intent",
  "correlation_id": "c9d8e7f6-0000-0000-0000-000000000005"
}
```

### Evaluator unavailable

`OPERATION_AWARE_ENABLED=true` but startup has not yet completed (or failed) — the route is
registered, but no evaluator is available:

`503`:

```json
{
  "error": "evaluator_unavailable",
  "message": "Evaluator not initialized",
  "correlation_id": "c9d8e7f6-0000-0000-0000-000000000006"
}
```

### A trusted producer's full request shape

For reference — every producer-only field populated at once (a caller classified as trusted via
`OPERATION_PRODUCER_SUBJECT_IDS`):

```json
{
  "action": "read",
  "resource_type": "ahu",
  "resource_id": "rooftop-1",
  "operation_intent": "read_only",
  "location": {"site_id": "site-1", "zone_id": "zone-a"},
  "device": {"device_id": "ahu-rooftop-1"},
  "protocol_context": {"protocol": "bacnet"},
  "safety_context": {"mode": "normal"},
  "environment_context": {"mode": "maintenance_mode"},
  "risk_context": {"classification": "low"},
  "identity_evidence_reference": {
    "reference_id": "identity-evidence-001",
    "evidence_digest": {"algorithm": "sha-256", "value": "abc123def456"},
    "identity_source": "basis-identity",
    "redaction_classification": "safe_to_expose"
  },
  "adapter_evidence_reference": {
    "reference_id": "adapter-evidence-001",
    "evidence_digest": {"algorithm": "sha-256", "value": "789abc012def"},
    "adapter_source": "basis-adapters-bacnet",
    "redaction_classification": "safe_to_expose"
  }
}
```

This shape validates against `OperationAwareEvaluateRequest`; whether it is *accepted* still
depends on the caller's producer-trust classification at request time (`400` if not classified as
a trusted producer, per [Producer-only context](#producer-only-context) above).

---

## Limitations

- No policy authoring tooling for the `PolicyBundle` format — bundles are hand-authored JSON.
- `invalid_request`, `unsupported_schema_version`, and `internal_evaluation_error` are governed,
  documented failure reasons, but are not reachable through the real gateway-to-kernel path with a
  structurally valid bundle and a well-formed request in this repository's own test suite — their
  HTTP classification is still exhaustively covered at the pure-function level (see
  `tests/test_operation_aware_http_classification.py`).

---

## Related documents

- [`docs/configuration.md`](configuration.md) — environment-variable reference
- [`docs/audit-model.md`](audit-model.md) — audit evidence model, sibling-artifact structure
- [`docs/readiness.md`](readiness.md) — readiness components and failure matrix
- [`docs/implementation/operation-aware-gateway-integration-plan.md`](implementation/operation-aware-gateway-integration-plan.md) — full architecture and design rationale
- [`demo/operation-aware/README.md`](../demo/operation-aware/README.md) — bounded, reproducible, offline demonstration
