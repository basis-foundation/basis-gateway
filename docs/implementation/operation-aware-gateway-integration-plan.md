# Operation-Aware Gateway Integration Plan

**Status**: PRs 1–10 implemented and merged. PR 11 (bounded end-to-end demonstration) is implemented and current.
**Date**: 2026-07-31 (original planning date; see "Implementation Status" below for the current state)
**Scope**: Architecture and implementation plan for adopting the released `basis-core` operation-aware authorization surface in `basis-gateway`. PRs 1–9 have implemented the runtime behavior this plan describes, behind the `OPERATION_AWARE_ENABLED` feature flag (default `false`). This document retains its original planning-time language throughout, labeled historical where relevant — see the status callout immediately below for what is now actually shipped.
**Branch**: `docs/operation-aware-gateway-integration-plan` (original); implementation landed across PRs 1–9's own branches; this PR (10) is `docs/operation-aware-release-hardening`.

> ## Implementation Status (updated for PR 10)
>
> - **PRs 1–9: complete and merged to `main`.** The operation-aware gateway path described by
>   this plan is implemented: the feature-gated `POST /v1/evaluate/operation-aware` endpoint,
>   operation-producer trust classification, provenance-gated composition, public `basis-core`
>   v0.2.1 kernel integration (`OperationAwareEnforcementPoint.for_bundle()`), the startup
>   semantic preflight, exact HTTP status classification, gateway+kernel audit evidence, the
>   four operation-aware readiness components, and the canonical/adversarial conformance suite.
>   See [`docs/operation-aware-endpoint.md`](../operation-aware-endpoint.md) and
>   [`docs/readiness.md`](../readiness.md) for the current-state reference documentation this
>   plan's implementation is now described by.
> - **PR 10 (documentation and release-hardening pass): complete and merged to `main`.** Updated
>   README, configuration reference, endpoint documentation, audit documentation, readiness
>   documentation, changelog, and a release-readiness review to accurately describe the
>   now-implemented surface. Added no runtime behavior.
> - **PR 11 (this bounded end-to-end demonstration): implemented, current.** Adds
>   `demo/operation-aware/` — a bounded, reproducible, offline demonstration of the real
>   gateway-to-kernel path (signed BASIS-local token -> real authentication -> operation-producer
>   trust classification -> composition -> the real public `basis-core`
>   `OperationAwareEnforcementPoint` -> HTTP enforcement classification -> gateway + kernel audit
>   evidence -> readiness diagnostics), covering allow, explicit deny, default deny,
>   `not_applicable`, untrusted-producer rejection, and a semantic-startup-failure scenario. See
>   [`demo/operation-aware/README.md`](../../demo/operation-aware/README.md). Adds no production
>   runtime behavior — `src/` is unchanged by this PR.
> - Sections below retain this document's original planning-time language (including forward
>   references to "future PRs" and design recommendations phrased before implementation). Where
>   the shipped implementation differs from an early draft's wording — notably §10's
>   evidence-composition description — a note is added inline rather than silently rewriting the
>   historical rationale.

This document is the authoritative implementation plan for the operation-aware phase of `basis-gateway`: controlled adoption of the operation-aware kernel surface released in `basis-core`. Sections 1–18 below are retained in their original planning-time form as the historical design record; the callout above is the authoritative statement of current implementation state.

---

## 1. Purpose

`basis-gateway` `v0.1.0` is a working, released trust boundary in front of `basis-core`'s original `EnforcementPoint`: it authenticates callers (OIDC or BASIS-local token), composes canonical actions and resource identifiers from adapter-normalized input, invokes `EnforcementPoint.evaluate()`, enforces the returned `DecisionResponse`, and emits both kernel and gateway-level audit evidence. That surface is stable, tested, and unaffected by anything in this plan.

`basis-core` `v0.2.0` is released and adds an entirely additive operation-aware surface alongside the `v0.1.0` surface it does not modify: `OperationAwareDecisionRequest`, `OperationAwareEnforcementPoint`, `OperationAwareDecisionResponse`, `EvaluationTrace`, and bounded, kernel-produced `AuditEvidence`. This surface can evaluate richer operational context — location, device, protocol evidence, operation intent, safety/environment/risk context — against a structured `PolicyBundle`, and it distinguishes `ALLOW`, explicit `DENY`, default deny, and `NOT_APPLICABLE` as separate, auditable outcomes.

`basis-gateway` is the next repository in the ecosystem's downstream rollout sequence. `basis-architecture`'s `ROADMAP.md` states this explicitly: `basis-core` v0.2.0's release "completes the kernel implementation phase," and the next step is "a governed, incremental adoption sequence," beginning with `basis-gateway operation-aware integration`, before `basis-console`, `basis-identity`, or `basis-adapters` do anything with the richer surface. The console has nothing operation-aware to explain to an operator until the gateway can produce operation-aware decisions and evidence; adapters and identity should evolve based on real integration needs the gateway work surfaces, not speculative work performed ahead of it. Gateway is the correct next repository because it is the only component positioned to compose the richer `OperationAwareDecisionRequest` — combining verified identity, adapter-normalized evidence, and gateway-derived context — and because it already owns the analogous v0.1 composition and enforcement responsibilities this phase extends rather than replaces.

This capability this phase introduces is: the ability for `basis-gateway` to accept a normalized operation carrying operation-aware context, compose it into a trustworthy `OperationAwareDecisionRequest`, invoke the released `OperationAwareEnforcementPoint`, and enforce and record the result — as an **additive** capability alongside the existing `/v1/evaluate` path, not a replacement for it.

This is not a redesign of `basis-gateway`. The trust-boundary model, the authentication model, the fail-closed philosophy, the action/resource composition boundary, and the audit-evidence-is-not-enforcement principle are all unchanged and are reused, not reinvented, by this plan. What changes is the width of the object the gateway composes and which kernel entry point it calls for the new path.

> The purpose of this phase is to make `basis-gateway` a trustworthy and semantically honest operation-aware enforcement boundary around `basis-core` v0.2.0.

---

## 2. Current State

This section describes `basis-gateway` as released and as it exists on `main` (commit `80083be`, matching `origin/main` at the time this plan was written). All citations are to files in this repository unless noted otherwise.

### 2.1 Authentication

`src/basis_gateway/auth/runtime.py` (`authenticate()`) dispatches on `GatewayConfig.auth_mode` (`src/basis_gateway/config.py`, `AuthMode` enum: `OIDC` default, `BASIS_LOCAL_TOKEN`) to one of two verifiers — `OIDCVerifier` (`auth/oidc.py`) or the BASIS-local token verifier (`auth/basis_local_token.py`) — with no fallback between modes. Both paths converge on the same `(NormalizedSubject, IdentityContext)` pair via `auth/subject_mapper.py`'s `map_claims()` (OIDC) or `basis_local_verification_result_to_gateway_identity()` (BASIS-local token). Subject identity is never caller-supplied: `EvaluateRequest` (`api/schemas.py`) rejects `subject_id`/`subject_roles` in the request body via a `model_validator`.

There is no existing concept, anywhere in this repository, of a caller class distinct from "authenticated subject." A human operator, a service account, and a protocol adapter all authenticate through the identical path today and are indistinguishable to the gateway once authenticated — this repository has no notion of a "trusted adapter" identity separate from "any other caller who presents a valid Bearer token." This is directly relevant to §5a below.

### 2.2 Identity normalization

`auth/subject_mapper.py` produces a `NormalizedSubject` (subject_id, name, roles, attributes) from verified claims only (`realm_access.roles` or flat `roles`; `sub` required). `core/evaluator.py`'s `_build_subject()` and `_build_identity_context()` translate that into `basis-core`'s `Subject` and `IdentityContext` domain types.

### 2.3 Current request model and `/v1/evaluate`

`api/schemas.py`'s `EvaluateRequest` accepts `request_id` (optional), `action` (required — either a composite `{verb}:{domain}` or a bare verb), `resource_type` (optional), `resource_id` (optional), and `context: dict[str, str]`. `api/routes.py`'s `evaluate()` handler:

1. Runs the fail-closed audit probe if `AUDIT_FAIL_CLOSED=true` and the writer is degraded.
2. Parses and validates the request body (`400` on failure, `gateway.validation_failed` event).
3. Rejects caller-supplied `basis_gateway.*` context keys (`core/actions.py`'s `reserved_key_collisions()`), then composes the action via `core/actions.py`'s `compose_action()` and the resource identifier via `core/resources.py`'s `compose_resource_id()`. Composition evidence is recorded under the `basis_gateway.*` reserved context namespace only when composition actually occurred.
4. Extracts and verifies the Bearer token (`401` on failure, `gateway.authentication_failed` event).
5. Confirms the evaluator is initialized (`503`, `gateway.evaluator_unavailable`).
6. Emits `gateway.evaluation_requested` (pre-kernel receipt).
7. Calls `GatewayEvaluator.evaluate()` (`core/evaluator.py`), which builds a `basis-core` `DecisionRequest` and calls `EnforcementPoint.evaluate()`.
8. Maps `DecisionOutcome.ALLOW` → `200`, anything else → `403`. `NOT_APPLICABLE` is not rewritten in the response body — `outcome` in `EvaluateResponse` reports the kernel's literal value (`"allow"`/`"deny"`/`"not_applicable"`) while the HTTP status collapses `DENY` and `NOT_APPLICABLE` to `403`.

### 2.4 Current `basis-core` integration

`core/evaluator.py`'s `GatewayEvaluator` wraps `basis_core.enforcement.EnforcementPoint` (v0.1 surface) exclusively. It imports `from basis_core.decisions import DecisionOutcome, DecisionRequest, DecisionResponse`, `from basis_core.domain import IdentityContext, Subject, SubjectType`, `from basis_core.enforcement import EnforcementPoint`, `from basis_core.policy import PolicyEngine, RolePolicyRule`. Nothing in the current codebase imports `basis_core.decisions.operation_aware`, `basis_core.enforcement.operation_aware`, `basis_core.audit.operation_aware`, or `basis_core.policy.operation_aware` — the operation-aware surface is entirely unused today. `pyproject.toml` pins `basis-core>=0.1.0` with no upper bound, so `v0.2.0` (additive to `v0.1.0`) already satisfies the existing constraint without a dependency change, but the gateway does not yet import or exercise any symbol from it.

### 2.5 Policy loading

`policy/loader.py`'s `load_policy_engine()` reads a flat JSON file (`{"rules": [{"rule_name": ..., "role_table": {...}}]}`) at startup and constructs a `basis_core.policy.PolicyEngine` from `RolePolicyRule` objects — a simple role-table format, structurally unrelated to the operation-aware `PolicyBundle`/`OperationAwarePolicyRule` model. Loading happens once, synchronously, at startup (`main.py`'s `lifespan()`), with no reload path. There is no existing concept of loading a `PolicyBundle` in this repository.

### 2.6 Audit emission

Two categories of `AuditEvent`, both `event_type`s from `basis-core`'s `basis_core.audit` package, are emitted through the same `GatewayAuditWriter` (`audit/writer.py`, wrapping `basis_core.audit.LogAuditWriter`, with consecutive-failure tracking and readiness escalation):

- **Kernel decision events** — written automatically by `EnforcementPoint` itself for every completed evaluation.
- **Gateway-level events** (`audit/gateway_events.py`, `event_type: SYSTEM_EVENT`) — `gateway.evaluation_requested`, `gateway.authentication_failed`, `gateway.validation_failed`, `gateway.evaluator_unavailable`, `gateway.evaluation_failed_closed`, `gateway.audit_recovery_probe` — for outcomes that occur before or outside kernel evaluation.

There is no `GatewayAuditEvent` model in this repository today (that name is a `basis-architecture` concept, not an implemented type here); gateway-level events reuse `basis-core`'s existing `AuditEvent` schema with `event_type: SYSTEM_EVENT`, per `docs/audit-model.md`.

### 2.7 Correlation IDs

`middleware/correlation.py`'s `CorrelationMiddleware` generates a UUIDv4 unconditionally per request, stores it on `request.state.correlation_id`, and adds it to every response via `X-Correlation-ID`. Caller-supplied `X-Correlation-ID` headers are ignored by design (`docs/audit-model.md` §3). `request_id` defaults to `correlation_id` when the caller does not supply one (`routes.py`, step 6 above).

### 2.8 Readiness

`readiness.py`'s `ReadinessState` tracks named components; `/ready` is `200` only when every *registered* component is ready. Components registered today: `configuration_loaded`, `oidc_configured`/`jwks_available` (OIDC mode) or `basis_local_token_configured` (BASIS-local token mode), `policy_loaded`, `audit_writer`, `evaluator_initialized`. An unregistered component never blocks readiness.

### 2.9 Compatibility commitments

`docs/release-readiness.md` and the `README.md` "Architecture position" section state the current invariants this plan must preserve: kernel evaluates / gateway enforces / audit records evidence; subject identity from token only; fail closed on every error path; gateway-generated correlation IDs. `CHANGELOG.md`'s `[Unreleased]` entry documents the action/resource composition boundary as the most recent additive change to `/v1/evaluate` — precedent for how this repository has previously extended the endpoint without a breaking change (accepting a second request shape behind validation, not replacing the first).

### 2.10 Current vs. planned vs. transitional

> **Updated for PR 10** — this table described the state at planning time (before PRs 2–9
> implemented this plan). It is retained for historical context; see the "Implementation Status"
> callout at the top of this document for the current state.

| Behavior | Status at planning time | Status as of PR 10 |
|---|---|---|
| `/v1/evaluate`, `EvaluateRequest`/`EvaluateResponse`, v0.1 `EnforcementPoint` integration | **Current, released** — unaffected by this plan | **Current, released** — still unaffected |
| Action/resource composition boundary (`core/actions.py`, `core/resources.py`) | **Current, released** — reused, not replaced, for operation-aware composition | **Current, released** — reused unchanged by the now-implemented operation-aware path |
| OIDC / BASIS-local token dual auth mode | **Current, released** — reused unchanged as the identity source for operation-aware requests | **Current, released** — reused unchanged |
| Operation-aware request ingestion, `OperationAwareEnforcementPoint` integration, `PolicyBundle` loading, operation-aware audit/readiness | **Planned** — this document | **Current, implemented, feature-flagged** (`OPERATION_AWARE_ENABLED`, default `false`) — PRs 3–9 |
| Operation-aware documentation and release hardening | not yet scoped | **Current** — this PR (10) |
| Bounded end-to-end operation-aware demonstration | not yet scoped | **Implemented** — PR 11 (`demo/operation-aware/`) |
| Nothing in this repository is deprecated or transitional as a result of this plan | — the operation-aware surface is additive; `/v1/evaluate` has no announced deprecation | Still true — `/v1/evaluate` remains supported with no announced deprecation |

---

## 3. Target State

```text
Authorization subject (caller) + Operation producer (may be the same caller, or may not be)
    ↓
Normalized operation input                    (new: gateway-validated)
    ↓
Gateway-owned authentication and identity normalization   (existing: auth/runtime.py, unchanged)
    ↓
Operation-producer trust classification        (new: §5a — is this authenticated caller
                                                 also a trusted operation producer?)
    ↓
Context validation and composition             (new: rejects gateway-owned-field spoofing
                                                 and non-trusted-producer context assertions;
                                                 composes canonical action/resource reusing
                                                 core/actions.py + core/resources.py)
    ↓
OperationAwareDecisionRequest                  (new: basis_core.decisions.operation_aware)
    ↓
OperationAwareEnforcementPoint                 (new: basis_core.enforcement.operation_aware,
                                                 configured with a loaded, semantically
                                                 preflighted PolicyBundle — see §8a)
    ↓
OperationAwareEnforcementResult
  (OperationAwareDecisionResponse + AuditEvidence + EnforcementDisposition)
    ↓
Gateway enforcement mapping                    (new: kernel status/outcome/failure-reason/
                                                 disposition preserved distinctly from the
                                                 gateway's own HTTP classification — see §9)
    ↓
GatewayAuditEvent (conceptual)                 (new: embeds the kernel's AuditEvidence in full,
                                                 plus gateway enforcement-boundary facts)
    ↓
HTTP response
```

**What each stage owns**, restated against this repository's modules:

- **Authorization subject / operation producer** — see §5a. This plan draws an explicit distinction between the human, service, or workload whose *authority* is being evaluated (the authorization subject) and the adapter, integration, or trusted service that normalized the operation and supplied operational context (the operation producer). The two may be the same caller in a simple deployment; they are not the same *concept*, and this plan does not treat them as automatically equivalent.
- **Authentication and identity normalization** is exactly `auth/runtime.py` and `auth/subject_mapper.py`, reused without modification. Operation-aware requests are authenticated identically to `/v1/evaluate` requests.
- **Operation-producer trust classification** is new gateway logic (§5a, §7) that determines, from the already-authenticated subject and gateway configuration, whether this caller may assert operation-producer context. This step has no v0.1 analogue.
- **Context validation and composition** is new gateway logic, structurally parallel to the existing action/resource composition boundary: it validates that no caller-owned field masquerades as a gateway-owned one, that no untrusted caller asserts operation-producer-only context, and it composes the canonical action/resource identifier using the same `core/actions.py`/`core/resources.py` functions already released — there is no second composition grammar.
- **`OperationAwareDecisionRequest`** construction is new gateway logic (a new module, not yet named a route) that assembles verified identity, composed action/resource, and validated context into the kernel's typed request model. Construction-time `ValidationError` is a gateway-owned, pre-kernel failure.
- **`OperationAwareEnforcementPoint`** is `basis-core`'s public kernel entry point, configured once at startup with an `OperationAwareEvaluationEngine` (stateless) and an already-validated, semantically preflighted `PolicyBundle` (loaded by new gateway policy-loading logic, parallel to but distinct from `policy/loader.py`; see §8a). `evaluate()` never raises.
- **Gateway enforcement mapping** preserves the kernel's evaluation status, semantic outcome, failure reason, and computed `EnforcementDisposition` as independent facts and derives an HTTP status from them without collapsing any of them into another (§9, §11).
- **`GatewayAuditEvent`** (conceptual — see §10) embeds the kernel's `AuditEvidence` in full and adds gateway-owned enforcement-boundary facts (route, HTTP result, correlation ID, timing, producer-trust classification) the kernel cannot know, following the same pattern `audit/gateway_events.py` already establishes for v0.1 gateway-level events.

---

## 4. Integration Boundaries

"Supplies" = originates the raw value. "Derives" = computes from other trusted inputs. "Verifies" = cryptographically or structurally confirms correctness. "Validates" = checks shape/presence without asserting truth. "Composes" = assembles a canonical form from parts. "Evaluates" = applies policy semantics. "Preserves" = passes through unchanged, never reinterpreting. "Enforces" = converts a decision into a runtime effect. "Records" = writes evidence.

This table splits the caller-side column in two, per §5a: **authorization subject** (whoever authenticated the HTTP request) and **operation producer** (the narrower class, established only by producer-trust classification, that may assert operation-aware context). A caller is always an authorization subject once authenticated; a caller is an operation producer only when the gateway has classified it as one.

| Concern | Authorization subject | Operation producer | Gateway | Core |
|---|---|---|---|---|
| Protocol parsing | — | Supplies (owns exclusively) | — | — |
| Normalized action input | Supplies (bare verb + resource_type, or composite) | — | Validates | — |
| Canonical action composition | — | — | Composes (reuses `core/actions.py`) | — |
| Canonical resource composition | — | — | Composes (reuses `core/resources.py`) | — |
| Caller authentication | Presents credential | — | Verifies | — |
| Subject normalization | — | — | Derives (`auth/subject_mapper.py`) | — |
| Operation-producer trust classification | — | — | Derives (`§5a`, from the verified subject + gateway configuration — never self-asserted) | — |
| Evaluation time | — | — | Derives (gateway clock; never caller-asserted) | — |
| Location context | — | Trusted-producer-asserted, optionally | Validates provenance; rejects from a non-producer caller; never fabricates | Evaluates |
| Device context | — | Trusted-producer-asserted, optionally | Validates provenance; rejects from a non-producer caller; never fabricates | Evaluates |
| Protocol evidence | — | Supplies | Preserves as reference/evidence; rejects from a non-producer caller | Evaluates (as evidence only; never protocol-aware) |
| Operation intent | — | Trusted-producer-asserted, optionally | Validates against closed vocabulary; rejects from a non-producer caller | Evaluates |
| Safety context | — | Trusted-producer-asserted, optionally | Validates provenance; rejects from a non-producer caller; never infers | Evaluates |
| Environmental context | — | Trusted-producer-asserted, optionally | Validates provenance; rejects from a non-producer caller; never infers | Evaluates |
| Risk context | — | Trusted-producer-asserted, optionally | Validates provenance; rejects from a non-producer caller; never calculates | Evaluates |
| Identity/adapter evidence references | — | Trusted-producer-asserted, optionally | Validates shape; rejects from a non-producer caller; never inspects referenced content | Evaluates (as evidence only) |
| Policy evaluation | — | — | Invokes | Evaluates (sole authority) |
| Startup semantic preflight | — | — | Invokes (§8a) | Evaluates (same public surface, synthetic request) |
| Kernel audit evidence | — | — | Preserves, embeds in full (§10) | Produces (`AuditEvidence`) |
| Enforcement disposition | — | — | Preserves (kernel-computed) → classifies HTTP status (§9) | Derives (`EnforcementDisposition`, per ADR-0006 Decision 7) |
| Gateway audit event | — | — | Composes and records | — |

Ownership is deliberately not shared for any row above. An **ordinary authenticated API caller is not automatically an operation producer** — see §5a for the full rule and the rejection behavior that applies when a non-producer caller attempts to assert producer-only context. Where a classified operation producer may assert a value (location, device, protocol evidence, intent, safety/environment/risk context), the gateway's role is still bounded to validating shape and provenance classification (§5) — never verifying the truth of the producer's claim, which the gateway structurally cannot do, consistent with the trusted-adapter-normalization boundary in `basis-architecture`'s threat model (§6.3).

---

## 5. Context Ownership and Provenance

This is the central section of this plan. `basis-core` evaluates supplied context deterministically but cannot determine whether upstream context is truthful — that determination, to the extent it is possible at all, belongs to the gateway. The governing principle, restated from the PR objective and consistent with `basis-architecture`'s "adapters normalize, gateway composes and enforces, core evaluates" division of labor:

> **Missing context is safer than fabricated context.** The gateway must preserve absence when no governed source exists. This plan introduces no default values for safety, environmental, risk, location, or device context.

### 5a. Trusted Operation Producer

Two distinct concepts are in play for every operation-aware request, and this plan does not treat them as equivalent:

```text
Authorization subject
    The human, service, or workload whose authority is being evaluated —
    subject_id, subject_roles, subject_attrs. Established by Bearer-token
    authentication (§2.1), exactly as for /v1/evaluate today.

Operation producer
    The adapter, gateway integration, or trusted service that normalized
    the operation and supplied operational context — location, device,
    protocol evidence, operation intent, safety/environment/risk context,
    identity/adapter evidence references.
```

**Authentication of the authorization subject does not prove that the same caller is authorized to assert operation-producer context.** A caller can present a perfectly valid Bearer token and still have no standing to claim, for example, that a request originated from a specific protocol operation under a specific safety context — that claim requires trust in the caller as a *producer*, which is a narrower and separate question from trust in the caller as an authenticated *subject*.

> **An ordinary authenticated API caller must not be treated as a trusted adapter or operation producer.**

As §2.1 notes, this repository has **no existing mechanism** that distinguishes an adapter from any other authenticated caller. This plan does not invent a new transport mechanism to close that gap — nothing in the existing gateway architecture makes one unavoidable — but it also does not paper over the gap by treating every authenticated caller as a trusted producer by default. Instead, this plan takes the position that **producer trust must be established, explicitly and conservatively, from what the gateway already has**: the verified `NormalizedSubject` produced by the existing authentication path, checked against new, explicit gateway configuration.

**Recommended initial direction (not implemented in this PR, scoped to §16 PR 4):** a governed, configuration-driven classification of the already-authenticated subject as a trusted operation producer — for example, a configured allowlist of producer subject IDs (`OPERATION_PRODUCER_SUBJECT_IDS`, comma-separated, mirroring the existing `basis_local_token_audience` CSV convention in `config.py`) or a configured required role claim (e.g. a subject whose verified `roles` include a configured `operation-producer`-style role). This reuses the existing authentication transport and the existing `NormalizedSubject.roles`/`subject_id` fields — it adds a classification *step*, not a new *mechanism* for proving identity. The specific configuration shape is left to PR 4's implementation, not fixed here.

**Other mechanisms a deployment could use for stronger producer trust in the future** — named here so this plan does not appear unaware of them, not selected or implemented:

- Registered machine-client identity (a distinct OAuth2 client ID recognized as a producer)
- Client-credentials grant issued specifically to adapter integrations
- mTLS client-certificate identity
- Signed adapter evidence (a cryptographic signature over the normalized operation, verifiable independent of the Bearer token)
- Gateway configuration mapping a network source or deployment topology to a producer identity
- Another explicitly governed mechanism, decided through its own `basis-architecture` review if a deployment's threat model requires it

**Until a producer-trust classification mechanism is configured and applied, no caller is treated as an operation producer.** The safe default is that no context field gated by this rule is ever accepted, from anyone, in an unconfigured deployment. Concretely:

> Arbitrary, non-producer-classified callers cannot supply policy-decisive operation-producer context. If such a caller's request includes any operation-producer-only field (§5's table, "Trusted-producer-asserted" rows), the gateway **rejects the request** (`400`, per §7/§11) rather than silently omitting the field and proceeding. Rejection, not silent stripping, is this plan's chosen behavior: it is consistent with how this repository already treats ambiguous or untrusted input at the composition boundary (`ActionCompositionError`/`ResourceCompositionError` reject rather than guess), and it surfaces a misconfigured or misbehaving caller immediately instead of silently discarding evidence the caller believed it was supplying.

This rule applies only to the *new* operation-aware-specific context categories introduced by this plan. It does not retroactively restrict the existing, already-released v0.1 action/resource composition boundary (`core/actions.py`/`core/resources.py`), which every caller — producer or not — continues to use exactly as it does for `/v1/evaluate` today; that boundary's risk posture is existing, accepted behavior this plan does not revisit.

### Provenance table

Gateway trust classifications used below (a closed set for this plan):

- **Verified** — cryptographically confirmed from the Bearer token.
- **Gateway-derived** — computed by the gateway from trusted inputs.
- **Trusted-producer-asserted** — supplied by a caller the gateway has classified as an operation producer per §5a. Never used for a caller that has not been so classified.
- **Untrusted-caller-asserted** — supplied by an authenticated caller not classified as an operation producer. Default classification for producer-only fields; such fields are rejected, not forwarded, when this is the only classification a caller can offer (§5a).
- **Configuration-derived** — derived from gateway/deployment configuration rather than any per-request assertion.
- **Unavailable** — no source exists for this field in this plan's scope; the field stays absent.

| Field | Source | Gateway trust classification | Policy-decisive? | Missing-value behavior | Caller may supply/override? |
|---|---|---|---|---|---|
| `subject_id` | Verified Bearer token (`sub` claim) | Verified | Yes | Request rejected pre-kernel (no evaluation without identity) | No — `EvaluateRequest`'s existing rejection pattern (`reject_caller_supplied_subject`) extends to the operation-aware input model |
| `subject_roles` | Verified Bearer token claims | Verified | Yes | Empty list (deny-by-absence in RBAC-shaped policy) | No |
| `subject_attrs` | Verified Bearer token claims (`auth/subject_mapper.py` attribute claims) | Verified | Yes, if policy uses ABAC conditions | Empty map | No |
| `identity_source` / `authority_mode` | Gateway configuration (`AuthMode`) or `basis-identity`, when deployed upstream | Gateway-derived / configuration-derived | Possibly (identity-authority-mode-scoped policy) | Absent — never guessed | No |
| `identity_evidence_reference` | `basis-identity`, when deployed upstream and the calling integration is classified as an operation producer (§5a) | Trusted-producer-asserted | Possibly | Absent — and rejected outright (400) if supplied by a non-producer caller, per §5a | No — gateway constructs this from its own auth path and producer-trust classification, never from an unclassified caller's assertion |
| `action` (composite) | Caller/adapter (bare verb + resource_type, or composite) | Untrusted-caller-asserted (verb; existing v0.1 posture, unrestricted by this plan — see §5a's scoping note), gateway-composed (composite) | Yes (defines what is being evaluated) | Rejected — required field | Yes, the bare-verb/resource_type pair (reused from `core/actions.py`); the *composed* canonical form is gateway-owned and not independently overridable |
| `resource` (canonical resource id) | Caller/adapter (local resource_id + resource_type, or typed) | Untrusted-caller-asserted (local id; existing v0.1 posture — see §5a's scoping note), gateway-composed (canonical form) | Yes | Absent permitted (resource-independent/domain-level request) | Yes, the local form; the composed canonical form is gateway-owned |
| `resource_type` | Caller/adapter | Untrusted-caller-asserted (existing v0.1 posture — see §5a's scoping note) | Yes | Absent permitted when resource composition does not require it | Yes |
| `operation_intent` | Operation producer (normalized from the protocol operation), when classified per §5a | Trusted-producer-asserted | Yes | Absent — condition referencing it simply does not match (per evaluation semantics §10); rejected outright (400) if supplied by a non-producer caller | Yes, only from a classified operation producer — never caller-overridable by an unclassified caller |
| `location` | Operation producer or gateway/site configuration, when classified per §5a | Trusted-producer-asserted / configuration-derived | Yes, if policy scopes on site/zone | Absent — never inferred from IP, network segment, or any other gateway-observed signal; rejected outright if supplied by a non-producer caller | Yes, only from a classified operation producer |
| `device` (identity, class) | Operation producer, when classified per §5a | Trusted-producer-asserted | Yes | Absent; rejected outright if supplied by a non-producer caller | Yes, only from a classified operation producer |
| `protocol_context` | Operation producer, when classified per §5a | Trusted-producer-asserted | Yes (as evidence only; kernel remains protocol-agnostic) | Absent; rejected outright if supplied by a non-producer caller | Yes, only from a classified operation producer |
| `safety_context` | Operation producer or a governed safety-context source, when classified per §5a | Trusted-producer-asserted | Yes | Absent — **never defaulted to a "safe" or "normal" value**; a safety-relevant condition that requires this context and finds it missing must deny or fail per evaluation semantics §10, not assume a benign state. Rejected outright if supplied by a non-producer caller. | Yes, only from a classified operation producer |
| `environment_context` | Operation producer or deployment configuration, when classified per §5a | Trusted-producer-asserted / configuration-derived | Yes | Absent; rejected outright if supplied by a non-producer caller | Yes, only from a classified operation producer |
| `risk_context` | Operation producer or a governed risk-scoring source, when classified per §5a | Trusted-producer-asserted | Yes | Absent — never computed by the gateway; the gateway performs no risk calculation. Rejected outright if supplied by a non-producer caller. | Yes, only from a classified operation producer |
| `adapter_evidence_reference` | Operation producer, when classified per §5a | Trusted-producer-asserted | Possibly | Absent; rejected outright if supplied by a non-producer caller | Yes, only from a classified operation producer |
| `evaluation_time` | Gateway clock | Gateway-derived | Possibly (time-window policy) | N/A — always gateway-generated at request-handling time; never caller-asserted, never defaulted from the kernel (the kernel has no clock, per `operation-aware-evaluation-orchestration.md` §7) | **No** |
| `request_id` | Gateway (or caller, mirroring the existing `EvaluateRequest.request_id` precedent) | Gateway-derived, with an existing precedent for optional caller supply | No (correlation only) | Gateway generates one (mirrors `request_id or correlation_id` in `routes.py` today) | Optional — same policy as `/v1/evaluate` today; unlike `DecisionRequest.request_id`, `OperationAwareDecisionRequest.request_id` has no default factory in the kernel itself, so the gateway must always supply a value |
| `correlation_id` | Gateway (`CorrelationMiddleware`) | Gateway-derived | No | Always gateway-generated | **No** — caller-supplied `X-Correlation-ID` headers are ignored today and this plan does not change that |
| `expected_policy_version` | — | Unavailable in this rollout | No | Not part of the accepted input surface at all | **Not applicable** — see §5b; this field is omitted from the input model entirely for now |

### 5b. `expected_policy_version` is omitted, not accepted-but-unenforced

An earlier draft of this plan accepted `expected_policy_version` as an "informational, unenforced" caller assertion. That is a misleading contract: it invites a caller to believe supplying the field has some effect, when this plan implements no comparison behavior against it whatsoever. This plan now takes the stricter position:

> **`expected_policy_version` is omitted from the gateway-facing operation-aware request model in this initial integration.** The kernel field (`OperationAwareDecisionRequest.expected_policy_version`) may remain unset by the gateway. A caller that supplies this field in the request body receives the same rejection any other unrecognized field would (§6) — it is not silently accepted and discarded, and it is not silently accepted and ignored.

Defining `expected_policy_version` comparison behavior — the authoritative loaded policy version, comparison timing, mismatch response, HTTP classification, audit representation, and readiness implications — is deferred to a future, separately-scoped architecture decision. This PR does not implement any part of that future behavior.

Two rows deserve emphasis because they are the fields most likely to be misused if this table is not honored precisely:

- **`evaluation_time` must never be caller-asserted.** `OperationAwareDecisionRequest.evaluation_time` is optional and has no default factory in the kernel — the kernel will not generate it. If the gateway does not generate it, it stays absent, which is the honest outcome for a request with no time-window-relevant policy; the gateway must not "help" by echoing a caller-supplied timestamp into this field.
- **`safety_context`, `environment_context`, `risk_context` must never receive a gateway-synthesized default, and must never be accepted from a caller that is not a classified operation producer.** The published `basis-core` v0.2.0 contract, `basis-architecture`'s evaluation semantics document (§10, "missing context behavior"), and this plan all converge on the same rule: a condition that references context the request does not carry simply does not match. Inventing a "presumed safe" default here, or accepting these categories from an unclassified caller, would silently manufacture policy-decisive evidence the gateway has no authority to assert.

---

## 6. Normalized Operation Input

This section defines the conceptual shape of the future gateway-side input model. **No implementation is included in this PR.**

The normalized operation input model is validated in two layers, mirroring where the necessary information becomes available:

1. **Shape validation** (no identity required yet) — every field's type, format, and closed-vocabulary membership, exactly as `EvaluateRequest` validates today. This layer cannot yet know whether the caller is a classified operation producer (§5a), because producer-trust classification depends on the already-authenticated subject.
2. **Provenance/trust validation** (after authentication) — whether the *specific* fields present on this request are ones this *specific*, now-authenticated caller is permitted to supply, per §5a/§5's table. A structurally valid request from a non-producer caller that includes a producer-only field fails at this layer, not the first.

An authenticated caller may submit, conceptually:

- The bare-verb/resource_type/resource_id triple already accepted by `EvaluateRequest` today (reused unchanged, and not subject to producer-trust gating — see §5a's scoping note).
- `operation_intent`, `location`, `device`, `protocol_context`, `safety_context`, `environment_context`, `risk_context` — each optional, each validated for shape at layer 1 and for producer-trust provenance at layer 2 (§5).
- `identity_evidence_reference` and `adapter_evidence_reference`, when the deployment has an upstream `basis-identity` or an adapter that produces them — never accepted as raw evidence content, only as the reference-shaped model `basis-core` already defines, and subject to the same producer-trust gating as the fields above.
- `context: dict[str, str]` — the existing free-form evaluation context, reused, with the same reserved-namespace rejection (`core/actions.py`'s `RESERVED_CONTEXT_PREFIX`) already enforced for `/v1/evaluate`.

`expected_policy_version` is **not** part of this input model in this rollout — see §5b. The model should use the same `extra="forbid"`-style strictness `EvaluateRequest` already uses (`ConfigDict(extra="forbid")`), so a caller that supplies `expected_policy_version` — or any other field this model does not define — is rejected at shape-validation time as an unrecognized field, not silently accepted and dropped.

A caller must **not** be allowed to assert, in this new input model, any of the following gateway-owned facts — this list restates §5's "Caller may supply/override?" column as a single, explicit enumeration for implementation reference:

- Authenticated `subject_id`, `subject_roles`, `subject_attrs`
- Verified `identity_source`/`authority_mode`
- `evaluation_time`
- Kernel outcome, `evaluation_status`, `failure_reason`, or any other result field
- `EnforcementDisposition`
- `correlation_id`
- The gateway's own operation-producer trust classification for this caller (§5a) — a caller cannot assert "I am a trusted producer" as a request field; that classification is derived entirely from the already-authenticated subject and gateway configuration
- Any gateway audit fact (route, HTTP result, timing)

And, per §5a, a caller must not be allowed to assert operation-producer-only context (`operation_intent`, `location`, `device`, `protocol_context`, `safety_context`, `environment_context`, `risk_context`, `identity_evidence_reference`, `adapter_evidence_reference`) **unless the gateway has classified this specific authenticated caller as a trusted operation producer.** This is a distinct rejection reason from the gateway-owned-fact list above, because the field itself is legitimately part of the schema — the rejection is about *who* is asserting it, not whether the field exists.

**Context-spoofing risk control**: the existing `reject_caller_supplied_subject` model-validator pattern in `EvaluateRequest` and the existing `reserved_key_collisions()` check in `core/actions.py` are the two proven mechanisms this repository already uses to reject exactly this class of forgery. The operation-aware input model should extend both patterns rather than invent new ones: (1) a model-validator that rejects any top-level field name that collides with a gateway-owned fact listed above, (2) an extension of `RESERVED_CONTEXT_PREFIX` collision-checking to any operation-aware context dict the model accepts, and (3) a new, post-authentication provenance check (§5a, §7) that rejects producer-only fields from a caller not classified as a producer. This plan does not repeat the identical implementation here; it commits to reusing the pattern, not to a specific new function signature.

**API surface decision, recommended but not implemented here**: A **separate endpoint** is the recommended direction — see §12 for the full compatibility analysis. This section notes only that a separate endpoint implies a separate request model (this section) rather than a discriminated variant of `EvaluateRequest`, because the two request shapes do not overlap cleanly: `EvaluateRequest.action` is required and always a single string; the operation-aware model's identity-bearing fields are absent by construction (identity never comes from the body in either model, but the *shape* of everything else differs enough that a discriminated union would be more confusing than clarifying to callers). This is labeled a planned API decision, not a foreclosed one — see §12.

---

## 7. Request Composition

The gateway constructs `OperationAwareDecisionRequest` from:

- **Identity derivation from verified authentication** — unchanged, reuses `auth/runtime.py` → `auth/subject_mapper.py` → the same `(NormalizedSubject, IdentityContext)` pair `/v1/evaluate` already produces. No new authentication code path.
- **Operation-producer trust classification** — new: after authentication succeeds, the gateway evaluates the authenticated subject against the configured producer-trust mechanism (§5a) and derives a boolean-shaped classification for this request (`is_trusted_operation_producer`, or equivalent — naming left to implementation). This classification is never caller-asserted and never cached across requests in a way that could go stale relative to configuration; it is computed fresh per request from the current configuration and the current request's authenticated subject.
- **Producer-context gating** — new: if the normalized input includes any operation-producer-only field (§5a's list) and the classification above is negative, the gateway rejects the request (`400`) before constructing `OperationAwareDecisionRequest`. If the classification is positive, those fields are composed into the request as trusted-producer-asserted evidence.
- **Canonical action composition** — reuses `core/actions.py`'s `compose_action()` unchanged. The operation-aware path composes the same way the v0.1 path does; there is exactly one action-composition boundary in this repository, not two.
- **Canonical resource identifier composition** — reuses `core/resources.py`'s `compose_resource_id()` unchanged, for the same reason.
- **Operation-intent validation** — new: validates the operation-producer-supplied `operation_intent` string against the closed `basis_core.decisions.operation_aware.OperationIntent` vocabulary (`read_only`/`state_changing`/`control_affecting`) before constructing the request, so an invalid value fails with a gateway-owned `400`, not a kernel-owned `invalid_request` evaluation failure. (Both are legitimate outcomes; validating early keeps the failure category consistent with how `compose_action`/`compose_resource_id` failures are already handled.)
- **Gateway-generated evaluation time** — new: `datetime.now(timezone.utc)`, generated once per request, exactly as `core/evaluator.py`'s existing `_build_identity_context()` and `DecisionRequest` construction already do for the v0.1 path (`timestamp=datetime.datetime.now(...)`). No new pattern; the same gateway-clock convention extends to the new field.
- **Request and correlation identifiers** — `correlation_id` from `CorrelationMiddleware` (unchanged); `request_id` defaults to `correlation_id` when the caller does not supply one, mirroring the existing `request_id = eval_request.request_id or correlation_id` line in `routes.py`. Because `OperationAwareDecisionRequest.request_id` has no kernel-side default, this gateway-side default becomes load-bearing in a way it is not (structurally, only conventionally) for the v0.1 path.
- **Context validation** — reuses the reserved-namespace collision check; extends it to whatever new reserved keys the operation-aware composition evidence needs (mirroring `EVIDENCE_ACTION_COMPOSED`, etc., from `core/actions.py`).
- **Optional context** — every operation-aware context category is optional at construction; absence is passed through as absence (`None`), never coerced to an empty-but-present object, so that "field omitted" remains distinguishable from "field present but empty" for policy conditions that check `exists`/`not_exists`.
- **`expected_policy_version`** — not accepted; see §5b. `OperationAwareDecisionRequest.expected_policy_version` is left unset by the gateway in this phase.
- **Rejection of contradictory inputs** — reuses the existing `ActionCompositionError`/`ResourceCompositionError` rejection pattern (composite action + resource_type supplied together, typed resource_id + resource_type supplied together, etc.); the operation-aware path does not introduce a second, divergent set of contradiction rules for the same two fields.
- **Rejection of untrusted gateway-owned fields** — per §6.
- **Rejection of untrusted producer-only fields** — per §5a, §6, this section.
- **Deterministic serialization** — `OperationAwareDecisionRequest` is a Pydantic model; construction is deterministic given deterministic inputs. The gateway's own responsibility is to make sure its *inputs* to construction (composed action, composed resource, generated `evaluation_time`, generated `request_id`, resolved producer-trust classification) are deterministic per request, which they already are by construction in the reused v0.1 composition functions and the new classification step above.

The gateway composes the request. It does not decide whether the composed request will be allowed — that determination is the kernel's alone, per §9.

---

## 8. Kernel Integration Surface

The public surface this plan integrates against, exactly as `basis-core` `v0.2.0` publishes it in `docs/public-api.md`:

```python
from basis_core.decisions import (
    OperationAwareDecisionRequest,
    OperationIntent,
    OperationAwareFailureReason,
    OperationAwareEvaluationStatus,
    OperationAwareDecisionOutcome,
)
from basis_core.domain import (
    OperationAwareLocation,
    OperationAwareDevice,
    OperationAwareProtocolContext,
    OperationAwareSafetyContext,
    OperationAwareEnvironmentContext,
    OperationAwareRiskContext,
    IdentityEvidenceReference,
    AdapterEvidenceReference,
)
from basis_core.policy import PolicyBundle
from basis_core.enforcement import (
    OperationAwareEnforcementPoint,
    OperationAwareEnforcementResult,
    EnforcementDisposition,
)
from basis_core.audit import AuditEvidence
```

**Why `OperationAwareEnforcementPoint` is the expected integration boundary.** It is the sole documented, stable entry point for operation-aware evaluation (`docs/public-api.md`, "Stable entry point"). `basis_core.evaluation` (the orchestration package that composes policy facts and trace/audit contracts, per `basis-architecture` ADR-0006) is explicitly **not** public: "The evaluation-orchestration package (`basis_core.evaluation`, including `basis_core.evaluation.operation_aware`) remains internal. It has no `__all__`, no package-level export, and no entry in this document." `OperationAwareEvaluationEngine`, `OperationAwareDecisionResponse`, and every response/trace/audit-evidence assembly function are "implementation details reached only indirectly, through `OperationAwareEnforcementResult.response`." This repository must not import `basis_core.evaluation.*` directly, for the same reason `core/evaluator.py` today imports `basis_core.enforcement.EnforcementPoint` and not `basis_core.policy.engine` internals to drive evaluation manually.

**What request it receives.** `OperationAwareEnforcementPoint.evaluate()` takes `request: OperationAwareDecisionRequest`, `trace_id: str`, `evidence_id: str`, `recorded_at: datetime`, and `embed_evaluation_trace: bool = False` — all caller-supplied. The kernel generates no clock value, no UUID, and no random value anywhere in this call (`OperationAwareEnforcementPoint`'s own docstring, Decision 4 of ADR-0006): `trace_id`, `evidence_id`, and `recorded_at` must all be generated by the gateway, exactly as `evaluation_time` must be (§5, §7). This is a new gateway responsibility that has no v0.1 analogue — `EnforcementPoint.evaluate()` does not take these arguments because `DecisionRequest`/`AuditEvent` construction is entirely kernel-internal in the v0.1 path.

**What response and evidence it returns.** `OperationAwareEnforcementResult` (`@dataclass(frozen=True, slots=True)`), always: `response: OperationAwareDecisionResponse`, `audit_evidence: AuditEvidence | None` (absent only when it could not be trustworthily assembled, per ADR-0006 Decision 9 — i.e., only on the internal-error fallback path), and `disposition: EnforcementDisposition`.

**What failure conditions the gateway should expect.** `evaluate()` is documented to **never raise**. Every governed evaluator failure (the six `OperationAwareFailureReason` categories — `invalid_request`, `unsupported_schema_version`, `invalid_policy_bundle`, `policy_validation_failure`, `condition_evaluation_error`, `internal_evaluation_error`) is returned as a normal, structured result with `disposition = deny`, not raised as an exception. An unexpected internal exception anywhere inside the kernel's own composition is caught *inside* `OperationAwareEnforcementPoint.evaluate()` and converted to a fixed internal-error result before it ever reaches the gateway. The gateway's own exception-handling responsibility is therefore narrower than it is for the v0.1 path (where `routes.py` today wraps `evaluator.evaluate()` in a broad `try/except Exception` specifically because the v0.1 kernel's guarantees are weaker in this respect): the gateway must still handle exceptions from its **own** pre-kernel work (constructing `OperationAwareDecisionRequest` — a Pydantic `ValidationError` is possible and is gateway-owned, per §5/§7) and from its own post-kernel work (audit-event assembly, HTTP response construction), but not from the `evaluate()` call itself under normal operation. Defensive handling around the `evaluate()` call is still warranted at the enforcement boundary (fail-closed discipline does not depend on trusting a dependency's documentation alone — see §11), but the expected code path treats an exception surfacing from `evaluate()` as an integration-failure case, not a routine one.

**Why internal kernel subpackages must not be imported.** `docs/kernel-boundary-rules.md` and `docs/public-api.md` are explicit that `basis_core.evaluation`, `basis_core.policy.operation_aware.validation` (`validate_policy_bundle`), `basis_core.policy.operation_aware.applicability`, `.selector`, `.condition_eval`, `.aggregation`, and their result types are internal, carry no compatibility guarantee, and are reachable only by direct submodule import that this repository must not perform. Notably, **semantic `PolicyBundle` validation happens automatically inside `OperationAwareEvaluationEngine.evaluate()`** (invoked by `OperationAwareEnforcementPoint.evaluate()`) as the first orchestrated step — the gateway does not need to, and must not attempt to, call `validate_policy_bundle` itself. The gateway's own responsibility is limited to *structural* construction of a `PolicyBundle` (a plain Pydantic model — construction-time field/shape validation only) from whatever the gateway's policy-loading mechanism produces; semantic validation (duplicate rule IDs, invalid scope declarations, unsupported condition operators, etc.) is re-run by the kernel on every `evaluate()` call, deterministically, and its failure surfaces as `OperationAwareFailureReason.POLICY_VALIDATION_FAILURE` (or `INVALID_POLICY_BUNDLE`) on the response, not as a gateway-raised exception. §8a builds directly on this fact.

### 8a. Startup Semantic Preflight

Structural construction of a `PolicyBundle` (a Pydantic model) proves only that the loaded data is *shaped* correctly. It does not prove the bundle is *semantically* valid — duplicate rule identifiers, invalid scope declarations, and unsupported condition operators are all caught by the kernel's semantic validation, which (per §8, above) runs automatically as the first step of every `OperationAwareEvaluationEngine.evaluate()` call, **not** at `PolicyBundle` construction time. Without an explicit preflight step, this plan would otherwise permit exactly the failure mode the PR objective calls out:

```text
bundle structurally loaded
enforcement point initialized
/ready reports ready
every evaluation returns policy_validation_failure
```

This plan closes that gap using only the public surface in §8 — **no import of `basis_core.evaluation.*` or any internal validation function.**

**Preflight direction:**

1. At startup, after `PolicyBundle` structural construction and `OperationAwareEnforcementPoint` construction succeed, the gateway constructs one deterministic, synthetic `OperationAwareDecisionRequest` — fixed, gateway-owned values for every required field (e.g. a reserved `request_id`/`subject_id` such as `"basis-gateway:startup-preflight"`, a syntactically valid placeholder `action`), carrying no real caller data.
2. The gateway calls `OperationAwareEnforcementPoint.evaluate()` with that synthetic request, a distinctly namespaced `trace_id`/`evidence_id` (e.g. prefixed `preflight-`, so they can never collide with or be mistaken for a real request's evidence), and `recorded_at` set to the startup timestamp.
3. Because policy-bundle semantic validation is the unconditional first step of evaluation — it runs before candidate-rule selection, and therefore before anything about the *specific* synthetic request's field values matters — **any** completed result (`ALLOW`, explicit `DENY`, default deny, or `NOT_APPLICABLE`) proves the loaded bundle passed semantic validation, regardless of which particular outcome the synthetic request happened to produce. The gateway does not need the synthetic request to be policy-realistic; it needs the bundle to be validated, and validation is bundle-wide, not request-specific.
4. A result with `evaluation_status = failed` and `failure_reason` in `{invalid_policy_bundle, policy_validation_failure}` is treated as a **startup/readiness failure** — the bundle is structurally well-formed but semantically broken (duplicate rule IDs, unsupported operator, invalid scope, etc.), and the gateway must not proceed to readiness.
5. Any other failed result (`invalid_request`, `unsupported_schema_version`, `condition_evaluation_error`, `internal_evaluation_error`) from the *synthetic* preflight request is unexpected — the gateway constructed the synthetic request itself and controls its shape — and is treated conservatively as a startup failure as well, logged distinctly so it is not confused with a genuine policy-authoring defect.
6. The preflight's `OperationAwareEnforcementResult` (response, audit evidence, disposition) is **never** written to the operational gateway audit stream and is never returned to any caller. It is a startup diagnostic only, logged with an explicit `preflight: true` marker (or equivalent) so it cannot be confused with a real evaluation. See §13.

This section's recommendation should be refined if a later inspection of the public API surface reveals a better-supported preflight method (for example, if a future `basis-core` release publishes a dedicated bundle-validation entry point); until then, a single real `evaluate()` call against a synthetic request is the only public-surface-only mechanism available.

**Dependency version pinning.** `pyproject.toml` currently pins `basis-core>=0.1.0` with no upper bound. This plan recommends widening to `basis-core>=0.2.0,<0.3.0` as part of the dependency-adoption PR (§16, PR 2) — a minimum-version bump (since the operation-aware surface requires `v0.2.0`) paired with an upper bound at the next major/breaking increment, consistent with `basis-architecture`'s compatibility philosophy (`basis-core` version increments "affect every component in the distribution," and the bar for a breaking kernel change is correspondingly high — but an explicit upper bound is still the safer default for a dependency this load-bearing). This does not depend on unreleased `basis-core` behavior anywhere in this plan; every symbol cited above is confirmed present at the verified `v0.2.0` tag (§ Evidence, in the final report).

---

## 9. Kernel Outcome Versus Gateway Disposition

`basis-core` v0.2.0 already draws a structural distinction between evaluation status, semantic outcome, failure reason, and computed disposition: `OperationAwareEnforcementResult` carries `response.outcome` (`OperationAwareDecisionOutcome | None` — three values, `allow`/`deny`/`not_applicable`, plus `None` when evaluation failed), `response.evaluation_status` (`completed`/`failed`), `response.failure_reason` (six governed values, present only when `failed`), **and** `disposition` (`EnforcementDisposition` — two values, `allow`/`deny`, kernel-computed) as independent fields, per ADR-0006 Decision 7. This plan preserves **all four** as distinct facts, and additionally preserves the gateway's own HTTP classification as a fifth, separately-derived fact and the gateway's audit classification as a sixth — none of the six overwrites or redefines another:

```text
kernel evaluation status   (completed / failed)              — preserved verbatim
kernel semantic outcome    (allow / deny / not_applicable)   — preserved verbatim
kernel failure reason      (one of six, or absent)           — preserved verbatim
kernel-computed disposition (allow / deny)                   — preserved verbatim, never gateway-recomputed
gateway HTTP status        (this section's table)            — derived, distinct from disposition
gateway audit classification (§10)                            — derived, distinct from HTTP status
```

The kernel's own disposition rule (already implemented, not something this plan defines): `disposition = allow` only when `evaluation_status = completed` **and** `outcome = allow`. Every other reachable state — explicit `deny`, default deny (reported as `outcome = deny` with a `NO_ALLOW_RULE_MATCHED`-style reason code, not as a distinct outcome value), `not_applicable`, or any of the six governed failure categories — is `disposition = deny`. Disposition alone tells the gateway whether to *permit or block* the operation; it does not, and must not, determine the HTTP status by itself, because — per the PR objective — not every blocked, fail-closed result should be reported to the caller as `403 Forbidden`. A `403` implies "policy considered this and refused it"; a `500`/`503` implies "the gateway or kernel could not reach a trustworthy policy decision at all." Collapsing that distinction into a single disposition-to-HTTP mapping would misrepresent evaluation failures as substantive denials.

```text
kernel_outcome: not_applicable
gateway_disposition: deny            (kernel-computed, not gateway-recomputed)
gateway_http_status: 403             (execution behavior: block — §9's table below)
enforcement_reason: no_applicable_policy_bundle   (gateway-owned label for the audit surface;
                                                    not a new basis-core reason code)
```

The gateway must not silently transform `not_applicable` into `deny` **inside the kernel response or kernel evidence** — and because the kernel already returns both fields distinctly, the gateway does not need to perform that transformation at all; it only needs to avoid *discarding* `response.outcome` when it derives an HTTP status. This is a stricter, easier-to-satisfy version of the analogous v0.1 invariant `docs/audit-model.md` already documents today (`EvaluateResponse.outcome` reports `"not_applicable"` literally even though the HTTP status is `403`).

### Result-to-HTTP classification

Every non-allow result remains fail-closed (the gateway's execution behavior is always "block" unless the kernel's evaluation both completed and allowed), but "fail closed" is not synonymous with "`403`."

| Result | Evaluation status | Gateway execution behavior | Kernel-computed disposition | Gateway HTTP status |
|---|---|---|---|---:|
| Completed `ALLOW` | `completed` | permit | `allow` | `200` |
| Completed explicit `DENY` | `completed` | block | `deny` | `403` |
| Completed default deny | `completed` | block | `deny` | `403` |
| Completed `NOT_APPLICABLE` | `completed` | block | `deny` | `403` |
| `invalid_request` | `failed` | block | `deny` | `400` |
| `unsupported_schema_version` | `failed` | block | `deny` | `400` |
| `invalid_policy_bundle` | `failed` | block | `deny` | `503` |
| `policy_validation_failure` | `failed` | block | `deny` | `503` |
| `condition_evaluation_error` | `failed` | block | `deny` | `500` |
| `internal_evaluation_error` | `failed` | block | `deny` | `500` |
| Evaluator unavailable (kernel dependency not constructed at request time) | N/A — evaluation never invoked | block | N/A | `503` |

**`503` vs. `500` for `invalid_policy_bundle`/`policy_validation_failure`.** This plan chooses `503` for these two categories, not `500`, for a specific reason tied to §8a: the loaded `PolicyBundle` is immutable for the lifetime of the process (no dynamic reload exists in this repository, per §2.5), and §8a's startup semantic preflight already proves, before the service becomes ready, that the configured bundle passes semantic validation. If a *per-request* `evaluate()` call ever returns one of these two failure reasons despite a passing startup preflight, that is not an ordinary request-shaped problem — it indicates the service's policy dependency is not in the valid state the preflight certified (for example, memory corruption, a bundle-mutation bug, or some other integrity failure this plan cannot fully enumerate). `503 Service Unavailable` — "the service's policy dependency is not currently able to serve evaluations" — is the more honest classification than `500`, which this repository already reserves (§11) for a per-request, kernel-internal evaluation exception rather than a dependency-integrity problem. An occurrence of either failure reason after a passing preflight should also be treated as an operational anomaly worth alerting on, independent of the HTTP status returned to the caller — a future PR may choose to reactively degrade `/ready` when this occurs; this plan does not require that reactive behavior, only notes it as a natural extension.

**`500` for `condition_evaluation_error`/`internal_evaluation_error`.** These are per-request, evaluation-time failures — a specific condition's actual field values could not be evaluated, or an unexpected internal kernel error occurred for this specific call — independent of whether the bundle passed preflight. `500` is consistent with the existing v0.1 `_evaluation_failed_closed` convention in `routes.py` for "unexpected error during evaluation; request denied (fail-closed)."

No new kernel reason codes are invented by this plan. `enforcement_reason` values like `no_applicable_policy_bundle` in the example above are gateway-owned labels for the gateway's own enforcement-boundary audit fields (§10) — they describe the gateway's own audit classification, not a claim about what reason code the kernel emitted.

---

## 10. Evidence and Audit Composition

**Kernel `AuditEvidence`** (`basis_core.audit.AuditEvidence`) is produced by `OperationAwareEnforcementPoint.evaluate()` on every reachable path except the internal-error fallback, and is never persisted by `basis-core` itself — the gateway receives it as a returned value and is responsible for what happens to it next, exactly as `docs/architecture/operation-aware-trace-audit-evidence.md` §14 assigns: "`basis-core` produces the kernel-side evidence that becomes part of an audit event, but it does not persist that evidence anywhere durable."

**This has a direct consequence for how the gateway records evidence, which an earlier draft of this plan got wrong.** A `GatewayAuditEvent` that carries only a *reference* to `AuditEvidence` (e.g. `AuditEvidence.evidence_id`) is not sufficient on its own, because nothing in `basis-core` or this plan durably persists the artifact that `evidence_id` would refer to. A reference to nothing is not evidence — it is a dangling pointer that looks like evidence.

> **The gateway must never write only an `evidence_id` pointing to an `AuditEvidence` artifact that was not itself persisted.**

**Recommended initial strategy:**

> **Embed the complete, bounded, redaction-governed `AuditEvidence` artifact alongside the gateway's own operation-aware `GatewayAuditEvent`, in the same durable record.**

> **Implementation note (PR 10 correction):** the shipped implementation
> (`basis_gateway.audit.operation_aware_gateway_events`) places `gateway_audit_event` and
> `audit_evidence` as **sibling keys** inside the outer durable `AuditEvent.detail` payload — the
> complete `AuditEvidence` is never nested *inside* the `GatewayAuditEvent` contract itself.
> `GatewayAuditEvent` instead carries a reference field, `audit_evidence_id`, and the invariant
> `gateway_audit_event.audit_evidence_id == audit_evidence.evidence_id` links the two sibling
> artifacts within one record. This satisfies the same "never write a dangling reference" rule
> this section establishes — the referenced artifact is always present in the same record — while
> keeping the two artifacts' ownership visibly distinct. See
> [`docs/audit-model.md`](../audit-model.md) §10 for the authoritative current-state description.

This is the recommended first implementation because:

- The artifact is already bounded (`basis-core`'s own audit-evidence model is deliberately size- and content-constrained, per `docs/architecture/operation-aware-trace-audit-evidence.md`).
- The artifact is already governed for redaction — the kernel does not place secrets or raw credentials into it, so embedding it does not introduce a new redaction obligation the gateway has to invent.
- The gateway already owns persistence (`GatewayAuditWriter` → `LogAuditWriter` today) — there is no new durability mechanism to build; embedding means the existing write path already makes the kernel evidence durable, for free.
- The audit event remains independently understandable — a single record contains everything needed to reconstruct the decision, without a second lookup.
- No second audit-record lookup, correlation model, or cross-record transaction is required — the two-writes problem (kernel evidence durably written, gateway event durably written, and what happens if only one succeeds) does not arise, because there is exactly one write.

**A separate, durable kernel-evidence store plus a lightweight reference remains a legitimate future option**, but only once it is designed to also solve the problems embedding avoids for free:

- Evidence persistence (where the referenced artifact actually lives)
- Retrievability (how a caller/auditor resolves the reference back to the artifact)
- Correlation guarantees (that the reference and the artifact it points to can never drift apart)
- Failure handling when one of the two records writes successfully and the other does not

This plan does not design that future option. It states only that adopting it later must not regress the "never write a dangling reference" rule above during any transition.

**Gateway-owned enforcement-boundary evidence** — this plan's conceptual `GatewayAuditEvent` model, combining the kernel's embedded `AuditEvidence` with gateway-owned facts this repository already knows how to produce for the v0.1 path and can reuse:

- Authenticated subject source (which `AuthMode` verified this request — already known via `config.auth_mode`)
- Token issuer (already available from `IdentityContext.claims`/`iss`, unused today for audit purposes but present)
- Operation-producer trust classification for this request (§5a/§7 — new; not present in the v0.1 audit model at all)
- Gateway instance/enforcement-point identity (new — not currently emitted anywhere in this repository; scoped to a later PR, not required for a minimal integration)
- Request source (route: `/v1/evaluate/operation-aware` or whatever §12 settles on)
- Correlation ID (`CorrelationMiddleware`, reused)
- Received/completion timestamps and latency (new — `audit/gateway_events.py` does not currently record timing; this plan does not require it for a minimal integration but notes it as a natural gateway-owned addition since the kernel structurally cannot know it)
- Caller identity (from the verified `Subject`, reused)
- Context provenance (per §5's classification table — which fields were trusted-producer-asserted vs. gateway-derived for *this* request, and whether producer-trust classification was positive or negative)
- Gateway disposition (`EnforcementDisposition`, preserved from the kernel result, per §9)
- HTTP result (status code actually returned, per §9's classification table)
- Integration failure, if one occurred (§11)
- Redaction decisions (reusing the existing "raw token never in audit" invariant `audit/gateway_events.py` already documents and enforces)

This plan does **not** freeze a new shared schema for `GatewayAuditEvent`. Consistent with `docs/architecture/operation-aware-trace-audit-evidence.md` (which itself defers "final audit event schema" to later work) and with how this repository's own `audit/gateway_events.py` currently represents gateway-level facts as an `AuditEvent` with `event_type: SYSTEM_EVENT` and a structured `detail` dict rather than a bespoke Pydantic model, the recommended initial approach — to be finalized in the PR that implements it (§16, PR 7) — is to extend the existing `emit_gateway_event()` pattern with an operation-aware-specific action vocabulary (e.g. `gateway.operation_aware_evaluation_requested`, `gateway.operation_aware_evaluation_completed`) and a `detail` payload that embeds the kernel's full `AuditEvidence` (serialized), rather than introducing a new top-level audit model in this repository ahead of any `basis-schemas` contract for one.

**What the gateway must not do**, restated against this repository's existing invariants (all already true of `/v1/evaluate` and extended unchanged to the operation-aware path):

- Rewrite `response.outcome` — never present a `not_applicable` result as a stored/returned `deny` outcome (§9).
- Invent `matched_rule_ids` — the gateway only ever forwards what `AuditEvidence.matched_rule_ids` already contains.
- Alter `response.explanation`/`reason_code` — passed through verbatim or omitted; never gateway-synthesized prose (consistent with `basis-architecture`'s evidence-provenance clarification, which explicitly forbids synthesizing top-level explanation text nobody produced).
- Convert `not_applicable` into an explicit policy denial in evidence — only the HTTP status collapses; the evidence does not.
- Claim trusted-producer-asserted context (§5) was gateway-verified — the gateway's own audit fields must record the provenance classification, not silently upgrade a producer assertion to "verified."
- Claim an untrusted caller's rejected producer-context assertion was ever evaluated — a rejected request (§5a, §7) produces no `AuditEvidence` at all, because the kernel was never invoked; the gateway-level audit event records the rejection, not a fabricated evaluation.
- Place raw tokens or secrets into audit records — reuses the existing, already-enforced invariant in `audit/gateway_events.py` and `auth/*`.
- Write an `AuditEvidence` reference without the corresponding artifact durably present in the same record — this section's central rule.

---

## 11. Failure Model

| Category | Kernel evaluation occurs? | Disposition | HTTP | Audit | Readiness impact | Safe to expose to caller? |
|---|---|---|---|---|---|---|
| Authentication failure (missing/invalid token, unmappable subject) | No | N/A | `401` | Gateway event (reuses `AUTHENTICATION_FAILED`) | None | Yes — sanitized message, reused from v0.1 |
| Normalized-input shape-validation failure (`OperationAwareDecisionRequest` construction `ValidationError`, invalid `operation_intent`, unrecognized field including `expected_policy_version`) | No | N/A | `400` | Gateway event (new `VALIDATION_FAILED`-style action) | None | Yes — Pydantic error detail is safe (no secrets), reused pattern from `/v1/evaluate` |
| Gateway-owned-fact spoofing (caller asserted a gateway-owned field, per §6) | No | N/A | `400` | Gateway event | None | Yes |
| Producer-context spoofing (non-producer-classified caller asserted a trusted-producer-only field, per §5a/§7) | No | N/A | `400` | Gateway event (new, distinct reason from generic validation failure, so the two are distinguishable in audit) | None | Yes — the rejection reason itself is safe to state; it does not reveal *how* producer trust is classified beyond "this caller is not a classified operation producer" |
| Action-composition failure | No | N/A | `400` | Gateway event (reuses existing `compose_action` error path) | None | Yes |
| Resource-composition failure | No | N/A | `400` | Gateway event (reuses existing `compose_resource_id` error path) | None | Yes |
| Policy-bundle structural loading failure (startup: `PolicyBundle` construction failure) | N/A (startup, not request-time) | N/A | N/A (`/ready` returns `503`; the operation-aware endpoint returns `503` for the lifetime of the degraded state) | Startup log; readiness reason string | `operation_aware_bundle_loaded` (new component) not-ready | Yes — sanitized construction error, mirrors `policy/loader.py`'s `PolicyLoadError` pattern |
| Policy-bundle semantic preflight failure (startup: §8a preflight returns `invalid_policy_bundle`/`policy_validation_failure`, or any other unexpected failure reason) | Yes, exactly once, at startup, against a synthetic request | N/A | N/A (`/ready` returns `503`; the operation-aware endpoint returns `503` for the lifetime of the degraded state) | Startup log only — the preflight's own result is never written to the operational audit stream (§8a) | New `operation_aware_policy_semantically_valid` component not-ready | Yes — the governed failure reason from the preflight is safe to log/report; no request content is involved since the request is synthetic |
| Kernel dependency unavailable (`OperationAwareEnforcementPoint` not constructed, or preflight never completed, at request time) | No | N/A | `503` | Gateway event (new, parallel to `EVALUATOR_UNAVAILABLE`) | Reflects existing not-ready state | Yes |
| Governed evaluator failure, per-request (`invalid_request`/`unsupported_schema_version`) | **Yes** — `evaluate()` ran and returned a structured result | `EnforcementDisposition.DENY` (kernel-computed) | `400` (§9) | `AuditEvidence` present (embedded, §10), `failure_reason` set | None | Yes — `failure_reason` is a closed, governed vocabulary value, safe by design |
| Governed evaluator failure, per-request (`invalid_policy_bundle`/`policy_validation_failure` despite a passing startup preflight) | **Yes** | `EnforcementDisposition.DENY` (kernel-computed) | `503` (§9 — treated as a dependency-integrity anomaly, not a routine request outcome) | `AuditEvidence` present (embedded, §10), `failure_reason` set; also logged as an operational anomaly per §9 | None automatically; worth alerting on operationally | Yes |
| Governed evaluator failure, per-request (`condition_evaluation_error`/`internal_evaluation_error`) | **Yes** | `EnforcementDisposition.DENY` (kernel-computed) | `500` (§9) | `AuditEvidence` present (embedded, §10), `failure_reason` set | None | Yes — `failure_reason` is a closed, governed vocabulary value, safe by design |
| Unexpected exception from `evaluate()` itself (should not occur per §8, defended against anyway) | Ambiguous — treat as "no trustworthy result produced" | N/A | `500` | Gateway event (new `EVALUATION_FAILED_CLOSED`-style action, reusing the existing v0.1 pattern for this exact scenario) | None | Yes — generic message only, no exception text, reusing the existing `_evaluation_failed_closed` pattern in `routes.py` |
| Audit-emission failure (`GatewayAuditEvent` write failure) | Yes (decision already returned) | Unaffected — decision stands | Unaffected | Failure logged; decision not reversed; because `AuditEvidence` is embedded (§10) rather than referenced, a failed gateway write loses the kernel evidence too — there is no partial-success state to reconcile, which is itself a benefit of the embedding strategy | Reuses existing `GatewayAuditWriter` consecutive-failure escalation (`AUDIT_FAILURE_THRESHOLD`) and, if configured, `AUDIT_FAIL_CLOSED` behavior — no new mechanism | N/A (the failure itself is never exposed as an error to a caller whose request otherwise succeeded) |

All ambiguous or unexpected failures fail closed, consistent with every existing failure path in this repository. No category above is collapsed into another: a governed kernel evaluation failure (kernel ran, returned a structured deny) is deliberately kept distinct in this table from a gateway integration failure (kernel never ran, or ran and produced no trustworthy result), because the two have different audit representations (`AuditEvidence` present vs. absent) and different operational meanings (a policy-authoring or per-request problem vs. a gateway/kernel-dependency problem) — and, per §9, the three governed-failure rows are themselves kept distinct from one another by HTTP status, because collapsing them would misrepresent a dependency-integrity anomaly or an internal evaluation error as an ordinary `403` policy decision.

---

## 12. Compatibility Strategy

**Recommendation: Option A — a new endpoint**, e.g. `POST /v1/evaluate/operation-aware`, gated behind a configuration flag (e.g. `OPERATION_AWARE_ENABLED`, defaulting to `false`) analogous to how `evaluation_enabled` already gates the existing `/v1/evaluate` path in `config.py`. Nothing in this focused correction pass changes this recommendation — the subject/producer distinction (§4, §5a), the semantic preflight (§8a), the embedded-evidence strategy (§10), the refined outcome/HTTP classification (§9), and the removal of `expected_policy_version` (§5b) are all naturally scoped to a new, additive endpoint and do not surface any reason a discriminated variant of `EvaluateRequest` would have been preferable.

**Why Option A over Option B (discriminated request on the existing endpoint).** `EvaluateRequest`/`EvaluateResponse` and `OperationAwareDecisionRequest`/`OperationAwareDecisionResponse` are not two versions of the same shape — they diverge in required fields (`EvaluateRequest.action` always required and always a plain string; the operation-aware request's identity/outcome/failure-reason vocabulary has no v0.1 analogue at all), in response semantics (`EvaluateResponse.outcome` is a bare string with no `evaluation_status`/`failure_reason` distinction; the operation-aware response distinguishes `completed`/`failed` explicitly), and in HTTP status conventions this plan does not want to entangle (§9's table has materially more rows and more distinct status codes than the existing three-outcome mapping in `docs/audit-model.md` §5). A discriminated union on one endpoint would require either a runtime-detected shape (fragile, and exactly the kind of caller-observable ambiguity `EvaluateRequest.reject_caller_supplied_subject`-style strictness is designed to avoid) or an explicit `"api_version"` field inside the body (workable, but functionally identical to a separate route with strictly more implementation complexity for no compatibility benefit). `docs/architecture/basis-gateway.md` itself lists `POST /v1/batch/evaluate` as an example of how the `/v1/` prefix already anticipates additional endpoints under the same version, not exclusively variants of one endpoint's body.

**Why not Option C (internal service, deferred public endpoint).** This repository does not have an existing "internal service, no public endpoint" pattern to extend, and deferring the public endpoint would not reduce implementation risk meaningfully — the composition, kernel-integration, and audit work (§16, PRs 3–7) is identical whether or not a route exists at the end of it; withholding the route only delays the conformance testing (§16, PR 9) that most needs a real HTTP path to be meaningful. Option C is rejected as adding a deferred-decision cost without a corresponding risk reduction, given that the new endpoint is opt-in via configuration flag regardless.

**Protecting existing surfaces:**

- `GET /health` — untouched; no dependency on anything in this plan.
- `GET /ready` — untouched for existing components; new components (§13) are additive and only registered when `OPERATION_AWARE_ENABLED=true`, so a deployment that does not enable the feature sees no readiness behavior change at all (mirrors the existing pattern where `basis_local_token_configured` never registers in OIDC mode and vice versa).
- Existing authentication behavior — fully reused, not modified (§7).
- Existing `POST /v1/evaluate` — byte-for-byte unchanged. No shared route, no shared request/response model, no shared code path beyond the authentication and composition modules that are reused (not modified) by both.
- Existing audit behavior — `audit/gateway_events.py`'s existing action vocabulary, reason vocabulary, and emission call sites are untouched; new operation-aware gateway events are additive constants in the same module or a new sibling module, never a redefinition of an existing constant.
- Existing policy loading — `policy/loader.py` and `POLICY_PATH` are untouched; operation-aware `PolicyBundle` loading is new, separately configured (a distinct env var, e.g. `OPERATION_AWARE_POLICY_BUNDLE_PATH`, to be finalized in §16 PR 5), and does not replace or share a code path with the existing loader.
- Existing users of `basis-gateway` v0.1.0 — a deployment that does not set `OPERATION_AWARE_ENABLED=true` (or does not upgrade past the release that introduces it) observes zero behavior change from this integration.

This plan explicitly avoids silently changing the meaning of the existing evaluation endpoint: nothing in §16's PR sequence modifies `routes.py`'s existing `evaluate()` handler, `EvaluateRequest`, or `EvaluateResponse`.

---

## 13. Readiness and Diagnostics

New readiness components, registered **only** when `OPERATION_AWARE_ENABLED=true` (mirroring the existing auth-mode-conditional registration pattern in `main.py`):

- `operation_aware_mode_enabled` — informational; true whenever the feature flag is set, independent of whether the rest of startup succeeds. (Optional — may be folded into the absence/presence of the other components below rather than tracked as its own boolean; left as an implementation decision for §16 PR 8.)
- `operation_aware_bundle_loaded` — the structural `PolicyBundle` construction step (§8) succeeded.
- `operation_aware_evaluator_initialized` — `OperationAwareEnforcementPoint` was constructed from the loaded bundle and a fresh `OperationAwareEvaluationEngine()`.
- `operation_aware_policy_semantically_valid` — **new (§8a)** — the startup semantic preflight completed with a governed, non-`invalid_policy_bundle`/`policy_validation_failure`/other-unexpected-failure result. This component is what prevents the exact failure mode named in the PR objective: a bundle can be structurally loaded and the evaluator can be constructed while the bundle is still semantically broken, so `/ready` must not report ready on `operation_aware_bundle_loaded` and `operation_aware_evaluator_initialized` alone — this fourth component is required, registered, and gates readiness independently.

**Readiness must distinguish**, per the PR objective:

- **Required dependency failure** — any of the four components above false while the feature is enabled: `/ready` returns `503`, exactly as `policy_loaded`/`evaluator_initialized` already do for the v0.1 path.
- **Optional context unavailable** — this plan introduces **no readiness component for safety/risk/environment/location/device context availability**, because none of those categories has a "provider" the gateway connects to in this plan's scope; they are per-request, operation-producer-supplied fields, not a service dependency. Per the PR objective, the gateway must not claim readiness for safety or risk context merely because the request model supports those fields — and the corollary this plan draws is that it also must not report *unreadiness* for them, since there is no such dependency to be unready. If a future phase introduces an actual context *provider* (e.g., a risk-scoring service the gateway calls), that provider's readiness would be tracked the same way JWKS availability is today — but no such provider exists in this plan's scope. The operation-producer trust-classification mechanism itself (§5a) is configuration, not a runtime dependency, so it also has no readiness component of its own — a misconfiguration there surfaces as every producer-context request being rejected, not as `/ready` returning `503`.
- **Feature disabled** — when `OPERATION_AWARE_ENABLED` is unset or `false`, none of the four components above are registered at all, so they cannot block `/ready` (identical mechanism to how `basis_local_token_configured` never registers in OIDC mode today).
- **Feature configured and ready** — all four registered operation-aware components true, including the semantic preflight.

---

## 14. Security Considerations

Grounded in `basis-architecture`'s threat model (`docs/security/threat-model.md`), particularly §3.2 (Gateway → Core), §6.2 (`basis-gateway` threats), and the "Next Gateway Boundary" section of `ROADMAP.md`.

- **Context spoofing** — the dominant new risk this plan introduces, because the operation-aware request surface is materially larger than `EvaluateRequest`. Mitigated by §5's provenance table, §5a's subject/producer distinction, and §6's explicit rejection lists; every policy-decisive field that is not cryptographically verified is, at minimum, classified as trusted-producer-asserted only when the caller has been explicitly classified as a producer, and untrusted-caller-asserted (and rejected) otherwise — never silently treated as trustworthy, consistent with the threat model's framing of the Adapter → Gateway boundary as a *semantic* trust boundary the gateway cannot verify at runtime (§6.3 of the threat model). The gateway's contribution is honest classification and rejection of the unclassified case, not verification it cannot perform.
- **Operation-producer identity spoofing, distinct from authorization-subject spoofing** — new risk category this plan introduces by name (§5a), because an ordinary authenticated caller and a genuine operation producer are not the same trust class even though both authenticate through the identical Bearer-token path today. Mitigated by §5a's rule that producer trust is derived from gateway configuration checked against the verified subject, never self-asserted by the caller, and by the default-deny posture (no configured producer-trust mechanism ⇒ no caller is ever classified as a producer ⇒ every producer-context field is rejected).
- **Forged operation intent** — bounded to the closed `OperationIntent` vocabulary (§7) and to callers classified as trusted producers (§5a); an invalid value is rejected before it can reach a policy condition, and a valid-but-producer-asserted value is never promoted to "verified" in gateway evidence (§10).
- **Forged device class / forged location** — no gateway-side verification exists or is claimed; both remain trusted-producer-asserted (never accepted from an unclassified caller) per §5/§5a, with the missing-context-is-safer-than-fabricated-context principle as the structural mitigation for a compromised or misconfigured producer.
- **Untrusted protocol evidence** — carried as evidence only, never interpreted by the kernel (protocol-agnostic boundary, unchanged); the gateway does not add protocol-parsing logic anywhere in this plan.
- **Caller attempts to set subject or roles** — rejected identically to the existing `/v1/evaluate` path, reusing the proven `reject_caller_supplied_subject` pattern (§6).
- **Caller attempts to set evaluation time** — rejected; always gateway-generated (§5, §7). This is a **new** risk relative to v0.1, since `DecisionRequest.timestamp` has always been gateway-generated with no analogous caller-facing field to reject in the v0.1 request model; the operation-aware model does expose `evaluation_time` as a request field, which is why explicit rejection logic (not just "we happen not to read a caller value") is required.
- **Caller attempts to assert a policy version** — this risk category is eliminated outright, not merely mitigated, by §5b's decision to omit `expected_policy_version` from the accepted input surface entirely in this rollout. There is no field to misuse.
- **Audit-evidence tampering** — bounded by the same "audit write failure does not alter authorization decisions" invariant already enforced for v0.1 (`docs/audit-model.md` §6), reused unchanged (§11). Embedding `AuditEvidence` in full (§10) rather than referencing it also removes a tampering surface a reference-based design would have introduced (a reference can be repointed or left dangling; an embedded artifact travels with the record that vouches for it).
- **Kernel-response reinterpretation** — the central risk §9 and §10 exist to close: the gateway must not recompute, rewrite, or collapse kernel-produced evaluation status, outcome, failure reason, or disposition beyond the documented, independent HTTP-status derivation.
- **Bypass paths** — no new path to `basis-core` is introduced; `OperationAwareEnforcementPoint` is invoked exclusively from the same trust boundary (`basis-gateway`'s process) as `EnforcementPoint` is today. This plan does not add a second network-facing component or a direct-to-kernel path for any caller class.
- **Enforcement consistency** — `EnforcementDisposition` is kernel-computed and gateway-preserved (§9), which structurally removes the risk category `docs/security/threat-model.md` §6.2 names as "enforcement behavior subverted so a DENY is not applied" for the *disposition* determination itself (the gateway still owns the HTTP-classification step, which remains a place discipline is required, per §9's table).
- **Redaction** — reuses the existing "no raw tokens/secrets in audit" invariant; extends it to the larger, now-embedded operation-aware evidence surface (safety/risk/environment context in particular, which may carry operationally sensitive detail even if not classically "secret") per §10.
- **Fail-closed behavior** — every new failure category in §11 fails closed, consistent with every existing failure category in this repository.
- **Backward compatibility as a security concern** — an unintentional behavior change to the existing `/v1/evaluate` endpoint would itself be a security regression (a deployment's existing policy assumptions silently evaluating differently). §12's compatibility strategy is written to make that structurally unlikely (separate route, separate models, separate feature flag, no shared mutable state).

---

## 15. Explicit Non-Goals

This integration phase does not include:

- New condition operators (the ten-operator registry in `basis-architecture`'s `condition-operator-semantics.md` is already implemented by `basis-core` v0.2.0; nothing in this plan adds an eleventh)
- Timestamp comparison semantics beyond what the existing operator registry already provides
- Array membership operators beyond `in`/`not_in`, already implemented in the kernel
- Selecting or implementing a final operation-producer trust *transport* mechanism (mTLS, client-credentials grant, signed adapter evidence, registered machine-client identity — §5a names these as future options; this PR recommends only a configuration-driven classification layered on the existing authentication transport, and does not commit to any of the stronger mechanisms)
- `expected_policy_version` acceptance or mismatch-comparison behavior of any kind (§5b — the field is omitted from the accepted input surface entirely, not accepted-and-unenforced)
- Policy authoring
- Policy editing
- Dynamic policy reload
- Policy synchronization
- Policy distribution
- Policy signing
- Policy databases
- Relationship-based authorization
- Multi-tenant authorization
- Topology discovery
- Active OT scanning
- Automated risk scoring (the gateway never computes `risk_context`; it only ever passes through what a classified operation producer asserts)
- AI policy generation
- `basis-console` work
- `basis-adapters` implementation
- Kubernetes
- Service mesh
- Fleet management
- Commercial BASAuth functionality
- A finalized `GatewayAuditEvent` schema (§10 describes a conceptual model and a recommended minimal implementation approach — embed, don't reference — without freezing a schema)
- A durable, separately-addressable kernel-evidence store with reference-based audit records (§10 names this as a legitimate future option, not implemented here)

If real gateway work during implementation demonstrates a requirement for a new condition operator or a timestamp/membership semantic the current registry does not cover, that requirement should be raised as a `basis-architecture` clarification, not implemented informally inside `basis-gateway`, per `docs/architecture/condition-operator-semantics.md`'s own framing of its scope. Similarly, if real integration needs demonstrate that the configuration-driven producer-trust classification recommended in §5a is insufficient for a deployment's threat model, adopting a stronger transport mechanism should be scoped as its own follow-on architecture decision, not folded informally into this sequence.

---

## 16. Proposed Implementation Sequence

Each PR is scoped to be reviewable independently and to leave the repository in a fully working, fully tested state at every step. This sequence has eleven PRs — one fewer than an earlier draft, which included a dedicated outcome/disposition test-hardening PR that duplicated the conformance work the final conformance PR already covers; that PR's scope has been folded into PR 6's completion criteria and PR 9's conformance suite (see PR 6 and PR 9 below).

### PR 1 — Integration plan and success criteria
*(this document)*
- **Objective**: establish architectural boundaries, context provenance, request composition, kernel integration surface, outcome/disposition separation, evidence composition, compatibility strategy, and PR sequence before implementation begins.
- **Dependencies**: none.
- **Files/areas**: `docs/implementation/operation-aware-gateway-integration-plan.md`, minimal `README.md` navigation update.
- **Architectural boundaries**: documentation only; no runtime code.
- **Required tests**: none (no runtime change); existing test suite and quality gates must pass unmodified, proving no accidental change.
- **Non-goals**: everything in §15.
- **Completion criteria**: this document merged; roadmap/navigation updated; existing gates green.

### PR 2 — Dependency and public-contract adoption
- **Objective**: bump `pyproject.toml`'s `basis-core` constraint to `>=0.2.0,<0.3.0`; add a smoke-level import test confirming every symbol listed in §8 is importable from its documented path at the installed version.
- **Dependencies**: PR 1.
- **Files/areas**: `pyproject.toml`, a new `tests/test_operation_aware_public_api_contract.py` (or similar) that imports and asserts presence of the §8 symbol set — no behavioral test yet.
- **Architectural boundaries**: no new gateway logic; no route changes; no config changes.
- **Required tests**: import-only contract test; full existing suite passes unchanged (proves the version bump is non-breaking for v0.1 behavior).
- **Non-goals**: any use of the newly available symbols.
- **Completion criteria**: `basis-core==0.2.0` installed and pinned; existing tests green; new import-contract test green.

### PR 3 — Normalized operation input model
- **Objective**: define the new Pydantic request model (§6) for operation-aware input — shape-layer validation only, in isolation, not yet wired to a route, to producer-trust classification, or to kernel construction.
- **Dependencies**: PR 2.
- **Files/areas**: new `src/basis_gateway/api/operation_aware_schemas.py` (or extends `api/schemas.py`); reuses `core/actions.py`/`core/resources.py` validation helpers.
- **Architectural boundaries**: reuses, does not fork, the existing composition boundary; rejects gateway-owned fields per §6; `extra="forbid"`-style strictness so `expected_policy_version` (and any other undefined field) is rejected at this layer (§5b); no route registration yet; no producer-trust logic (that is layer 2, PR 4).
- **Required tests**: unit tests for every rejection case in §6's enumeration; a specific test that supplying `expected_policy_version` is rejected as an unrecognized field; unit tests confirming optional-field absence is preserved as `None`, not defaulted.
- **Non-goals**: kernel integration, HTTP route, audit, producer-trust classification.
- **Completion criteria**: model fully unit-tested in isolation; not reachable from any endpoint.

### PR 4 — Operation-producer trust classification, context composition, and provenance
- **Objective**: implement (a) the operation-producer trust classification step (§5a) — a configuration-driven check of the already-authenticated subject, recommended as a first cut but not fixed by this plan — and (b) the composition step that turns validated normalized input + verified identity + producer-trust classification into the values that will populate `OperationAwareDecisionRequest`, applying §5's provenance table and rejecting producer-only fields from non-producer callers.
- **Dependencies**: PR 3.
- **Files/areas**: new `src/basis_gateway/core/operation_aware_composition.py`; new `src/basis_gateway/auth/operation_producer.py` (or folded into the composition module — left to implementation) for the trust-classification step; `config.py` additions for the producer-trust configuration surface; reuses `auth/subject_mapper.py` output and `core/actions.py`/`core/resources.py` composition functions.
- **Architectural boundaries**: no kernel invocation yet; produces the composed *inputs* to `OperationAwareDecisionRequest` construction, not the construction call itself (kept separate so composition logic is testable without a live `PolicyBundle`); producer-trust classification never trusts a caller-supplied claim of producer status (§5a, §6).
- **Required tests**: table-driven tests covering every row of §5 (verified vs. trusted-producer-asserted vs. gateway-derived vs. untrusted-caller-asserted vs. configuration-derived vs. unavailable); tests confirming `evaluation_time` is always gateway-generated and never caller-influenced; tests confirming safety/risk/environment context is never defaulted; **tests proving an ordinary authenticated caller cannot assert producer-only context (rejected, 400)**; **tests proving a classified operation producer cannot assert gateway-owned identity facts (subject/roles/evaluation_time/etc. — still rejected, per §6)**; **tests proving operation-producer identity and authorization-subject identity remain distinct facts in the composed request and in test fixtures**; **tests proving untrusted context is never silently promoted to trusted context** (an unclassified caller's producer-context fields are rejected outright, never accepted-and-downgraded-in-label).
- **Non-goals**: `PolicyBundle` loading, `OperationAwareEnforcementPoint` construction, selecting a final producer-trust transport mechanism beyond the recommended configuration-driven classification (§15).
- **Completion criteria**: composition and producer-trust logic fully covered by the provenance and producer-trust test matrices; still not reachable from any endpoint.

### PR 5 — Kernel enforcement-point integration and semantic preflight
- **Objective**: implement structural `PolicyBundle` loading (parallel to, not shared with, `policy/loader.py`), construct `OperationAwareEnforcementPoint` at startup, gated by `OPERATION_AWARE_ENABLED`, and implement the startup semantic preflight (§8a) using only the public kernel surface.
- **Dependencies**: PR 4.
- **Files/areas**: new `src/basis_gateway/policy/operation_aware_loader.py`; new `src/basis_gateway/core/operation_aware_evaluator.py` (wraps `OperationAwareEnforcementPoint`, generates `trace_id`/`evidence_id`/`recorded_at` per call, per §8); new preflight logic (§8a) invoked once during `main.py` lifespan startup; `config.py` additions (`operation_aware_enabled`, `operation_aware_policy_bundle_path`); `main.py` lifespan additions.
- **Architectural boundaries**: no route yet; no import of `basis_core.evaluation.*` internals (§8); relies on the kernel's own semantic validation inside `evaluate()`, does not call `validate_policy_bundle` directly; the preflight uses only `OperationAwareEnforcementPoint`/`OperationAwareDecisionRequest`, never an internal module.
- **Required tests**: startup success/failure tests for structural bundle loading; **startup tests for a structurally invalid bundle** (fails before preflight is even reached); **startup tests for a structurally valid but semantically invalid bundle** (duplicate rule IDs, invalid scope — preflight fails, startup fails); **startup tests for a bundle containing an unsupported condition operator** (preflight fails, startup fails); **startup tests for duplicate or otherwise invalid rules**; **startup tests for a semantically valid bundle that produces a completed, non-`ALLOW` preflight result** (preflight succeeds — a non-allow outcome from the synthetic request is not a failure, per §8a); construction tests for the enforcement-point wrapper; tests confirming `trace_id`/`evidence_id`/`recorded_at` are generated fresh per call, never reused across requests; a test confirming the preflight's own evidence is never written to the operational audit stream.
- **Non-goals**: HTTP route, audit event emission for real requests.
- **Completion criteria**: enforcement-point wrapper and preflight fully unit-tested against a real `OperationAwareEnforcementPoint` (not a mock of the kernel), still not reachable via HTTP.

### PR 6 — Operation-aware evaluation endpoint
- **Objective**: wire PRs 3–5 together behind `POST /v1/evaluate/operation-aware` (or the finalized route name), following the same authentication → producer-trust classification → validation → composition → invocation → response-classification sequence this plan establishes, and — folding in the scope an earlier draft assigned to a separate hardening PR — verify the five canonical `basis-schemas` compatibility scenarios (`allow-basic`, `deny-precedence`, `default-deny`, `not-applicable`, `invalid-policy-bundle`) against the real gateway-to-kernel path as part of this PR's own completion criteria.
- **Dependencies**: PR 5.
- **Files/areas**: `api/routes.py` (new handler, new route registration; existing `/v1/evaluate` handler untouched); `main.py` (route inclusion, feature-flag gating).
- **Architectural boundaries**: §9's result-to-HTTP classification table implemented exactly, including the `400`/`503`/`500` split across governed failure categories; §11's failure model implemented exactly; existing `/v1/evaluate` behavior byte-for-byte unchanged (verified by the existing test suite passing unmodified).
- **Required tests**: full request-lifecycle tests for every row of §9's classification table and §11's failure model; the five canonical scenario shapes (`allow-basic`, `deny-precedence`, `default-deny`, `not-applicable`, `invalid-policy-bundle`) run end to end through the real endpoint; a regression run of the complete existing `/v1/evaluate` test suite with zero changes required.
- **Non-goals**: readiness (PR 8), full audit assembly (PR 7) — a minimal audit emission may be stubbed here and completed in PR 7, or PR 6 and PR 7 may be combined if review finds the split artificial; sequencing is not binding if a later PR demonstrates a cleaner boundary. The broader adversarial security suite beyond the five canonical scenarios remains in PR 9.
- **Completion criteria**: new endpoint fully reachable and functional behind the feature flag; existing endpoint provably unaffected; all five canonical scenarios pass through the real path with the exact HTTP/disposition/evidence combination §9 specifies.

### PR 7 — Gateway audit-event assembly
- **Objective**: implement the conceptual `GatewayAuditEvent` composition from §10 — extends `audit/gateway_events.py`'s pattern with an operation-aware action vocabulary and a `detail` payload that **embeds** the kernel's full `AuditEvidence` (§10's central rule — never a dangling `evidence_id` reference).
- **Dependencies**: PR 6.
- **Files/areas**: `audit/gateway_events.py` (additive constants only) or a new sibling module; `api/routes.py` (emission call sites in the new handler).
- **Architectural boundaries**: reuses `GatewayAuditWriter`; no new schema frozen (§10); existing v0.1 gateway events untouched.
- **Required tests**: tests confirming every §10 "must not" bullet (no outcome rewriting, no invented matched rules, no raw tokens, no dangling evidence references, etc.); **tests proving the durable gateway record contains, or the record itself directly carries, all of: kernel outcome, evaluation status, failure reason, policy bundle identity, matched-rule evidence, trace information allowed by the configured evidence tier, evidence ID, gateway disposition, correlation ID, and context provenance** — i.e., that nothing in this list requires a second, unresolvable lookup to reconstruct.
- **Non-goals**: durable audit storage beyond what `GatewayAuditWriter` already provides, SIEM integration, a separate kernel-evidence store (§10, §15).
- **Completion criteria**: every evaluation through the new endpoint produces a gateway-level audit record that embeds the kernel's evidence and combines it with gateway facts, matching §10 exactly, and the record is independently reconstructable without any second lookup.

### PR 8 — Readiness and diagnostics
- **Objective**: implement §13's four readiness components, feature-flag-gated, including the new `operation_aware_policy_semantically_valid` component tied to PR 5's preflight.
- **Dependencies**: PR 5 (bundle/evaluator construction and preflight to report on).
- **Files/areas**: `readiness.py` usage in `main.py`'s lifespan; no changes to `readiness.py` itself (the existing component-registration pattern is reused, not modified).
- **Architectural boundaries**: no readiness component for context categories that have no provider (§13); no readiness component for the producer-trust configuration itself (§13); existing components' behavior unaffected when the feature is disabled.
- **Required tests**: `/ready` tests for enabled/disabled, healthy/degraded states, mirroring the existing `test_ready.py`/`test_auth_mode_readiness.py` patterns; **a specific test proving `/ready` remains `503` when structural loading and evaluator construction succeed but the semantic preflight fails** — the exact failure mode named in the PR objective.
- **Non-goals**: any new operational dependency (no new external service is introduced).
- **Completion criteria**: `/ready` behavior fully specified and tested for the operation-aware feature flag in both states, and specifically tested against the "ready but every evaluation would fail" bad state this plan exists to prevent.

### PR 9 — Canonical and adversarial conformance
- **Objective**: the full §17 testing strategy, end to end — the sole home of both canonical scenario conformance (beyond what PR 6 already established as an endpoint completion criterion) and the broader adversarial/security suite.
- **Dependencies**: PRs 6–8.
- **Files/areas**: new test modules under `tests/operation_aware/` (mirroring `basis-core`'s own `tests/operation_aware/` naming convention).
- **Architectural boundaries**: tests exercise the real gateway-to-kernel path; no reimplementation of kernel behavior in test mocks for the canonical scenarios.
- **Required tests**: §17, in full.
- **Non-goals**: new features.
- **Completion criteria**: §17's four categories (compatibility, composition, kernel semantics, evidence agreement, security) each have passing coverage, including the producer-trust, semantic-preflight, evidence-embedding, and outcome-classification test additions from this correction pass.

### PR 10 — Documentation and compatibility hardening
- **Status: current (this PR).**
- **Objective**: update `docs/audit-model.md`, `docs/release-readiness.md`, `README.md`, and `CHANGELOG.md` to accurately describe the now-implemented operation-aware surface, following this repository's existing documentation conventions (accurate-to-implementation, not aspirational, per `docs/release-checklist.md` §1).
- **Dependencies**: PRs 1–9 complete. ✅ Satisfied — confirmed against merged `main` at the start of this PR (1087 passed).
- **Files/areas**: the docs listed above, plus new `docs/configuration.md`, `docs/operation-aware-endpoint.md`, `docs/readiness.md`, `docs/release-readiness/operation-aware-gateway-readiness-review.md`, and a new `tests/test_operation_aware_documentation.py`; no other `src/` changes.
- **Architectural boundaries**: documentation only.
- **Required tests**: documentation/example-validation tests added in `tests/test_operation_aware_documentation.py` (environment-variable inventory, JSON example validation, readiness-name checks, audit sibling-artifact wording, required limitation statements).
- **Non-goals**: new features.
- **Completion criteria**: documentation accurately reflects shipped behavior; `docs/release-readiness.md` and the new operation-aware release-readiness review together cover the operation-aware counterpart to the v0.1 "what's included" narrative, including the producer-trust posture and the `expected_policy_version` omission.

### PR 11 — Bounded end-to-end demonstration scenario
- **Status: implemented, current (this PR).**
- **Objective**: a documented, reproducible demonstration (not a product feature) showing a classified-operation-producer-shaped normalized operation flowing through authentication, producer-trust classification, composition, kernel evaluation, enforcement, and audit for at least one `ALLOW`, one explicit `DENY`, one default-deny, and one `NOT_APPLICABLE` scenario — plus one rejected scenario showing an unclassified caller's producer-context assertion being refused before the kernel is ever invoked.
- **Delivered**: `demo/operation-aware/` — `run_demo.py` (a single entry point, `python demo/operation-aware/run_demo.py`, with an optional `--scenario`/`--json` selector, standard-library `argparse` only), two policy bundles (`policy-bundles/operation-aware-demo-bundle.json` valid, `policy-bundles/operation-aware-invalid-bundle.json` structurally valid but semantically invalid), a stable expectations file (`expected/scenario-summary.json`), and a `README.md` explaining purpose, requirements, scenarios, architecture, evidence model, safety, limitations, and the `basis-console` relationship. Six scenarios, one more than originally scoped here: `allow`, `explicit-deny`, `default-deny`, `not-applicable`, `untrusted-producer`, and `semantic-startup-failure` (demonstrating the startup semantic preflight's failure mode from `docs/readiness.md`, not only the five originally listed).
- **Dependencies**: PR 10 (documentation and release hardening). ✅ Satisfied — confirmed against merged `main` at the start of this PR (1178 passed).
- **Files/areas**: `demo/operation-aware/` (new, self-contained — not under `src/` or `policies/`), `tests/test_operation_aware_demo.py` (new), narrow doc updates to `README.md`, `docs/operation-aware-endpoint.md`, `docs/readiness.md`, `CHANGELOG.md`, and `docs/release-readiness/operation-aware-gateway-readiness-review.md`. No `src/` changes.
- **Architectural boundaries**: demonstration/documentation scope only; no new runtime code beyond what PRs 1–9 already shipped. The demonstration drives the real `basis_gateway.main.create_app()` through its real ASGI lifespan and the real `POST /v1/evaluate/operation-aware` route — it does not call route functions directly, does not bypass authentication, and does not mock the kernel result.
- **Required tests**: `tests/test_operation_aware_demo.py` — the demonstration scenario is executable as part of the existing test suite (not just a manual walkthrough), so it cannot silently drift from the shipped behavior it documents.
- **Non-goals**: a permanent demo service, a UI, or console integration — none added.
- **Completion criteria**: a new contributor or downstream integrator can follow the demonstration and reproduce all six scenarios against the real gateway-to-kernel path. Met — see this PR's completion report.

---

## 17. Testing Strategy

### Compatibility

- Existing `/v1/evaluate` request behavior unchanged — full existing test suite passes with zero modifications after every PR in §16.
- Existing response behavior unchanged.
- Existing audit behavior unchanged — `audit/gateway_events.py`'s existing constants, emission call sites, and event shapes are untouched.
- Existing readiness behavior unchanged when `OPERATION_AWARE_ENABLED` is unset.

### Composition

- Identity cannot be caller-supplied (§5, §6) — extends `test_action_composition.py`/`test_resource_composition.py`-style rejection testing to the new input model.
- Roles cannot be caller-supplied.
- Evaluation time is gateway-generated, never caller-influenced (§5, §7, §14).
- Canonical action is composed correctly (reuses existing `core/actions.py` test coverage; adds coverage for the operation-aware call site).
- Canonical resource identifier is composed correctly (reuses existing `core/resources.py` test coverage).
- Absent optional context remains absent — `None`, not an empty-but-present object (§7).
- Contradictory context is rejected (reuses `ActionCompositionError`/`ResourceCompositionError` patterns).
- Untrusted fields cannot override gateway-owned values (§6's full enumeration, table-driven).
- `expected_policy_version` is rejected as an unrecognized field, not silently accepted and ignored (§5b, §6).

### Operation-producer trust (new)

- An ordinary authenticated caller (not classified as a producer) cannot assert operation-producer-only context (`operation_intent`, `location`, `device`, `protocol_context`, `safety_context`, `environment_context`, `risk_context`, `identity_evidence_reference`, `adapter_evidence_reference`) — request rejected `400` (§5a, §7).
- A classified operation producer still cannot assert gateway-owned identity facts (subject, roles, evaluation time, correlation ID, kernel result fields) — the producer-trust classification does not widen what a caller may assert about itself as an authorization subject (§5a, §6).
- Operation-producer identity and authorization-subject identity remain two distinct, independently-tracked facts throughout composition, in the composed request's evidence, and in gateway audit fields — never merged into a single "is this caller trusted" boolean (§5a).
- Untrusted (unclassified) context is never silently promoted to trusted context anywhere in the pipeline — a rejected request produces no `OperationAwareDecisionRequest`, no kernel evaluation, and no `AuditEvidence`; it is not "accepted with a weaker label" (§5a, §10).
- With no producer-trust mechanism configured at all, every caller is treated as non-producer and every producer-context field is rejected (the safe default, §5a).

### Semantic policy-bundle readiness (new)

- A structurally invalid `PolicyBundle` fails at structural construction, before the preflight is reached (§8a).
- A structurally valid but semantically invalid bundle (e.g. duplicate rule IDs, invalid scope declaration) fails the startup semantic preflight; startup fails; `/ready` remains `503` (§8a, §13).
- A bundle containing an unsupported condition operator fails the startup semantic preflight for the same reason (§8a).
- A bundle with duplicate or otherwise structurally-valid-but-semantically-invalid rules fails the startup semantic preflight (§8a).
- A semantically valid bundle that produces a completed, non-`ALLOW` result for the synthetic preflight request (e.g. `DENY` or `NOT_APPLICABLE`) is treated as a **successful** preflight — the specific outcome of the synthetic request does not matter, only that evaluation completed (§8a).
- `/ready` remains unavailable (`503`) specifically because of a failed semantic preflight, even when structural loading and evaluator construction both succeeded — the exact bad state the PR objective calls out (§8a, §13).

### Kernel semantics

- Allow.
- Explicit deny.
- Deny precedence (a request matching both an allow and a deny rule).
- Default deny (no allow rule matches, no deny rule matches).
- `NOT_APPLICABLE` (bundle scope does not cover the request).
- Each of the six `OperationAwareFailureReason` categories individually, **each asserted against its own HTTP status per §9's classification table** — `invalid_request`/`unsupported_schema_version` → `400`; `invalid_policy_bundle`/`policy_validation_failure` → `503`; `condition_evaluation_error`/`internal_evaluation_error` → `500` — not collapsed into a single "governed failure → 403" assertion.
- Missing context (a condition referencing an absent field — confirms no-match, not error, per evaluation semantics §10).
- Unsupported operator — not applicable to this plan's scope as a *gateway* concern (the kernel's ten-operator registry is fixed and this plan adds no new operators); covered instead by confirming the gateway does not attempt to pre-validate condition operators itself (that remains exclusively kernel-owned) and by the semantic-preflight tests above, which do exercise an unsupported-operator bundle at startup.
- Unexpected kernel failure (defensive test only, since `evaluate()` is documented never to raise — confirms the gateway's own defensive handling around the call, per §8/§11, without asserting a false expectation about kernel behavior).

### Evidence agreement

- Kernel evaluation status, semantic outcome, and failure reason are all preserved verbatim in the response body and in the embedded gateway audit evidence (§9, §10) — none of the three is ever inferred from another.
- Gateway disposition is preserved separately from kernel outcome and from the gateway's own HTTP status, never conflated with either (§9).
- Kernel evidence (`AuditEvidence`) is embedded in full inside the gateway's audit record, not referenced by ID alone — a test asserts the durable gateway record contains, or directly carries without a second lookup, all of: kernel outcome, evaluation status, failure reason, policy bundle identity, matched-rule evidence, trace information allowed by the configured evidence tier, evidence ID, gateway disposition, correlation ID, and context provenance (§10).
- Gateway evidence correctly enriched with the fields listed in §10, without duplicating kernel-owned fields under a different name.
- Context provenance accurate — the gateway's own audit fields correctly reflect §5's classification (including operation-producer trust classification) for the specific fields present on a given request.
- Secrets redacted — no raw token, claim set beyond what is already audited today, or credential material in any new audit path, including the newly-embedded `AuditEvidence`.
- Correlation IDs preserved end to end (request → embedded kernel evidence → gateway audit event → HTTP response header).
- No gateway audit record ever contains an `evidence_id` whose corresponding artifact was not itself durably written in the same record (§10's central rule).

### Security

- Spoofed identity rejected (§6, §14).
- Spoofed operation-producer status rejected — see "Operation-producer trust" above (§5a, §14).
- Forged context rejected when the caller is not a classified producer, and correctly classified as trusted-producer-asserted (never silently promoted to verified) when the caller is (§5, §5a, §14).
- Malformed input fails closed (§11).
- Unexpected integration failure fails closed (§11).
- Bypass behavior is not introduced — no test path reaches `OperationAwareEnforcementPoint` without first passing through the same authentication the existing `/v1/evaluate` path requires, and no test path reaches producer-context evaluation without first passing producer-trust classification.

Canonical conformance (§16, PR 6's completion criteria and PR 9) exercises the real gateway-to-kernel path — a live `OperationAwareEnforcementPoint` backed by a real `PolicyBundle` — rather than a mocked reimplementation of kernel behavior, consistent with how this repository's existing test suite already exercises the real v0.1 `EnforcementPoint` rather than mocking it.

---

## 18. Success Criteria

This planning PR is complete because:

- Current gateway behavior is documented against specific files and symbols (§2), including the absence of any existing subject/producer distinction (§2.1).
- The exact `basis-core` v0.2.0 integration surface is identified, with every cited symbol confirmed present at the verified tag (§8; verification recorded in the final report).
- Context ownership is defined for every operation-aware field (§5), with authorization-subject and operation-producer trust kept explicitly distinct (§5a).
- Context provenance classifications are defined (§5's table: verified / gateway-derived / trusted-producer-asserted / untrusted-caller-asserted / configuration-derived / unavailable).
- Caller-supplied versus gateway-owned versus producer-only fields are enumerated explicitly (§6).
- Request-composition ownership is clear and maps to specific reused and new modules, including producer-trust classification (§7).
- Kernel evaluation status, semantic outcome, failure reason, and computed disposition are explicitly separated from each other and from the gateway's own HTTP classification, with a result-to-HTTP table that does not collapse every governed failure into `403` (§9).
- Kernel evidence and gateway evidence are explicitly separated, with an embed-not-reference strategy and a "must not" list (§10).
- A compatibility strategy is selected (Option A, a new endpoint) with the rejected alternatives' reasoning recorded, confirmed still valid after this correction pass (§12).
- Readiness implications are defined, including a startup semantic preflight that closes the "structurally loaded but semantically broken" gap, and what deliberately has no readiness component and why (§8a, §13).
- Failure categories are defined and kept distinct rather than collapsed, including a `400`/`503`/`500` split across governed kernel failures (§11).
- Security risks are documented and tied to the existing threat model, including operation-producer identity spoofing as a distinct risk from authorization-subject spoofing (§14).
- Implementation PRs are sequenced, eleven in total, each independently reviewable, with the prior duplication between outcome-mapping hardening and canonical conformance resolved (§16).
- Each implementation PR has stated completion criteria (§16).
- Non-goals are explicit, including the deferred producer-trust transport mechanism and the omitted `expected_policy_version` field (§15).
- No runtime behavior has changed as a result of this PR (verified in the final report's Validation section).

---

## Related documents

- [`README.md`](../../README.md) — current gateway feature set, setup, API reference
- [`docs/release-readiness.md`](../release-readiness.md) — v0.1 scope and known limitations this plan does not alter
- [`docs/audit-model.md`](../audit-model.md) — the v0.1 audit model this plan's gateway-audit-event work extends
- [`docs/implementation/basis-gateway-v0.1-plan.md`](basis-gateway-v0.1-plan.md) — the precedent this plan follows for structure and rigor
- [`basis-architecture/ROADMAP.md`](https://github.com/basis-foundation/basis-architecture/blob/main/ROADMAP.md) — "Downstream Rollout Sequence" and "The Next Gateway Boundary"
- [`basis-architecture/docs/architecture/basis-gateway.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/basis-gateway.md) — the architectural role and invariants this plan preserves
- [`basis-architecture/docs/architecture/operation-aware-authorization-model.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/operation-aware-authorization-model.md) — the conceptual model this plan implements against
- [`basis-architecture/docs/architecture/operation-aware-evaluation-semantics.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/operation-aware-evaluation-semantics.md) — outcome/failure semantics referenced throughout §9–§11
- [`basis-architecture/docs/architecture/operation-aware-trace-audit-evidence.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/operation-aware-trace-audit-evidence.md) — the evidence model §10 implements against
- [`basis-architecture/docs/architecture/operation-aware-evaluation-orchestration.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/operation-aware-evaluation-orchestration.md) — why `basis_core.evaluation` must not be imported directly (§8)
- [`basis-architecture/docs/security/threat-model.md`](https://github.com/basis-foundation/basis-architecture/blob/main/docs/security/threat-model.md) — the threat analysis §14 is grounded in
- [`basis-core/docs/public-api.md`](https://github.com/basis-foundation/basis-core/blob/main/docs/public-api.md) at tag `v0.2.0` — the authoritative symbol inventory §8 cites
