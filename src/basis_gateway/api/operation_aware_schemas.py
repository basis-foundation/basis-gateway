"""Normalized operation-aware gateway input model (shape validation only).

This module defines ``OperationAwareEvaluateRequest`` — the gateway-facing
input shape for a future, not-yet-registered operation-aware evaluation
endpoint. It exists in isolation, per PR 3 of
``docs/implementation/operation-aware-gateway-integration-plan.md`` (§6
"Normalized Operation Input"): the model is not imported by any route, does
not compose a ``basis_core.decisions.OperationAwareDecisionRequest``, does
not invoke any kernel entry point, and does not evaluate policy.

Two-layer validation, this module implements only the first
-------------------------------------------------------------
The integration plan (§6) splits validation into two layers:

1. **Shape validation** (this module) — field type, format, and closed
   vocabulary membership. This layer runs before authentication and cannot
   know anything about the caller.
2. **Provenance/trust validation** (a later PR, §5a/§7) — whether the
   *specific*, now-authenticated caller is permitted to supply the fields
   present on this request (for example, whether the caller has been
   classified as a trusted operation producer).

**Successful model validation proves only that the request has a supported
shape. It does not establish that the caller is authorized to assert
operation-producer context.** Identity is still derived exclusively from
authentication (unchanged from ``EvaluateRequest``/``/v1/evaluate``);
operation-producer trust is evaluated later, by later gateway logic, not by
this model. This module makes no producer-trust decision of any kind — it
does not fabricate one, and it does not accept a caller-supplied claim of
producer status.

Reused, not forked, normalized-operation fields
------------------------------------------------
``request_id``, ``action``, ``resource_type``, and ``resource_id`` carry the
same conceptual meanings as ``EvaluateRequest`` (``api/schemas.py``):
``action`` may be a composite action or a bare verb; ``resource_type``/
``resource_id`` may support later gateway composition. This module does not
duplicate the full action/resource composition logic — that remains
``core/actions.py``/``core/resources.py`` logic, reused unchanged by a later
PR (§7). ``context`` is reused in *name and type* only
(``dict[str, str]``, defaulting to an independent ``{}`` per instance) — its
*accepted values* do not mirror ``EvaluateRequest``'s: this model does not
support arbitrary caller-provided free-form context as a normalized
operation-aware field. See the next section for the currently-enforced,
empty-only contract and why.

``context`` is empty-only on the operation-aware path (PR 5)
----------------------------------------------------------------
Unlike v0.1's ``EvaluateRequest``, the released public
``basis_core.decisions.OperationAwareDecisionRequest`` has **no free-form
``context: dict[str, str]`` field** — it deliberately replaces that
catch-all with governed, explicit, named context categories (see
``basis_gateway.core.operation_aware_evaluator``'s module docstring). A
caller-supplied, non-empty ``context`` on this model would therefore be
accepted here only to be silently unrepresentable at the kernel boundary —
this module refuses to do that. ``context`` remains a structurally present
field (an omitted value still defaults to an independent ``{}`` per
instance, and an explicit ``{}`` is accepted) so this model's shape stays
compatible with ``EvaluateRequest``'s, but any non-empty value fails
validation clearly, via ``operation_aware_context_must_be_empty`` below.
This is a temporary, governed restriction for this rollout — not a
structural claim that free-form context can never be added to the
operation-aware contract later.

Operation-aware context fields reuse basis-core's public domain models
------------------------------------------------------------------------
``operation_intent`` and the eight nested context/evidence fields reuse the
public ``basis-core`` v0.2.0 models directly
(``basis_core.decisions.OperationIntent``;
``basis_core.domain.OperationAware*``, ``IdentityEvidenceReference``,
``AdapterEvidenceReference``) rather than duplicating their field-level
validation in gateway-owned types. Every one of these fields is optional and
independently nested; when omitted, it remains ``None`` — this module never
manufactures an empty-but-present context object, because "field absent" and
"field present but empty" are distinguishable states the kernel's future
policy conditions may depend on (§7).

Gateway-owned and producer-trust fields are rejected, not stripped
---------------------------------------------------------------------
``model_config = ConfigDict(extra="forbid")`` rejects any field this model
does not define — including every gateway-owned fact
(``subject_id``, ``subject_roles``, ``subject_attrs``, ``identity_source``,
``authority_mode``, ``evaluation_time``, ``correlation_id``,
``evaluation_status``, ``outcome``, ``failure_reason``, ``disposition``,
policy-bundle identity fields), any producer-trust flag
(``is_trusted_operation_producer``, ``producer_trust_classification``), and
``expected_policy_version``. Per §5b of the integration plan,
``expected_policy_version`` is omitted from this input model entirely in
this rollout — a caller that supplies it receives the same rejection any
other unrecognized field would, not silent acceptance-and-discard.

Wired to a route (PR 6)
-------------------------
This model is imported by ``api/routes.py`` and is the shape-validation
layer for ``POST /v1/evaluate/operation-aware`` — see
``api.routes.evaluate_operation_aware``. This module still performs no
kernel request composition itself: shape validation (this class) is layer
1 of the two-layer model described above; provenance/trust validation and
kernel request construction remain
``basis_gateway.core.operation_aware_composition``/
``basis_gateway.core.operation_aware_evaluator``'s responsibility, invoked
by the route after this model validates successfully.
"""

from __future__ import annotations

from typing import Any

from basis_core.decisions import OperationIntent
from basis_core.domain import (
    AdapterEvidenceReference,
    IdentityEvidenceReference,
    OperationAwareDevice,
    OperationAwareEnvironmentContext,
    OperationAwareLocation,
    OperationAwareProtocolContext,
    OperationAwareRiskContext,
    OperationAwareSafetyContext,
)
from basis_core.enforcement import OperationAwareEnforcementResult
from pydantic import BaseModel, ConfigDict, Field, field_validator


class OperationAwareEvaluateRequest(BaseModel):
    """Normalized operation-aware input shape (shape validation only).

    See this module's docstring for the full boundary this model does and
    does not enforce. In short: this proves the request is *shaped*
    correctly. It does not authenticate a caller, does not classify a
    caller as a trusted operation producer, and does not construct a
    kernel-facing request.

    Existing normalized-operation fields
    ─────────────────────────────────────
    request_id     Optional caller-supplied request identifier, reused
                    unchanged from ``EvaluateRequest``.
    action          Required. A composite action (e.g. ``"read:ahu"``) or a
                    bare verb (e.g. ``"read"``) — composition is a later
                    gateway responsibility, not performed here.
    resource_type   Optional. May support later gateway composition.
    resource_id     Optional. May be local, typed, or absent.
    context         Empty-only (not a supported free-form field on this
                    model — see this module's docstring, "``context`` is
                    empty-only on the operation-aware path"). Defaults to
                    an empty, independent dict per instance; a non-empty
                    value fails validation.

    Operation-aware context (all optional; absent stays ``None``)
    ─────────────────────────────────────────────────────────────
    operation_intent               Closed vocabulary
                                    (``basis_core.decisions.OperationIntent``).
    location                       ``basis_core.domain.OperationAwareLocation``.
    device                         ``basis_core.domain.OperationAwareDevice``.
    protocol_context               ``basis_core.domain.OperationAwareProtocolContext``.
    safety_context                 ``basis_core.domain.OperationAwareSafetyContext``.
    environment_context            ``basis_core.domain.OperationAwareEnvironmentContext``.
    risk_context                   ``basis_core.domain.OperationAwareRiskContext``.
    identity_evidence_reference    ``basis_core.domain.IdentityEvidenceReference``.
    adapter_evidence_reference     ``basis_core.domain.AdapterEvidenceReference``.

    Strictness
    ──────────
    ``extra="forbid"`` — any field not listed above (gateway-owned facts,
    producer-trust flags, ``expected_policy_version``, or any other unknown
    field) fails validation rather than being silently accepted or dropped.
    """

    model_config = ConfigDict(extra="forbid")

    # -- Existing normalized-operation fields (reused from EvaluateRequest) --
    request_id: str | None = None
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    context: dict[str, str] = Field(default_factory=dict)

    # -- Operation-aware context (all optional; absence preserved as None) --
    operation_intent: OperationIntent | None = None
    location: OperationAwareLocation | None = None
    device: OperationAwareDevice | None = None
    protocol_context: OperationAwareProtocolContext | None = None
    safety_context: OperationAwareSafetyContext | None = None
    environment_context: OperationAwareEnvironmentContext | None = None
    risk_context: OperationAwareRiskContext | None = None
    identity_evidence_reference: IdentityEvidenceReference | None = None
    adapter_evidence_reference: AdapterEvidenceReference | None = None

    @field_validator("action")
    @classmethod
    def action_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("action must not be empty")
        return v

    @field_validator("context")
    @classmethod
    def operation_aware_context_must_be_empty(cls, v: dict[str, str]) -> dict[str, str]:
        """Reject non-empty free-form context (temporary, governed restriction).

        The public ``OperationAwareDecisionRequest`` has no free-form
        ``context`` field to map this onto (see this module's docstring,
        "``context`` is empty-only on the operation-aware path"). An omitted
        ``context`` still defaults to ``{}``; an explicit ``{}`` is accepted
        unchanged. Any non-empty value fails validation clearly, rather than
        being accepted here and silently discarded at kernel-request
        construction time.
        """
        if v:
            raise ValueError(
                "free-form context is not supported by the operation-aware request "
                "contract; OperationAwareDecisionRequest has no context field to map "
                "it onto. Supply operation-aware context via the dedicated typed "
                "fields (operation_intent, location, device, protocol_context, "
                "safety_context, environment_context, risk_context, "
                "identity_evidence_reference, adapter_evidence_reference) instead."
            )
        return v


class OperationAwareEvaluateResponse(BaseModel):
    """Response body for ``POST /v1/evaluate/operation-aware`` (PR 6, §9/§16).

    Preserves the public kernel result — ``OperationAwareEnforcementResult``
    (``basis_gateway.core.operation_aware_evaluator.OperationAwareGatewayEvaluator
    .evaluate()``'s return value) — without reinterpretation. Every field
    below is copied verbatim from ``result.response``/``result.disposition``;
    none is recomputed, rewritten, or gateway-synthesized. See
    ``from_result`` and
    ``docs/implementation/operation-aware-gateway-integration-plan.md`` §9
    ("Kernel Outcome Versus Gateway Disposition") for the invariants this
    model exists to preserve:

    - ``outcome`` and ``failure_reason`` are preserved exactly, including
      ``None`` when not applicable (a completed result has no
      ``failure_reason``; a failed result has no ``outcome``).
    - ``disposition`` is the kernel-*computed* value
      (``basis_core.enforcement.EnforcementDisposition``) — never
      gateway-recomputed from ``outcome``.
    - ``NOT_APPLICABLE`` is preserved as ``"not_applicable"`` in ``outcome``,
      never rewritten to ``"deny"`` (only the gateway's separately-derived
      HTTP status collapses ``deny``/``not_applicable`` to the same code —
      see ``basis_gateway.api.operation_aware_classification``).
    - A failed evaluation is preserved as ``evaluation_status="failed"``,
      ``outcome=None``, and the kernel's own governed ``failure_reason`` —
      never rewritten as an explicit policy denial.

    This model carries no raw request data, tokens, claims, policy
    documents, or protocol payloads, and no gateway-authored explanation or
    invented reason code — ``explanation``/``reason_code`` are passed
    through only when the kernel itself populated them.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: str
    correlation_id: str | None = None
    evaluation_status: str
    outcome: str | None = None
    failure_reason: str | None = None
    bundle_id: str | None = None
    bundle_version: str | None = None
    trace_id: str | None = None
    reason_code: str | None = None
    explanation: str | None = None
    disposition: str
    # Only ever non-None if a future caller of OperationAwareGatewayEvaluator
    # requests trace embedding (embed_evaluation_trace=True) — PR 5/PR 6's
    # own evaluator wrapper does not request it, so this is always None
    # today. Represented as a plain dict (via the trace's own model_dump()),
    # never as an imported internal trace type, so this module never imports
    # basis_core.evaluation.* / basis_core.audit.operation_aware.evaluation_trace
    # directly.
    evaluation_trace: dict[str, Any] | None = None

    @classmethod
    def from_result(cls, result: OperationAwareEnforcementResult) -> OperationAwareEvaluateResponse:
        """Build the HTTP response body from a real ``OperationAwareEnforcementResult``.

        Copies every field verbatim from ``result.response``/
        ``result.disposition`` — no reinterpretation, no recomputation. See
        this class's docstring for the invariants this preserves.
        """
        response = result.response
        evaluation_trace_dump: dict[str, Any] | None = None
        if response.evaluation_trace is not None:
            evaluation_trace_dump = response.evaluation_trace.model_dump(mode="json")

        return cls(
            request_id=response.request_id,
            correlation_id=response.correlation_id,
            evaluation_status=response.evaluation_status.value,
            outcome=response.outcome.value if response.outcome is not None else None,
            failure_reason=(
                response.failure_reason.value if response.failure_reason is not None else None
            ),
            bundle_id=response.bundle_id,
            bundle_version=response.bundle_version,
            trace_id=response.trace_id,
            reason_code=response.reason_code,
            explanation=response.explanation,
            disposition=result.disposition.value,
            evaluation_trace=evaluation_trace_dump,
        )
