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
``request_id``, ``action``, ``resource_type``, ``resource_id``, and
``context`` carry the same conceptual meanings as ``EvaluateRequest``
(``api/schemas.py``): ``action`` may be a composite action or a bare verb;
``resource_type``/``resource_id`` may support later gateway composition;
``context`` carries caller-provided string key/value pairs. This module does
not duplicate the full action/resource composition logic — that remains
``core/actions.py``/``core/resources.py`` logic, reused unchanged by a later
PR (§7).

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

Not wired to a route
---------------------
This model is not imported by ``api/routes.py``, ``main.py``, or any other
runtime module in this PR. No kernel request composition occurs here.
"""

from __future__ import annotations

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
    context         Caller-provided string key/value context. Defaults to
                    an empty, independent dict per instance.

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
