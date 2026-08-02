"""Tests for basis_gateway.core.operation_aware_evaluator (PR 5).

Covers §7/§8/§16 PR 5 of
``docs/implementation/operation-aware-gateway-integration-plan.md``: kernel
request construction from ``ComposedOperationAwareInput`` (PR 4) and the
``OperationAwareGatewayEvaluator`` wrapper around the real public
``OperationAwareEnforcementPoint``. Uses a real enforcement point throughout
— no mocking of the kernel evaluator.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from types import MappingProxyType

import pytest
from basis_core.decisions import OperationIntent
from basis_core.decisions.operation_aware import OperationAwareDecisionRequest
from basis_core.domain import (
    OperationAwareDevice,
    OperationAwareLocation,
    OperationAwareRiskContext,
    RedactionClassification,
)
from basis_core.enforcement import EnforcementDisposition, OperationAwareEnforcementPoint
from basis_core.policy import PolicyBundle

from basis_gateway.auth.operation_producer import (
    OperationProducerTrust,
    OperationProducerTrustSource,
    OperationProducerTrustStatus,
)
from basis_gateway.auth.subject_mapper import IdentityContext as GatewayIdentityContext
from basis_gateway.auth.subject_mapper import NormalizedSubject
from basis_gateway.core.operation_aware_composition import ComposedOperationAwareInput
from basis_gateway.core.operation_aware_evaluator import (
    OperationAwareEvaluatorInternalError,
    OperationAwareGatewayEvaluator,
    OperationAwareRequestConstructionError,
    build_operation_aware_decision_request,
    build_operation_aware_evaluator,
)

# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

_FIXED_TIME = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


def _subject(
    subject_id: str = "human-1", roles: tuple[str, ...] = ("viewer",), **attrs: object
) -> NormalizedSubject:
    return NormalizedSubject(subject_id=subject_id, name=subject_id, roles=roles, attributes=attrs)


def _identity_context(subject_id: str = "human-1") -> GatewayIdentityContext:
    return GatewayIdentityContext(
        issuer="https://issuer.example.com", subject_id=subject_id, claims={"sub": subject_id}
    )


def _trust(subject_id: str = "human-1") -> OperationProducerTrust:
    return OperationProducerTrust(
        status=OperationProducerTrustStatus.UNTRUSTED,
        source=OperationProducerTrustSource.NOT_CONFIGURED,
        authorization_subject_id=subject_id,
        operation_producer_subject_id=None,
    )


def _composed(**overrides: object) -> ComposedOperationAwareInput:
    base: dict[str, object] = {
        "request_id": "req-1",
        "correlation_id": "corr-1",
        "authorization_subject": _subject(),
        "identity_context": _identity_context(),
        "operation_producer_trust": _trust(),
        "action": "read:ahu",
        "resource_id": None,
        "resource_type": None,
        "context": MappingProxyType({}),
        "operation_intent": None,
        "location": None,
        "device": None,
        "protocol_context": None,
        "safety_context": None,
        "environment_context": None,
        "risk_context": None,
        "identity_evidence_reference": None,
        "adapter_evidence_reference": None,
        "evaluation_time": _FIXED_TIME,
        "provenance": MappingProxyType({}),
    }
    base.update(overrides)
    return ComposedOperationAwareInput(**base)  # type: ignore[arg-type]


VALID_BUNDLE = PolicyBundle(
    bundle_id="test-bundle",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    rules=[
        {
            "rule_id": "allow-read-ahu",
            "effect": "allow",
            "match": {"actions": ["read:ahu"]},
        }
    ],
)


def _real_evaluator(
    bundle: PolicyBundle = VALID_BUNDLE, **kwargs: object
) -> OperationAwareGatewayEvaluator:
    return build_operation_aware_evaluator(bundle, **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 1. Request construction — field mapping
# ---------------------------------------------------------------------------


def test_request_id_mapped() -> None:
    request = build_operation_aware_decision_request(_composed(request_id="req-xyz"))
    assert request.request_id == "req-xyz"


def test_correlation_id_mapped() -> None:
    request = build_operation_aware_decision_request(_composed(correlation_id="corr-xyz"))
    assert request.correlation_id == "corr-xyz"


def test_subject_id_mapped() -> None:
    composed = _composed(authorization_subject=_subject("adapter-1"))
    request = build_operation_aware_decision_request(composed)
    assert request.subject_id == "adapter-1"


def test_subject_roles_mapped() -> None:
    composed = _composed(authorization_subject=_subject(roles=("operator", "viewer")))
    request = build_operation_aware_decision_request(composed)
    assert set(request.subject_roles) == {"operator", "viewer"}


def test_subject_attrs_string_values_mapped() -> None:
    composed = _composed(authorization_subject=_subject(email="a@example.com"))
    request = build_operation_aware_decision_request(composed)
    assert request.subject_attrs == {"email": "a@example.com"}


def test_subject_attrs_non_string_values_dropped() -> None:
    composed = _composed(authorization_subject=_subject(count=42))
    request = build_operation_aware_decision_request(composed)
    assert "count" not in request.subject_attrs


def test_action_mapped() -> None:
    request = build_operation_aware_decision_request(_composed(action="write:hvac:setpoint"))
    assert request.action == "write:hvac:setpoint"


def test_resource_id_mapped_to_resource_field() -> None:
    request = build_operation_aware_decision_request(_composed(resource_id="ahu:rooftop-1"))
    assert request.resource == "ahu:rooftop-1"


def test_resource_type_mapped() -> None:
    request = build_operation_aware_decision_request(_composed(resource_type="ahu"))
    assert request.resource_type == "ahu"


def test_operation_intent_mapped() -> None:
    request = build_operation_aware_decision_request(
        _composed(operation_intent=OperationIntent.STATE_CHANGING)
    )
    assert request.operation_intent is OperationIntent.STATE_CHANGING


def test_location_mapped() -> None:
    location = OperationAwareLocation(site_id="site-1")
    request = build_operation_aware_decision_request(_composed(location=location))
    assert request.location == location


def test_device_mapped() -> None:
    device = OperationAwareDevice(device_id="device-1", device_class="controller")
    request = build_operation_aware_decision_request(_composed(device=device))
    assert request.device == device


def test_risk_context_mapped() -> None:
    risk = OperationAwareRiskContext(classification="elevated")
    request = build_operation_aware_decision_request(_composed(risk_context=risk))
    assert request.risk_context == risk


def test_evaluation_time_mapped() -> None:
    request = build_operation_aware_decision_request(_composed(evaluation_time=_FIXED_TIME))
    assert request.evaluation_time == _FIXED_TIME


def test_identity_evidence_reference_mapped() -> None:
    from basis_core.domain import IdentityEvidenceReference

    ref = IdentityEvidenceReference(
        reference_id="id-ev-1",
        evidence_digest={"algorithm": "sha-256", "value": "abc123"},
        identity_source="basis-identity",
        redaction_classification=RedactionClassification.SAFE_TO_EXPOSE,
    )
    request = build_operation_aware_decision_request(_composed(identity_evidence_reference=ref))
    assert request.identity_evidence_reference == ref


def test_adapter_evidence_reference_mapped() -> None:
    from basis_core.domain import AdapterEvidenceReference

    ref = AdapterEvidenceReference(
        reference_id="ad-ev-1",
        evidence_digest={"algorithm": "sha-256", "value": "abc123"},
        adapter_source="basis-adapters:bacnet",
        redaction_classification=RedactionClassification.SAFE_TO_EXPOSE,
    )
    request = build_operation_aware_decision_request(_composed(adapter_evidence_reference=ref))
    assert request.adapter_evidence_reference == ref


# ---------------------------------------------------------------------------
# 2. Omitted / never-mapped fields
# ---------------------------------------------------------------------------


def test_omitted_optional_context_remains_absent() -> None:
    request = build_operation_aware_decision_request(_composed())
    assert request.location is None
    assert request.device is None
    assert request.protocol_context is None
    assert request.safety_context is None
    assert request.environment_context is None
    assert request.risk_context is None
    assert request.identity_evidence_reference is None
    assert request.adapter_evidence_reference is None


def test_expected_policy_version_remains_unset() -> None:
    request = build_operation_aware_decision_request(_composed())
    assert request.expected_policy_version is None


def test_identity_source_and_authority_mode_remain_unset() -> None:
    """ComposedOperationAwareInput has no field for either — per the
    integration plan §5 provenance table, both are "absent, never
    guessed" in this rollout."""
    request = build_operation_aware_decision_request(_composed())
    assert request.identity_source is None
    assert request.authority_mode is None


def test_kernel_request_model_has_no_free_form_context_field() -> None:
    """OperationAwareDecisionRequest deliberately has no context: dict[str,
    str] catch-all (see the model's own "Deliberately absent fields"
    docstring section) — there is no field to map
    ComposedOperationAwareInput.context onto, structurally, not merely by
    this module's choice."""
    assert "context" not in OperationAwareDecisionRequest.model_fields


def test_composed_context_with_only_reserved_keys_does_not_error_or_leak() -> None:
    """Gateway-owned, reserved-namespace composition evidence does not
    prevent construction and is not smuggled onto the kernel request under
    another name (there is no field to smuggle it onto — see
    ``test_kernel_request_model_has_no_free_form_context_field``)."""
    composed = _composed(context=MappingProxyType({"basis_gateway.action_composed": "true"}))
    request = build_operation_aware_decision_request(composed)
    dumped = request.model_dump(mode="json")
    assert "action_composed" not in str(dumped)


def test_composed_context_with_non_reserved_key_raises_construction_error() -> None:
    """A non-reserved key in an already-composed context is a
    gateway-internal contract violation (§8 PR 5 correction) — never
    silently accepted and dropped at kernel-request construction time. An
    ordinary caller can never produce this composed input in practice
    (PR 3's ``OperationAwareEvaluateRequest.context`` is validated
    empty-only), so this exercises the defense-in-depth guard directly
    against a manually constructed, malformed
    ``ComposedOperationAwareInput``."""
    composed = _composed(context=MappingProxyType({"maintenance_ticket": "CHG-123"}))
    with pytest.raises(OperationAwareRequestConstructionError):
        build_operation_aware_decision_request(composed)


def test_unexpected_context_key_error_does_not_expose_its_value() -> None:
    composed = _composed(context=MappingProxyType({"maintenance_ticket": "CHG-123"}))
    with pytest.raises(OperationAwareRequestConstructionError) as exc_info:
        build_operation_aware_decision_request(composed)
    assert "CHG-123" not in str(exc_info.value)


def test_malformed_composed_input_not_mutated_by_rejected_construction() -> None:
    composed = _composed(context=MappingProxyType({"maintenance_ticket": "CHG-123"}))
    context_before = dict(composed.context)
    action_before = composed.action
    with pytest.raises(OperationAwareRequestConstructionError):
        build_operation_aware_decision_request(composed)
    assert dict(composed.context) == context_before
    assert composed.action == action_before


def test_normal_composed_input_with_no_composition_evidence_builds_successfully() -> None:
    """A normal composed input whose context carries no composition
    evidence at all (the common case: no bare-verb/resource_type or
    local-resource-id composition occurred) builds the public kernel
    request successfully."""
    composed = _composed(context=MappingProxyType({}))
    request = build_operation_aware_decision_request(composed)
    assert isinstance(request, OperationAwareDecisionRequest)


def test_reserved_action_composition_evidence_stays_outside_kernel_request() -> None:
    composed = _composed(
        context=MappingProxyType(
            {
                "basis_gateway.action_composed": "true",
                "basis_gateway.original_action": "read",
                "basis_gateway.resource_type": "ahu",
                "basis_gateway.composed_action": "read:ahu",
            }
        )
    )
    request = build_operation_aware_decision_request(composed)
    dumped = request.model_dump(mode="json")
    assert "action_composed" not in str(dumped)
    assert "original_action" not in str(dumped)


def test_reserved_resource_composition_evidence_stays_outside_kernel_request() -> None:
    composed = _composed(
        context=MappingProxyType(
            {
                "basis_gateway.resource_composed": "true",
                "basis_gateway.original_resource_id": "rooftop-1",
                "basis_gateway.composed_resource_id": "ahu:rooftop-1",
            }
        )
    )
    request = build_operation_aware_decision_request(composed)
    dumped = request.model_dump(mode="json")
    assert "resource_composed" not in str(dumped)
    assert "rooftop-1" not in str(dumped)


def test_operation_producer_trust_and_provenance_not_on_kernel_model() -> None:
    forbidden = {
        "operation_producer_trust",
        "provenance",
        "correlation_id_source",
        "route",
        "http_method",
    }
    model_field_names = set(OperationAwareDecisionRequest.model_fields) - {"correlation_id"}
    assert forbidden.isdisjoint(model_field_names)


# ---------------------------------------------------------------------------
# 3. Input immutability and construction failure
# ---------------------------------------------------------------------------


def test_composed_input_not_mutated_by_construction() -> None:
    composed = _composed(context=MappingProxyType({"basis_gateway.original_action": "read"}))
    context_before = dict(composed.context)
    action_before = composed.action
    build_operation_aware_decision_request(composed)
    assert dict(composed.context) == context_before
    assert composed.action == action_before


def test_invalid_action_raises_construction_error() -> None:
    composed = _composed(action="NOT A VALID ACTION")
    with pytest.raises(OperationAwareRequestConstructionError):
        build_operation_aware_decision_request(composed)


def test_construction_error_does_not_expose_full_composed_input() -> None:
    composed = _composed(action="NOT A VALID ACTION")
    with pytest.raises(OperationAwareRequestConstructionError) as exc_info:
        build_operation_aware_decision_request(composed)
    assert "NOT A VALID ACTION" not in str(exc_info.value)


def test_construction_error_chains_original_validation_error() -> None:
    from pydantic import ValidationError

    composed = _composed(action="NOT A VALID ACTION")
    with pytest.raises(OperationAwareRequestConstructionError) as exc_info:
        build_operation_aware_decision_request(composed)
    assert isinstance(exc_info.value.__cause__, ValidationError)


# ---------------------------------------------------------------------------
# 4. Real enforcement path — result preservation
# ---------------------------------------------------------------------------


def test_valid_bundle_allow_preserved() -> None:
    evaluator = _real_evaluator()
    result = evaluator.evaluate(_composed(action="read:ahu"))
    assert result.response.outcome.value == "allow"
    assert result.disposition is EnforcementDisposition.ALLOW


def test_explicit_deny_preserved() -> None:
    bundle = PolicyBundle(
        bundle_id="deny-bundle",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[
            {"rule_id": "allow-read", "effect": "allow", "match": {"actions": ["read:ahu"]}},
            {"rule_id": "deny-write", "effect": "deny", "match": {"actions": ["write:ahu"]}},
        ],
    )
    evaluator = _real_evaluator(bundle)
    result = evaluator.evaluate(_composed(action="write:ahu"))
    assert result.response.outcome.value == "deny"
    assert result.disposition is EnforcementDisposition.DENY


def test_default_deny_preserved() -> None:
    """No rule matches the request's action -> completed default deny, not
    NOT_APPLICABLE (the bundle itself has no scope restriction)."""
    evaluator = _real_evaluator()
    result = evaluator.evaluate(_composed(action="write:other"))
    assert result.response.evaluation_status.value == "completed"
    assert result.response.outcome.value == "deny"
    assert result.disposition is EnforcementDisposition.DENY


def test_not_applicable_preserved() -> None:
    bundle = PolicyBundle(
        bundle_id="scoped-bundle",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        scope={"actions": ["read:other_domain"]},
        rules=[{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
    )
    evaluator = _real_evaluator(bundle)
    result = evaluator.evaluate(_composed(action="read:ahu"))
    assert result.response.evaluation_status.value == "completed"
    assert result.response.outcome.value == "not_applicable"
    assert result.disposition is EnforcementDisposition.DENY


def test_kernel_failure_status_and_reason_preserved() -> None:
    """Duplicate rule_id: structurally accepted by PolicyBundle, but a
    governed semantic failure at evaluate() time. Constructed directly via
    the released public ``OperationAwareEnforcementPoint.for_bundle()``
    factory (bypassing ``build_operation_aware_evaluator``'s own preflight,
    which would itself reject this bundle) to isolate the wrapper's own
    result-preservation behavior from preflight — without ever importing
    the internal ``OperationAwareEvaluationEngine``."""
    dup_bundle = PolicyBundle(
        bundle_id="dup-bundle",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[
            {"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}},
            {"rule_id": "r1", "effect": "deny", "match": {"actions": ["write:ahu"]}},
        ],
    )
    enforcement_point = OperationAwareEnforcementPoint.for_bundle(dup_bundle)
    evaluator = OperationAwareGatewayEvaluator(
        _enforcement_point=enforcement_point,
        _trace_id_factory=lambda: "trace-1",
        _evidence_id_factory=lambda: "evidence-1",
        _clock=lambda: _FIXED_TIME,
    )
    result = evaluator.evaluate(_composed(action="read:ahu"))
    assert result.response.evaluation_status.value == "failed"
    assert result.response.failure_reason.value == "policy_validation_failure"
    assert result.disposition is EnforcementDisposition.DENY


def test_enforcement_disposition_preserved_exactly() -> None:
    evaluator = _real_evaluator()
    result = evaluator.evaluate(_composed(action="read:ahu"))
    assert isinstance(result.disposition, EnforcementDisposition)


def test_audit_evidence_preserved() -> None:
    evaluator = _real_evaluator()
    result = evaluator.evaluate(_composed(action="read:ahu"))
    assert result.audit_evidence is not None
    assert result.audit_evidence.request_id == "req-1"


def test_trace_id_reference_preserved_on_response() -> None:
    evaluator = _real_evaluator(trace_id_factory=lambda: "fixed-trace-id")
    result = evaluator.evaluate(_composed())
    assert result.response.trace_id == "fixed-trace-id"


# ---------------------------------------------------------------------------
# 5. Per-call metadata generation
# ---------------------------------------------------------------------------


def test_trace_id_factory_called_once_per_evaluation() -> None:
    calls: list[int] = []

    def counting_trace_id() -> str:
        calls.append(1)
        return f"trace-{len(calls)}"

    evaluator = _real_evaluator(trace_id_factory=counting_trace_id)
    evaluator.evaluate(_composed())
    assert len(calls) == 1


def test_evidence_id_factory_called_once_per_evaluation() -> None:
    calls: list[int] = []

    def counting_evidence_id() -> str:
        calls.append(1)
        return f"evidence-{len(calls)}"

    evaluator = _real_evaluator(evidence_id_factory=counting_evidence_id)
    evaluator.evaluate(_composed())
    assert len(calls) == 1


def test_clock_called_once_per_evaluation() -> None:
    calls: list[int] = []

    def counting_clock() -> datetime:
        calls.append(1)
        return _FIXED_TIME

    evaluator = _real_evaluator(clock=counting_clock)
    evaluator.evaluate(_composed())
    assert len(calls) == 1


def test_two_evaluations_receive_different_trace_ids() -> None:
    ids = iter(["trace-a", "trace-b"])
    evaluator = _real_evaluator(trace_id_factory=lambda: next(ids))
    r1 = evaluator.evaluate(_composed())
    r2 = evaluator.evaluate(_composed())
    assert r1.response.trace_id != r2.response.trace_id


def test_two_evaluations_receive_different_evidence_ids() -> None:
    ids = iter(["evidence-a", "evidence-b"])
    evaluator = _real_evaluator(evidence_id_factory=lambda: next(ids))
    r1 = evaluator.evaluate(_composed())
    r2 = evaluator.evaluate(_composed())
    assert r1.audit_evidence.evidence_id != r2.audit_evidence.evidence_id


def test_two_evaluations_receive_independent_recorded_at() -> None:
    times = iter([_FIXED_TIME, _FIXED_TIME.replace(hour=13)])
    evaluator = _real_evaluator(clock=lambda: next(times))
    r1 = evaluator.evaluate(_composed())
    r2 = evaluator.evaluate(_composed())
    assert r1.audit_evidence.recorded_at != r2.audit_evidence.recorded_at


def test_evidence_id_and_recorded_at_reach_audit_evidence_exactly() -> None:
    evaluator = _real_evaluator(
        evidence_id_factory=lambda: "fixed-evidence-id",
        clock=lambda: _FIXED_TIME,
    )
    result = evaluator.evaluate(_composed())
    assert result.audit_evidence.evidence_id == "fixed-evidence-id"
    assert result.audit_evidence.recorded_at == _FIXED_TIME


def test_caller_cannot_influence_trace_evidence_or_recorded_at() -> None:
    """evaluate() takes only a ComposedOperationAwareInput — there is no
    parameter through which a caller could supply trace_id/evidence_id/
    recorded_at directly."""
    import inspect

    sig = inspect.signature(OperationAwareGatewayEvaluator.evaluate)
    assert list(sig.parameters) == ["self", "composed"]


def test_naive_clock_result_rejected() -> None:
    naive = datetime(2026, 8, 1, 12, 0, 0)  # no tzinfo
    evaluator = _real_evaluator(clock=lambda: naive)
    with pytest.raises(OperationAwareEvaluatorInternalError):
        evaluator.evaluate(_composed())


def test_request_id_not_reused_as_trace_id() -> None:
    evaluator = _real_evaluator(trace_id_factory=lambda: "unrelated-trace-id")
    result = evaluator.evaluate(_composed(request_id="req-should-not-appear-as-trace"))
    assert result.response.trace_id != "req-should-not-appear-as-trace"
    assert result.response.trace_id == "unrelated-trace-id"


def test_correlation_id_not_reused_as_evidence_id() -> None:
    evaluator = _real_evaluator(evidence_id_factory=lambda: "unrelated-evidence-id")
    result = evaluator.evaluate(_composed(correlation_id="corr-should-not-appear-as-evidence"))
    assert result.audit_evidence.evidence_id != "corr-should-not-appear-as-evidence"
    assert result.audit_evidence.evidence_id == "unrelated-evidence-id"


def test_preflight_metadata_does_not_leak_into_real_calls() -> None:
    from basis_gateway.core.operation_aware_evaluator import (
        _PREFLIGHT_EVIDENCE_ID,
        _PREFLIGHT_TRACE_ID,
    )

    evaluator = _real_evaluator()
    result = evaluator.evaluate(_composed())
    assert result.response.trace_id != _PREFLIGHT_TRACE_ID
    assert result.audit_evidence.evidence_id != _PREFLIGHT_EVIDENCE_ID


# ---------------------------------------------------------------------------
# 6. Immutability
# ---------------------------------------------------------------------------


def test_evaluator_does_not_mutate_loaded_bundle() -> None:
    bundle_before = copy.deepcopy(VALID_BUNDLE)
    evaluator = _real_evaluator()
    evaluator.evaluate(_composed())
    assert bundle_before == VALID_BUNDLE


def test_evaluator_does_not_mutate_composed_input() -> None:
    composed = _composed(context=MappingProxyType({"basis_gateway.original_action": "read"}))
    context_before = dict(composed.context)
    action_before = composed.action
    evaluator = _real_evaluator()
    evaluator.evaluate(composed)
    assert dict(composed.context) == context_before
    assert composed.action == action_before


def test_evaluator_holds_no_mutable_state_between_calls() -> None:
    evaluator = _real_evaluator()
    fields_before = vars(evaluator).copy() if hasattr(evaluator, "__dict__") else None
    evaluator.evaluate(_composed(action="read:ahu"))
    evaluator.evaluate(_composed(action="write:other"))
    # Frozen, slotted dataclass: no new instance attributes can appear.
    assert not hasattr(evaluator, "__dict__") or vars(evaluator) == fields_before


def test_evaluator_is_frozen_dataclass() -> None:
    evaluator = _real_evaluator()
    with pytest.raises(AttributeError):
        evaluator._trace_id_factory = lambda: "hacked"  # type: ignore[misc]
