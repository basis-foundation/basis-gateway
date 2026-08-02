"""Unit tests for ``OperationAwareEvaluateRequest`` (PR 3 — shape validation only).

Scope, per ``docs/implementation/operation-aware-gateway-integration-plan.md``
§6/§16 (PR 3) and §17 ("Composition"): this model is tested in complete
isolation. No route, no authentication, no producer-trust classification, no
kernel request composition, no policy loading, and no HTTP behavior is
exercised here — all of that is deferred to later PRs.
"""

from __future__ import annotations

import copy

import pytest
from basis_core.decisions import OperationIntent
from basis_core.domain import (
    AdapterEvidenceReference,
    EvidenceDigest,
    IdentityEvidenceReference,
    OperationAwareDevice,
    OperationAwareEnvironmentContext,
    OperationAwareLocation,
    OperationAwareProtocolContext,
    OperationAwareRiskContext,
    OperationAwareSafetyContext,
    RedactionClassification,
)
from pydantic import ValidationError

from basis_gateway.api.operation_aware_schemas import OperationAwareEvaluateRequest

# ---------------------------------------------------------------------------
# Shared minimal fixtures for nested basis-core public models
# ---------------------------------------------------------------------------

_EVIDENCE_DIGEST = {"algorithm": "sha-256", "value": "abc123"}


def _identity_evidence_reference_payload() -> dict:
    return {
        "reference_id": "identity-evidence-1",
        "evidence_digest": dict(_EVIDENCE_DIGEST),
        "identity_source": "basis-identity",
        "redaction_classification": RedactionClassification.SAFE_TO_EXPOSE.value,
    }


def _adapter_evidence_reference_payload() -> dict:
    return {
        "reference_id": "adapter-evidence-1",
        "evidence_digest": dict(_EVIDENCE_DIGEST),
        "adapter_source": "basis-adapters:bacnet",
        "redaction_classification": RedactionClassification.SAFE_TO_EXPOSE.value,
    }


# ---------------------------------------------------------------------------
# 1. Minimal valid request
# ---------------------------------------------------------------------------


def test_minimal_valid_request() -> None:
    req = OperationAwareEvaluateRequest(action="read:ahu")

    assert req.action == "read:ahu"
    assert req.request_id is None
    assert req.resource_type is None
    assert req.resource_id is None
    assert req.context == {}

    for field_name in (
        "operation_intent",
        "location",
        "device",
        "protocol_context",
        "safety_context",
        "environment_context",
        "risk_context",
        "identity_evidence_reference",
        "adapter_evidence_reference",
    ):
        assert getattr(req, field_name) is None, f"{field_name} should default to None"


# ---------------------------------------------------------------------------
# 2. Existing normalized-operation fields
# ---------------------------------------------------------------------------


def test_existing_normalized_operation_fields_preserved() -> None:
    payload = {
        "request_id": "request-123",
        "action": "read",
        "resource_type": "ahu",
        "resource_id": "rooftop-1",
    }

    req = OperationAwareEvaluateRequest(**payload)

    assert req.request_id == "request-123"
    assert req.action == "read"
    assert req.resource_type == "ahu"
    assert req.resource_id == "rooftop-1"
    assert req.context == {}


# ---------------------------------------------------------------------------
# 3. Operation intent
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("intent", list(OperationIntent))
def test_every_operation_intent_value_is_accepted(intent: OperationIntent) -> None:
    req = OperationAwareEvaluateRequest(action="read:ahu", operation_intent=intent.value)

    assert req.operation_intent == intent
    assert req.model_dump()["operation_intent"] == intent.value


def test_unsupported_operation_intent_is_rejected() -> None:
    with pytest.raises(ValidationError):
        OperationAwareEvaluateRequest(action="read:ahu", operation_intent="not_a_real_intent")


# ---------------------------------------------------------------------------
# 4. Each nested context category
# ---------------------------------------------------------------------------


def test_location_context_accepted() -> None:
    req = OperationAwareEvaluateRequest(
        action="read:ahu",
        location={"site_id": "site-1", "building_id": "building-2"},
    )
    assert isinstance(req.location, OperationAwareLocation)
    assert req.location.site_id == "site-1"
    assert req.location.building_id == "building-2"
    assert req.location.zone_id is None
    assert req.location.area_id is None


def test_device_context_accepted() -> None:
    req = OperationAwareEvaluateRequest(
        action="read:ahu",
        device={"device_id": "device-1", "device_class": "controller"},
    )
    assert isinstance(req.device, OperationAwareDevice)
    assert req.device.device_id == "device-1"
    assert req.device.device_class == "controller"


def test_protocol_context_accepted() -> None:
    req = OperationAwareEvaluateRequest(
        action="read:ahu",
        protocol_context={"protocol": "bacnet", "operation": "readProperty"},
    )
    assert isinstance(req.protocol_context, OperationAwareProtocolContext)
    assert req.protocol_context.protocol == "bacnet"
    assert req.protocol_context.operation == "readProperty"


def test_safety_context_accepted() -> None:
    req = OperationAwareEvaluateRequest(
        action="read:ahu",
        safety_context={
            "mode": "interlock-engaged",
            "classification": "high",
            "constraint_ids": ["constraint-1", "constraint-2"],
        },
    )
    assert isinstance(req.safety_context, OperationAwareSafetyContext)
    assert req.safety_context.mode == "interlock-engaged"
    assert req.safety_context.classification == "high"
    assert req.safety_context.constraint_ids == ("constraint-1", "constraint-2")


def test_environment_context_accepted() -> None:
    req = OperationAwareEvaluateRequest(
        action="read:ahu",
        environment_context={
            "mode": "maintenance_mode",
            "condition_ids": ["condition-1"],
        },
    )
    assert isinstance(req.environment_context, OperationAwareEnvironmentContext)
    assert req.environment_context.mode == "maintenance_mode"
    assert req.environment_context.condition_ids == ("condition-1",)


def test_risk_context_accepted() -> None:
    req = OperationAwareEvaluateRequest(
        action="read:ahu",
        risk_context={"classification": "elevated", "score": 0.62},
    )
    assert isinstance(req.risk_context, OperationAwareRiskContext)
    assert req.risk_context.classification == "elevated"
    assert req.risk_context.score == 0.62


def test_identity_evidence_reference_accepted() -> None:
    req = OperationAwareEvaluateRequest(
        action="read:ahu",
        identity_evidence_reference=_identity_evidence_reference_payload(),
    )
    assert isinstance(req.identity_evidence_reference, IdentityEvidenceReference)
    assert req.identity_evidence_reference.reference_id == "identity-evidence-1"
    assert req.identity_evidence_reference.identity_source == "basis-identity"
    assert (
        req.identity_evidence_reference.redaction_classification
        == RedactionClassification.SAFE_TO_EXPOSE
    )


def test_adapter_evidence_reference_accepted() -> None:
    req = OperationAwareEvaluateRequest(
        action="read:ahu",
        adapter_evidence_reference=_adapter_evidence_reference_payload(),
    )
    assert isinstance(req.adapter_evidence_reference, AdapterEvidenceReference)
    assert req.adapter_evidence_reference.reference_id == "adapter-evidence-1"
    assert req.adapter_evidence_reference.adapter_source == "basis-adapters:bacnet"
    assert isinstance(req.adapter_evidence_reference.evidence_digest, EvidenceDigest)


# ---------------------------------------------------------------------------
# 5. Optional absence preservation
# ---------------------------------------------------------------------------


def test_omitted_operation_aware_fields_remain_none_and_excluded_from_dump() -> None:
    req = OperationAwareEvaluateRequest(action="read:ahu")

    dumped = req.model_dump(exclude_none=True)

    for field_name in (
        "operation_intent",
        "location",
        "device",
        "protocol_context",
        "safety_context",
        "environment_context",
        "risk_context",
        "identity_evidence_reference",
        "adapter_evidence_reference",
        "request_id",
        "resource_type",
        "resource_id",
    ):
        assert field_name not in dumped, f"{field_name} should be excluded when None"


# ---------------------------------------------------------------------------
# 6. Unknown-field rejection (gateway-owned / producer-trust / result fields)
# ---------------------------------------------------------------------------


FORBIDDEN_FIELDS = [
    ("subject_id", "operator-1"),
    ("subject_roles", ["operator"]),
    ("subject_attrs", {"department": "facilities"}),
    ("identity_source", "oidc"),
    ("authority_mode", "federated"),
    ("evaluation_time", "2026-07-31T12:00:00Z"),
    ("correlation_id", "corr-1"),
    ("evaluation_status", "completed"),
    ("outcome", "allow"),
    ("failure_reason", "invalid_request"),
    ("disposition", "allow"),
    ("expected_policy_version", "2026.07.31"),
    ("is_trusted_operation_producer", True),
    ("producer_trust_classification", "trusted"),
    ("gateway_http_status", 200),
    ("policy_bundle_id", "bundle-1"),
    ("policy_bundle_version", "1.0.0"),
]


@pytest.mark.parametrize("field_name,field_value", FORBIDDEN_FIELDS)
def test_forbidden_gateway_owned_fields_are_rejected(field_name: str, field_value: object) -> None:
    with pytest.raises(ValidationError):
        OperationAwareEvaluateRequest(action="read", **{field_name: field_value})


def test_expected_policy_version_is_rejected_not_silently_dropped() -> None:
    """§5b: expected_policy_version must fail validation, not be accepted-and-ignored."""
    with pytest.raises(ValidationError) as exc_info:
        OperationAwareEvaluateRequest(action="read", expected_policy_version="2026.07.31")

    assert "expected_policy_version" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 7. Extra arbitrary field rejection (proves general strictness, not a
#    security-specific allowlist)
# ---------------------------------------------------------------------------


def test_arbitrary_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        OperationAwareEvaluateRequest(action="read", unexpected_field="surprise")


# ---------------------------------------------------------------------------
# 7a. Free-form context contract (PR 5, basis-core v0.2.1 correction)
#
# OperationAwareDecisionRequest has no free-form context field to map this
# onto (see basis_gateway.core.operation_aware_evaluator's module
# docstring). Omitted/explicit-empty context remains valid; any non-empty
# value is rejected clearly, rather than accepted here and silently dropped
# at kernel-request construction time.
# ---------------------------------------------------------------------------


def test_omitted_context_defaults_to_empty_dict() -> None:
    req = OperationAwareEvaluateRequest(action="read:ahu")
    assert req.context == {}


def test_explicit_empty_context_is_accepted() -> None:
    req = OperationAwareEvaluateRequest(action="read:ahu", context={})
    assert req.context == {}


def test_non_empty_context_is_rejected() -> None:
    with pytest.raises(ValidationError):
        OperationAwareEvaluateRequest(action="read:ahu", context={"maintenance_ticket": "CHG-123"})


def test_non_empty_context_rejection_identifies_context_field() -> None:
    with pytest.raises(ValidationError) as exc_info:
        OperationAwareEvaluateRequest(action="read:ahu", context={"a": "b"})
    assert "context" in str(exc_info.value)


def test_non_empty_single_key_context_rejected() -> None:
    """Even a single, otherwise-innocuous key is rejected — there is no
    partial-acceptance or best-effort filtering of caller context."""
    with pytest.raises(ValidationError):
        OperationAwareEvaluateRequest(action="read:ahu", context={"note": "ok"})


# ---------------------------------------------------------------------------
# 8. Input mutation
# ---------------------------------------------------------------------------


def test_validation_does_not_mutate_input_dict() -> None:
    payload = {
        "action": "read:ahu",
        "location": {"site_id": "site-1"},
        "context": {},
    }
    original = copy.deepcopy(payload)

    OperationAwareEvaluateRequest(**payload)

    assert payload == original


# ---------------------------------------------------------------------------
# 9. Independent mutable defaults
# ---------------------------------------------------------------------------


def test_context_default_is_independent_across_instances() -> None:
    first = OperationAwareEvaluateRequest(action="read:ahu")
    second = OperationAwareEvaluateRequest(action="read:ahu")

    first.context["leaked"] = "value"

    assert second.context == {}
    assert "leaked" not in second.context


# ---------------------------------------------------------------------------
# 10. No trust decision
# ---------------------------------------------------------------------------


def test_model_exposes_no_producer_trust_field() -> None:
    """The model structurally cannot carry a trust decision.

    Covered two ways: field-set inspection (this test) and unknown-field
    rejection (test_forbidden_gateway_owned_fields_are_rejected, above).
    """
    field_names = set(OperationAwareEvaluateRequest.model_fields.keys())

    assert "is_trusted_operation_producer" not in field_names
    assert "producer_trust_classification" not in field_names


def test_structurally_accepted_producer_context_is_not_labeled_trusted() -> None:
    """Structural acceptance of producer-context fields carries no trust label.

    PR 3 performs shape validation only: the model may accept an
    operation-producer-shaped field (e.g. safety_context) without adding any
    provenance/trust metadata about it. There is no field anywhere on this
    model that records a trust classification for any value supplied.
    """
    req = OperationAwareEvaluateRequest(
        action="read:ahu",
        safety_context={"mode": "interlock-engaged"},
    )

    assert req.safety_context is not None
    dumped = req.model_dump()
    assert "is_trusted_operation_producer" not in dumped
    assert "producer_trust_classification" not in dumped
