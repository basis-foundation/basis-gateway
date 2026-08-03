"""Unit tests for the operation-aware gateway audit-event assembly layer (PR 7).

Covers ``basis_gateway.audit.operation_aware_gateway_events`` in isolation:
``GatewayAuditEvent`` construction/validation, ``assemble_gateway_audit_event``,
safe serialization of ``AuditEvidence``/provenance, the durable-envelope
assembly function, and the three emission helpers (using a capturing writer,
never a mock kernel).

Real, public ``basis-core`` types are used throughout to produce
``OperationAwareEnforcementResult`` fixtures — ``PolicyBundle`` +
``OperationAwareEnforcementPoint.for_bundle(...).evaluate(...)``, exactly the
pattern already established by
``tests/test_operation_aware_endpoint_canonical_scenarios.py`` — never a
hand-constructed kernel result and never an import from
``basis_core.evaluation.*``.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Any

import pytest
from basis_core.decisions import OperationAwareDecisionRequest
from basis_core.enforcement import (
    EnforcementDisposition,
    OperationAwareEnforcementPoint,
    OperationAwareEnforcementResult,
)
from basis_core.policy import PolicyBundle
from pydantic import ValidationError

from basis_gateway.api.operation_aware_schemas import OperationAwareEvaluateRequest
from basis_gateway.audit.operation_aware_gateway_events import (
    AUTHORIZATION_COMPLETED,
    EVIDENCE_MISSING,
    GATEWAY_AUDIT_EVENT_TYPE,
    REASON_MISSING_AUDIT_EVIDENCE,
    GatewayAuditEvent,
    assemble_gateway_audit_event,
    build_operation_aware_audit_detail,
    emit_operation_aware_completed_event,
    emit_operation_aware_missing_evidence_event,
    emit_operation_aware_system_event,
    serialize_audit_evidence,
    serialize_provenance,
)
from basis_gateway.auth.operation_producer import (
    OperationProducerTrust,
    classify_operation_producer,
)
from basis_gateway.auth.subject_mapper import IdentityContext, NormalizedSubject
from basis_gateway.core.operation_aware_composition import (
    ComposedOperationAwareInput,
    ProvenanceClassification,
    compose_operation_aware_input,
)

_FIXED_TIME = datetime(2026, 8, 1, 12, tzinfo=timezone.utc)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _build_result(
    rules: list[dict],
    action: str,
    *,
    resource_id: str | None = None,
    scope: dict | None = None,
    bundle_id: str = "test-bundle",
    bundle_version: str = "1.0.0",
    request_id: str = "req-1",
    subject_id: str = "user1",
    trace_id: str = "trace-1",
    evidence_id: str = "evidence-1",
) -> OperationAwareEnforcementResult:
    """Build a real ``OperationAwareEnforcementResult`` through the public
    ``OperationAwareEnforcementPoint.for_bundle()`` + ``evaluate()`` path —
    never a hand-constructed kernel result."""
    kwargs: dict[str, Any] = {
        "bundle_id": bundle_id,
        "bundle_version": bundle_version,
        "schema_version": "1.0.0",
        "policy_owner": "test-owner",
        "rules": rules,
    }
    if scope is not None:
        kwargs["scope"] = scope
    bundle = PolicyBundle(**kwargs)
    enforcement_point = OperationAwareEnforcementPoint.for_bundle(bundle)
    request = OperationAwareDecisionRequest(
        request_id=request_id,
        subject_id=subject_id,
        action=action,
        resource=resource_id,
        evaluation_time=_FIXED_TIME,
    )
    return enforcement_point.evaluate(
        request=request,
        trace_id=trace_id,
        evidence_id=evidence_id,
        recorded_at=_FIXED_TIME,
    )


def _allow_result() -> OperationAwareEnforcementResult:
    return _build_result(
        [{"rule_id": "allow-read", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
        "read:ahu",
    )


def _explicit_deny_result() -> OperationAwareEnforcementResult:
    return _build_result(
        [
            {"rule_id": "allow-write", "effect": "allow", "match": {"actions": ["write:ahu"]}},
            {"rule_id": "deny-write", "effect": "deny", "match": {"actions": ["write:ahu"]}},
        ],
        "write:ahu",
    )


def _default_deny_result() -> OperationAwareEnforcementResult:
    return _build_result(
        [{"rule_id": "allow-read", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
        "write:ahu",
    )


def _not_applicable_result() -> OperationAwareEnforcementResult:
    return _build_result(
        [{"rule_id": "allow-read", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
        "read:ahu",
        scope={"actions": ["read:other_domain"]},
    )


def _condition_evaluation_error_result() -> OperationAwareEnforcementResult:
    return _build_result(
        [
            {
                "rule_id": "cond-error-rule",
                "effect": "allow",
                "match": {"actions": ["read:ahu"]},
                "conditions": [
                    {
                        "condition_id": "c1",
                        "field_path": "subject_id",
                        "operator": "not_a_real_operator",
                        "expected_value": "irrelevant",
                    }
                ],
            }
        ],
        "read:ahu",
    )


def _subject(subject_id: str = "human-1") -> NormalizedSubject:
    return NormalizedSubject(
        subject_id=subject_id, name=subject_id, roles=("viewer",), attributes={}
    )


def _identity_context(subject_id: str = "human-1") -> IdentityContext:
    return IdentityContext(
        issuer="https://issuer.example.com", subject_id=subject_id, claims={"sub": subject_id}
    )


def _trust(subject_id: str = "human-1", *, trusted: bool = False) -> OperationProducerTrust:
    allowlist = frozenset({subject_id}) if trusted else frozenset()
    return classify_operation_producer(_subject(subject_id), allowlist)


def _composed(
    *,
    subject_id: str = "human-1",
    correlation_id: str = "corr-1",
    trusted: bool = False,
) -> ComposedOperationAwareInput:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    return compose_operation_aware_input(
        request,
        subject=_subject(subject_id),
        identity_context=_identity_context(subject_id),
        producer_trust=_trust(subject_id, trusted=trusted),
        correlation_id=correlation_id,
        clock=lambda: _FIXED_TIME,
    )


class _CapturingWriter:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def write(self, event: Any) -> None:
        self.events.append(event)


class _AlwaysRaisingWriter:
    def write(self, event: Any) -> None:
        raise OSError("audit sink down")


# ---------------------------------------------------------------------------
# GatewayAuditEvent construction/validation
# ---------------------------------------------------------------------------


def test_gateway_audit_event_accepts_completed_allow() -> None:
    event = GatewayAuditEvent(
        event_type=GATEWAY_AUDIT_EVENT_TYPE,
        request_id="req-1",
        evaluation_status="completed",
        outcome="allow",
        failure_reason=None,
        audit_evidence_id="evidence-1",
        enforcement_action="allow",
    )
    assert event.to_dict() == {
        "event_type": GATEWAY_AUDIT_EVENT_TYPE,
        "request_id": "req-1",
        "evaluation_status": "completed",
        "outcome": "allow",
        "failure_reason": None,
        "audit_evidence_id": "evidence-1",
        "enforcement_action": "allow",
    }


def test_gateway_audit_event_accepts_completed_not_applicable_with_deny_enforcement() -> None:
    """§9's central invariant at the assembly layer: NOT_APPLICABLE outcome
    coexists with deny enforcement_action without collapsing."""
    event = GatewayAuditEvent(
        event_type=GATEWAY_AUDIT_EVENT_TYPE,
        request_id="req-1",
        evaluation_status="completed",
        outcome="not_applicable",
        failure_reason=None,
        audit_evidence_id="evidence-1",
        enforcement_action="deny",
    )
    assert event.outcome == "not_applicable"
    assert event.enforcement_action == "deny"


@pytest.mark.parametrize(
    "reason",
    [
        "invalid_request",
        "unsupported_schema_version",
        "invalid_policy_bundle",
        "policy_validation_failure",
        "condition_evaluation_error",
        "internal_evaluation_error",
    ],
)
def test_gateway_audit_event_accepts_every_governed_failure_reason(reason: str) -> None:
    event = GatewayAuditEvent(
        event_type=GATEWAY_AUDIT_EVENT_TYPE,
        request_id="req-1",
        evaluation_status="failed",
        outcome=None,
        failure_reason=reason,
        audit_evidence_id="evidence-1",
        enforcement_action="deny",
    )
    assert event.outcome is None
    assert event.failure_reason == reason
    assert event.enforcement_action == "deny"


@pytest.mark.parametrize(
    "kwargs",
    [
        # completed but outcome missing
        {"evaluation_status": "completed", "outcome": None, "failure_reason": None},
        # completed but failure_reason present
        {"evaluation_status": "completed", "outcome": "allow", "failure_reason": "invalid_request"},
        # failed but outcome present
        {"evaluation_status": "failed", "outcome": "allow", "failure_reason": "invalid_request"},
        # failed but failure_reason missing
        {"evaluation_status": "failed", "outcome": None, "failure_reason": None},
        # unrecognized evaluation_status
        {"evaluation_status": "bogus", "outcome": None, "failure_reason": None},
    ],
)
def test_gateway_audit_event_rejects_contradictory_evaluation_state(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        GatewayAuditEvent(
            event_type=GATEWAY_AUDIT_EVENT_TYPE,
            request_id="req-1",
            audit_evidence_id="evidence-1",
            enforcement_action="deny",
            **kwargs,
        )


def test_gateway_audit_event_rejects_wrong_event_type() -> None:
    with pytest.raises(ValueError):
        GatewayAuditEvent(
            event_type="something_else",
            request_id="req-1",
            evaluation_status="completed",
            outcome="allow",
            failure_reason=None,
            audit_evidence_id="evidence-1",
            enforcement_action="allow",
        )


def test_gateway_audit_event_rejects_empty_request_id() -> None:
    with pytest.raises(ValueError):
        GatewayAuditEvent(
            event_type=GATEWAY_AUDIT_EVENT_TYPE,
            request_id="   ",
            evaluation_status="completed",
            outcome="allow",
            failure_reason=None,
            audit_evidence_id="evidence-1",
            enforcement_action="allow",
        )


def test_gateway_audit_event_rejects_empty_audit_evidence_id() -> None:
    with pytest.raises(ValueError):
        GatewayAuditEvent(
            event_type=GATEWAY_AUDIT_EVENT_TYPE,
            request_id="req-1",
            evaluation_status="completed",
            outcome="allow",
            failure_reason=None,
            audit_evidence_id="",
            enforcement_action="allow",
        )


def test_gateway_audit_event_rejects_invalid_enforcement_action() -> None:
    with pytest.raises(ValueError):
        GatewayAuditEvent(
            event_type=GATEWAY_AUDIT_EVENT_TYPE,
            request_id="req-1",
            evaluation_status="completed",
            outcome="allow",
            failure_reason=None,
            audit_evidence_id="evidence-1",
            enforcement_action="maybe",
        )


def test_gateway_audit_event_is_frozen() -> None:
    event = GatewayAuditEvent(
        event_type=GATEWAY_AUDIT_EVENT_TYPE,
        request_id="req-1",
        evaluation_status="completed",
        outcome="allow",
        failure_reason=None,
        audit_evidence_id="evidence-1",
        enforcement_action="allow",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.outcome = "deny"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# assemble_gateway_audit_event
# ---------------------------------------------------------------------------


def test_assemble_completed_allow() -> None:
    result = _allow_result()
    event = assemble_gateway_audit_event(result)
    assert event is not None
    assert event.evaluation_status == "completed"
    assert event.outcome == "allow"
    assert event.failure_reason is None
    assert event.enforcement_action == EnforcementDisposition.ALLOW.value == "allow"
    assert event.audit_evidence_id == result.audit_evidence.evidence_id
    assert event.request_id == result.response.request_id


def test_assemble_explicit_deny_preserves_matched_rules_on_evidence() -> None:
    """``_explicit_deny_result()``'s bundle declares ``allow-write`` before
    ``deny-write``, both matching ``write:ahu``; the kernel's own governed
    sequence is therefore ``["allow-write", "deny-write"]`` (declaration
    order, deny taking precedence for the outcome without dropping the
    allow rule from the evidence trail). Assembly/serialization must not
    reorder, sort, or drop entries from this real, previously-observed
    sequence — asserting against a hand-copied expected list (not the field
    compared to itself) so a reordering regression in either
    ``assemble_gateway_audit_event`` or ``serialize_audit_evidence`` fails
    this test.
    """
    result = _explicit_deny_result()
    event = assemble_gateway_audit_event(result)
    assert event is not None
    assert event.outcome == "deny"
    assert event.enforcement_action == "deny"

    expected_matched_rule_ids = ["allow-write", "deny-write"]
    assert list(result.audit_evidence.matched_rule_ids) == expected_matched_rule_ids

    # The same governed order must survive safe serialization unchanged.
    serialized = serialize_audit_evidence(result.audit_evidence)
    assert serialized["matched_rule_ids"] == expected_matched_rule_ids


def test_assemble_default_deny() -> None:
    result = _default_deny_result()
    event = assemble_gateway_audit_event(result)
    assert event is not None
    assert event.evaluation_status == "completed"
    assert event.outcome == "deny"
    assert event.enforcement_action == "deny"


def test_assemble_not_applicable_outcome_preserved_not_collapsed_to_deny() -> None:
    result = _not_applicable_result()
    event = assemble_gateway_audit_event(result)
    assert event is not None
    assert event.outcome == "not_applicable"
    assert event.outcome != "deny"
    # Only enforcement_action collapses to deny — outcome itself never does.
    assert event.enforcement_action == "deny"


def test_assemble_failed_condition_evaluation_error() -> None:
    result = _condition_evaluation_error_result()
    event = assemble_gateway_audit_event(result)
    assert event is not None
    assert event.evaluation_status == "failed"
    assert event.outcome is None
    assert event.failure_reason == "condition_evaluation_error"
    assert event.enforcement_action == "deny"


def test_assemble_enforcement_action_copied_from_disposition_not_recomputed() -> None:
    """Even though disposition and outcome agree in ordinary cases, assembly
    must read result.disposition.value directly — proven by checking every
    scenario's enforcement_action equals disposition.value exactly."""
    for result in (
        _allow_result(),
        _explicit_deny_result(),
        _default_deny_result(),
        _not_applicable_result(),
        _condition_evaluation_error_result(),
    ):
        event = assemble_gateway_audit_event(result)
        assert event is not None
        assert event.enforcement_action == result.disposition.value


def test_assemble_returns_none_when_audit_evidence_missing() -> None:
    real_result = _allow_result()
    missing_evidence_result = OperationAwareEnforcementResult(
        response=real_result.response,
        audit_evidence=None,
        disposition=real_result.disposition,
    )
    assert assemble_gateway_audit_event(missing_evidence_result) is None


def test_assemble_request_id_agreement_with_response() -> None:
    result = _build_result(
        [{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
        "read:ahu",
        request_id="custom-request-id",
    )
    event = assemble_gateway_audit_event(result)
    assert event is not None
    assert event.request_id == "custom-request-id" == result.response.request_id


def test_assemble_bundle_identity_reachable_via_evidence() -> None:
    result = _build_result(
        [{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
        "read:ahu",
        bundle_id="bundle-xyz",
        bundle_version="2.3.4",
    )
    assert result.audit_evidence.bundle_id == "bundle-xyz"
    assert result.audit_evidence.bundle_version == "2.3.4"


# ---------------------------------------------------------------------------
# Safe serialization
# ---------------------------------------------------------------------------


def test_serialize_audit_evidence_is_json_safe_and_deterministic() -> None:
    result = _allow_result()
    evidence = result.audit_evidence
    serialized = serialize_audit_evidence(evidence)

    assert serialized["evidence_id"] == evidence.evidence_id
    assert serialized["evaluation_status"] == "completed"
    assert serialized["outcome"] == "allow"
    assert serialized["failure_reason"] is None
    assert isinstance(serialized["recorded_at"], str)
    assert serialized["matched_rule_ids"] == list(evidence.matched_rule_ids)

    # Deterministic: calling twice yields an equal (not just similar) dict.
    assert serialize_audit_evidence(evidence) == serialized


def test_serialize_audit_evidence_does_not_mutate_source() -> None:
    result = _allow_result()
    evidence = result.audit_evidence
    before = evidence.model_dump(mode="json")
    serialize_audit_evidence(evidence)
    after = evidence.model_dump(mode="json")
    assert before == after
    # AuditEvidence is itself frozen; attempting to set an attribute raises.
    with pytest.raises(ValidationError):
        evidence.evidence_id = "mutated"  # type: ignore[misc]


def test_serialize_audit_evidence_preserves_failed_nullable_fields() -> None:
    result = _condition_evaluation_error_result()
    serialized = serialize_audit_evidence(result.audit_evidence)
    assert "outcome" in serialized
    assert serialized["outcome"] is None
    assert serialized["failure_reason"] == "condition_evaluation_error"


def test_serialize_provenance_preserves_classifications() -> None:
    provenance = {
        "authorization_subject_id": ProvenanceClassification.VERIFIED,
        "operation_producer_subject_id": ProvenanceClassification.TRUSTED_PRODUCER_ASSERTED,
        "action": ProvenanceClassification.GATEWAY_DERIVED,
        "location": ProvenanceClassification.UNAVAILABLE,
    }
    serialized = serialize_provenance(provenance)
    assert serialized == {
        "authorization_subject_id": "verified",
        "operation_producer_subject_id": "trusted_producer_asserted",
        "action": "gateway_derived",
        "location": "unavailable",
    }


def test_serialize_provenance_from_real_composition_producer_assertion_stays_asserted() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu", operation_intent="read_only")
    real_composed = compose_operation_aware_input(
        request,
        subject=_subject("adapter-1"),
        identity_context=_identity_context("adapter-1"),
        producer_trust=_trust("adapter-1", trusted=True),
        correlation_id="corr-1",
        clock=lambda: _FIXED_TIME,
    )
    serialized = serialize_provenance(real_composed.provenance)
    assert serialized["operation_intent"] == "trusted_producer_asserted"
    # No resource_type was supplied, so no action composition occurred —
    # action passes through as the caller's own untrusted assertion (gateway
    # composition only happens when a bare verb + resource_type triggers it;
    # see the gateway_derived case covered separately below).
    assert serialized["action"] == "untrusted_caller_asserted"
    # Missing optional context stays unavailable — never upgraded.
    assert serialized["location"] == "unavailable"


def test_serialize_provenance_gateway_derived_when_action_is_composed() -> None:
    request = OperationAwareEvaluateRequest(action="read", resource_type="ahu")
    real_composed = compose_operation_aware_input(
        request,
        subject=_subject("human-1"),
        identity_context=_identity_context("human-1"),
        producer_trust=_trust("human-1", trusted=False),
        correlation_id="corr-1",
        clock=lambda: _FIXED_TIME,
    )
    serialized = serialize_provenance(real_composed.provenance)
    assert serialized["action"] == "gateway_derived"


def test_serialize_provenance_does_not_mutate_source_mapping() -> None:
    composed = _composed()
    original = dict(composed.provenance)
    serialize_provenance(composed.provenance)
    assert dict(composed.provenance) == original


# ---------------------------------------------------------------------------
# Durable envelope assembly
# ---------------------------------------------------------------------------


def test_build_operation_aware_audit_detail_keeps_artifacts_separate() -> None:
    result = _allow_result()
    event = assemble_gateway_audit_event(result)
    assert event is not None
    detail = build_operation_aware_audit_detail(
        gateway_audit_event=event,
        audit_evidence=result.audit_evidence,
        http_method="POST",
        request_path="/v1/evaluate/operation-aware",
        http_status=200,
        operation_producer_subject_id=None,
        operation_producer_trust_status="not_configured",
        operation_producer_trust_source="not_configured",
        provenance={},
    )
    assert "gateway_audit_event" in detail
    assert "audit_evidence" in detail
    assert detail["gateway_audit_event"] == event.to_dict()
    assert detail["audit_evidence"]["evidence_id"] == result.audit_evidence.evidence_id
    # Linkage: the reference and the artifact it refers to always agree.
    assert (
        detail["gateway_audit_event"]["audit_evidence_id"]
        == detail["audit_evidence"]["evidence_id"]
    )
    # audit_evidence is beside gateway_audit_event, never nested inside it.
    assert "audit_evidence" not in detail["gateway_audit_event"]
    assert detail["enforcement_action"] == "allow"
    assert detail["http_status"] == 200


# ---------------------------------------------------------------------------
# Emission helpers
# ---------------------------------------------------------------------------


def test_emit_completed_event_writes_exactly_one_record() -> None:
    writer = _CapturingWriter()
    result = _allow_result()
    composed = _composed()
    emit_operation_aware_completed_event(writer, result=result, composed=composed, http_status=200)
    assert len(writer.events) == 1
    event = writer.events[0]
    assert event.action == AUTHORIZATION_COMPLETED
    assert event.correlation_id == composed.correlation_id
    assert event.subject_id == composed.authorization_subject.subject_id
    assert (
        event.detail["gateway_audit_event"]["audit_evidence_id"]
        == result.audit_evidence.evidence_id
    )
    assert event.detail["audit_evidence"]["evidence_id"] == result.audit_evidence.evidence_id
    assert event.detail["http_status"] == 200


def test_emit_completed_event_noop_on_none_writer() -> None:
    result = _allow_result()
    composed = _composed()
    # Must not raise.
    emit_operation_aware_completed_event(None, result=result, composed=composed, http_status=200)


def test_emit_completed_event_routes_missing_evidence_to_missing_evidence_path() -> None:
    writer = _CapturingWriter()
    real_result = _allow_result()
    missing_evidence_result = OperationAwareEnforcementResult(
        response=real_result.response,
        audit_evidence=None,
        disposition=real_result.disposition,
    )
    composed = _composed()
    emit_operation_aware_completed_event(
        writer, result=missing_evidence_result, composed=composed, http_status=200
    )
    assert len(writer.events) == 1
    event = writer.events[0]
    assert event.action == EVIDENCE_MISSING
    assert event.reason == REASON_MISSING_AUDIT_EVIDENCE
    assert "gateway_audit_event" not in event.detail
    assert "audit_evidence" not in event.detail


def test_emit_missing_evidence_event_writes_no_gateway_audit_event_or_evidence() -> None:
    writer = _CapturingWriter()
    composed = _composed()
    emit_operation_aware_missing_evidence_event(writer, composed=composed, http_status=500)
    assert len(writer.events) == 1
    event = writer.events[0]
    assert event.action == EVIDENCE_MISSING
    assert event.reason == REASON_MISSING_AUDIT_EVIDENCE
    assert "gateway_audit_event" not in event.detail
    assert "audit_evidence" not in event.detail
    assert event.correlation_id == composed.correlation_id


def test_emit_system_event_includes_http_status() -> None:
    writer = _CapturingWriter()
    emit_operation_aware_system_event(
        writer,
        action="gateway.operation_aware_validation_failed",
        correlation_id="corr-x",
        reason="malformed_request_body",
        http_status=400,
    )
    assert len(writer.events) == 1
    event = writer.events[0]
    assert event.detail["http_status"] == 400
    assert event.reason == "malformed_request_body"


def test_emit_system_event_noop_on_none_writer() -> None:
    emit_operation_aware_system_event(None, action="gateway.operation_aware_validation_failed")


def test_emit_write_failure_is_caught_and_never_propagates() -> None:
    writer = _AlwaysRaisingWriter()
    result = _allow_result()
    composed = _composed()
    # Must not raise despite the inner writer always failing.
    emit_operation_aware_completed_event(writer, result=result, composed=composed, http_status=200)
    emit_operation_aware_missing_evidence_event(writer, composed=composed, http_status=500)
    emit_operation_aware_system_event(writer, action="gateway.operation_aware_validation_failed")
