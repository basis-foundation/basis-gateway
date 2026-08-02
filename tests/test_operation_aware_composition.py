"""Tests for the operation-aware trust and composition boundary (PR 4).

Covers ``basis_gateway.core.operation_aware_composition`` — see
``docs/implementation/operation-aware-gateway-integration-plan.md`` §5, §6,
§7, §16 (PR 4), §17 ("Composition", "Operation-producer trust"). Uses real
gateway and public ``basis-core`` types throughout; no kernel evaluator
(``OperationAwareEnforcementPoint``, ``PolicyBundle``) is imported,
constructed, or invoked anywhere in this module — composition is tested in
complete isolation from kernel evaluation, per this PR's scope.
"""

from __future__ import annotations

import copy
import inspect
from collections.abc import Callable
from datetime import datetime, timezone

import pytest
from basis_core.decisions import OperationIntent
from basis_core.domain import RedactionClassification

from basis_gateway.api.operation_aware_schemas import OperationAwareEvaluateRequest
from basis_gateway.auth.operation_producer import (
    OperationProducerTrust,
    OperationProducerTrustSource,
    OperationProducerTrustStatus,
    classify_operation_producer,
)
from basis_gateway.auth.subject_mapper import IdentityContext, NormalizedSubject
from basis_gateway.core.actions import RESERVED_CONTEXT_PREFIX, ActionCompositionError
from basis_gateway.core.operation_aware_composition import (
    OPERATION_PRODUCER_ONLY_FIELDS,
    ComposedOperationAwareInput,
    CompositionInternalError,
    ProvenanceClassification,
    ReservedContextKeyError,
    UntrustedOperationProducerContextError,
    compose_operation_aware_input,
    present_operation_producer_only_fields,
)
from basis_gateway.core.resources import ResourceCompositionError

# ---------------------------------------------------------------------------
# Shared fixtures
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


# One representative, structurally valid payload per producer-only field.
PRODUCER_ONLY_FIELD_PAYLOADS: dict[str, object] = {
    "operation_intent": OperationIntent.READ_ONLY.value,
    "location": {"site_id": "site-1"},
    "device": {"device_id": "device-1", "device_class": "controller"},
    "protocol_context": {"protocol": "bacnet", "operation": "readProperty"},
    "safety_context": {"mode": "interlock-engaged"},
    "environment_context": {"mode": "maintenance_mode"},
    "risk_context": {"classification": "elevated"},
    "identity_evidence_reference": _identity_evidence_reference_payload(),
    "adapter_evidence_reference": _adapter_evidence_reference_payload(),
}

assert set(PRODUCER_ONLY_FIELD_PAYLOADS) == set(OPERATION_PRODUCER_ONLY_FIELDS)


def _subject(subject_id: str = "human-1") -> NormalizedSubject:
    return NormalizedSubject(
        subject_id=subject_id, name=subject_id, roles=("viewer",), attributes={}
    )


def _identity_context(subject_id: str = "human-1") -> IdentityContext:
    return IdentityContext(
        issuer="https://issuer.example.com",
        subject_id=subject_id,
        claims={"sub": subject_id},
    )


def _trusted(subject_id: str = "adapter-1") -> OperationProducerTrust:
    return classify_operation_producer(_subject(subject_id), frozenset({subject_id}))


def _untrusted(subject_id: str = "human-1") -> OperationProducerTrust:
    return classify_operation_producer(_subject(subject_id), frozenset())


def _fixed_clock(value: datetime) -> Callable[[], datetime]:
    return lambda: value


_FIXED_TIME = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


def _compose(
    request: OperationAwareEvaluateRequest,
    *,
    subject: NormalizedSubject | None = None,
    identity_context: IdentityContext | None = None,
    producer_trust: OperationProducerTrust | None = None,
    correlation_id: str = "corr-1",
    clock=None,
) -> ComposedOperationAwareInput:
    return compose_operation_aware_input(
        request,
        subject=subject or _subject(),
        identity_context=identity_context or _identity_context(),
        producer_trust=producer_trust if producer_trust is not None else _untrusted(),
        correlation_id=correlation_id,
        clock=clock or _fixed_clock(_FIXED_TIME),
    )


# ---------------------------------------------------------------------------
# 1. Untrusted producer-context rejection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field_name", OPERATION_PRODUCER_ONLY_FIELDS)
def test_untrusted_caller_rejected_for_each_producer_only_field(field_name: str) -> None:
    payload = {"action": "read:ahu", field_name: PRODUCER_ONLY_FIELD_PAYLOADS[field_name]}
    request = OperationAwareEvaluateRequest(**payload)

    with pytest.raises(UntrustedOperationProducerContextError) as exc_info:
        _compose(request, producer_trust=_untrusted())

    assert exc_info.value.offending_fields == (field_name,)
    # The field name appears in the error text; the exception carries no
    # composed result at all (raised before any ComposedOperationAwareInput
    # is constructed), so there is nothing else to inspect.
    assert field_name in str(exc_info.value)


def test_untrusted_caller_rejected_for_multiple_fields_deterministic_order() -> None:
    payload = {
        "action": "read:ahu",
        "risk_context": PRODUCER_ONLY_FIELD_PAYLOADS["risk_context"],
        "location": PRODUCER_ONLY_FIELD_PAYLOADS["location"],
        "operation_intent": PRODUCER_ONLY_FIELD_PAYLOADS["operation_intent"],
    }
    request = OperationAwareEvaluateRequest(**payload)

    with pytest.raises(UntrustedOperationProducerContextError) as exc_info:
        _compose(request, producer_trust=_untrusted())

    # Deterministic: OPERATION_PRODUCER_ONLY_FIELDS order, not payload order.
    assert exc_info.value.offending_fields == ("operation_intent", "location", "risk_context")


def test_untrusted_rejection_does_not_leak_field_values() -> None:
    request = OperationAwareEvaluateRequest(
        action="read:ahu",
        location={"site_id": "top-secret-site"},
    )
    with pytest.raises(UntrustedOperationProducerContextError) as exc_info:
        _compose(request, producer_trust=_untrusted())

    assert "top-secret-site" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 2. Untrusted caller without producer-only context
# ---------------------------------------------------------------------------


def test_untrusted_caller_can_compose_existing_normalized_shape() -> None:
    request = OperationAwareEvaluateRequest(
        action="read",
        resource_type="ahu",
        resource_id="rooftop-1",
        request_id="req-1",
    )
    composed = _compose(request, producer_trust=_untrusted())

    assert composed.action == "read:ahu"
    assert composed.resource_id == "ahu:rooftop-1"
    assert composed.operation_producer_trust.operation_producer_subject_id is None
    assert composed.operation_producer_trust.status is OperationProducerTrustStatus.UNTRUSTED


# ---------------------------------------------------------------------------
# 3. Trusted producer context
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field_name", OPERATION_PRODUCER_ONLY_FIELDS)
def test_trusted_producer_field_passes_through(field_name: str) -> None:
    payload = {"action": "read:ahu", field_name: PRODUCER_ONLY_FIELD_PAYLOADS[field_name]}
    request = OperationAwareEvaluateRequest(**payload)

    composed = _compose(
        request,
        subject=_subject("adapter-1"),
        identity_context=_identity_context("adapter-1"),
        producer_trust=_trusted("adapter-1"),
    )

    composed_value = getattr(composed, field_name)
    request_value = getattr(request, field_name)
    assert composed_value == request_value
    assert composed.provenance[field_name] is ProvenanceClassification.TRUSTED_PRODUCER_ASSERTED
    # Never upgraded to VERIFIED.
    assert composed.provenance[field_name] is not ProvenanceClassification.VERIFIED


def test_trusted_producer_and_authorization_subject_identity_distinct() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu", location={"site_id": "site-1"})
    trust = _trusted("adapter-1")
    composed = _compose(
        request,
        subject=_subject("adapter-1"),
        identity_context=_identity_context("adapter-1"),
        producer_trust=trust,
    )

    assert composed.operation_producer_trust.authorization_subject_id == "adapter-1"
    assert composed.operation_producer_trust.operation_producer_subject_id == "adapter-1"
    # Still two separately named facts, not a single boolean.
    assert hasattr(composed.operation_producer_trust, "authorization_subject_id")
    assert hasattr(composed.operation_producer_trust, "operation_producer_subject_id")


# ---------------------------------------------------------------------------
# 4. Subject versus producer identity
# ---------------------------------------------------------------------------


def test_trusted_subject_and_producer_ids_equal_but_separate_fields() -> None:
    trust = _trusted("adapter-1")
    assert trust.authorization_subject_id == "adapter-1"
    assert trust.operation_producer_subject_id == "adapter-1"


def test_untrusted_subject_present_producer_absent() -> None:
    trust = _untrusted("human-1")
    assert trust.authorization_subject_id == "human-1"
    assert trust.operation_producer_subject_id is None


def test_trust_is_not_a_property_of_generic_boolean() -> None:
    """No field named is_trusted_caller anywhere on the trust result."""
    import dataclasses

    trust = _trusted("adapter-1")
    field_names = {f.name for f in dataclasses.fields(trust)}
    assert "is_trusted_caller" not in field_names


# ---------------------------------------------------------------------------
# 5. Action composition
# ---------------------------------------------------------------------------


def test_action_composite_pass_through() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    composed = _compose(request)
    assert composed.action == "read:ahu"
    assert composed.provenance["action"] is ProvenanceClassification.UNTRUSTED_CALLER_ASSERTED


def test_action_bare_plus_resource_type_composed() -> None:
    request = OperationAwareEvaluateRequest(action="read", resource_type="ahu")
    composed = _compose(request)
    assert composed.action == "read:ahu"
    assert composed.provenance["action"] is ProvenanceClassification.GATEWAY_DERIVED
    assert composed.context[f"{RESERVED_CONTEXT_PREFIX}action_composed"] == "true"


def test_action_bare_without_resource_type_rejected() -> None:
    request = OperationAwareEvaluateRequest(action="read")
    with pytest.raises(ActionCompositionError):
        _compose(request)


def test_action_composite_plus_resource_type_rejected() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu", resource_type="ahu")
    with pytest.raises(ActionCompositionError):
        _compose(request)


def test_action_composition_evidence_preserved_in_context() -> None:
    request = OperationAwareEvaluateRequest(action="read", resource_type="ahu")
    composed = _compose(request)
    assert composed.context[f"{RESERVED_CONTEXT_PREFIX}original_action"] == "read"
    assert composed.context[f"{RESERVED_CONTEXT_PREFIX}composed_action"] == "read:ahu"


# ---------------------------------------------------------------------------
# 6. Resource composition
# ---------------------------------------------------------------------------


def test_resource_typed_pass_through() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu", resource_id="ahu:rooftop-1")
    composed = _compose(request)
    assert composed.resource_id == "ahu:rooftop-1"
    assert composed.provenance["resource_id"] is ProvenanceClassification.UNTRUSTED_CALLER_ASSERTED


def test_resource_local_plus_type_composed() -> None:
    request = OperationAwareEvaluateRequest(
        action="read", resource_type="ahu", resource_id="rooftop-1"
    )
    composed = _compose(request)
    assert composed.resource_id == "ahu:rooftop-1"
    assert composed.provenance["resource_id"] is ProvenanceClassification.GATEWAY_DERIVED
    assert composed.context[f"{RESERVED_CONTEXT_PREFIX}resource_composed"] == "true"


def test_resource_typed_plus_resource_type_rejected() -> None:
    """A typed resource_id combined with resource_type is rejected.

    Uses a bare-verb action (``"read"``) so action composition succeeds
    (``read`` + ``resource_type="ahu"`` -> ``"read:ahu"``) and the call
    reaches resource composition, which must then reject the already-typed
    ``resource_id`` supplied alongside a redundant ``resource_type`` — this
    proves the operation-aware composition call site reaches and preserves
    the existing ``compose_resource_id()`` rejection, not merely the
    earlier, unrelated composite-action conflict.
    """
    request = OperationAwareEvaluateRequest(
        action="read",
        resource_type="ahu",
        resource_id="ahu:rooftop-1",
    )

    with pytest.raises(ResourceCompositionError):
        _compose(request)


def test_resource_local_without_resource_type_rejected() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu", resource_id="rooftop-1")
    with pytest.raises(ResourceCompositionError):
        _compose(request)


def test_resource_absent_accepted() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    composed = _compose(request)
    assert composed.resource_id is None
    assert composed.provenance["resource_id"] is ProvenanceClassification.UNAVAILABLE


def test_resource_composition_evidence_preserved() -> None:
    request = OperationAwareEvaluateRequest(
        action="read", resource_type="ahu", resource_id="rooftop-1"
    )
    composed = _compose(request)
    assert composed.context[f"{RESERVED_CONTEXT_PREFIX}original_resource_id"] == "rooftop-1"
    assert composed.context[f"{RESERVED_CONTEXT_PREFIX}composed_resource_id"] == "ahu:rooftop-1"


# ---------------------------------------------------------------------------
# 7. Reserved context collision
#
# PR 5 (basis-core v0.2.1 correction): OperationAwareEvaluateRequest.context
# is now validated empty-only (see test_operation_aware_input_model.py's
# test_non_empty_context_is_rejected) — an ordinary caller can never reach
# compose_operation_aware_input() with a non-empty (reserved or otherwise)
# context at all; PR 3's own validator rejects it first. The reserved-key
# collision check in compose_operation_aware_input() therefore becomes an
# internal defense-in-depth invariant rather than a caller-reachable path.
# These tests exercise that invariant directly against a request object
# built via model_construct() (bypassing PR 3's validator on purpose,
# mirroring the identity-consistency invariant tests below) to prove the
# defense still holds even if some future caller ever reached this function
# with such a request.
# ---------------------------------------------------------------------------


def test_reserved_context_key_rejected() -> None:
    request = OperationAwareEvaluateRequest.model_construct(
        action="read:ahu", context={f"{RESERVED_CONTEXT_PREFIX}forged": "true"}
    )
    with pytest.raises(ReservedContextKeyError) as exc_info:
        _compose(request)
    assert f"{RESERVED_CONTEXT_PREFIX}forged" in exc_info.value.offending_keys


def test_reserved_context_key_not_silently_overwritten() -> None:
    """A rejected reserved-key request never reaches a composed result at all."""
    request = OperationAwareEvaluateRequest.model_construct(
        action="read:ahu", context={f"{RESERVED_CONTEXT_PREFIX}original_action": "forged"}
    )
    with pytest.raises(ReservedContextKeyError):
        _compose(request)


def test_ordinary_caller_cannot_reach_reserved_context_collision_at_all() -> None:
    """The validated-construction path (no model_construct bypass) can never
    even produce a non-empty context — PR 3's own validator rejects it
    before compose_operation_aware_input() is ever called."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        OperationAwareEvaluateRequest(
            action="read:ahu", context={f"{RESERVED_CONTEXT_PREFIX}forged": "true"}
        )


# ---------------------------------------------------------------------------
# 8. Request and correlation identifiers
# ---------------------------------------------------------------------------


def test_caller_supplied_request_id_preserved() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu", request_id="caller-req-1")
    composed = _compose(request, correlation_id="corr-9")
    assert composed.request_id == "caller-req-1"
    assert composed.provenance["request_id"] is ProvenanceClassification.UNTRUSTED_CALLER_ASSERTED


def test_absent_request_id_falls_back_to_correlation_id() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    composed = _compose(request, correlation_id="corr-9")
    assert composed.request_id == "corr-9"
    assert composed.provenance["request_id"] is ProvenanceClassification.GATEWAY_DERIVED


def test_correlation_id_preserved_unchanged() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    composed = _compose(request, correlation_id="corr-abc-123")
    assert composed.correlation_id == "corr-abc-123"
    assert composed.provenance["correlation_id"] is ProvenanceClassification.GATEWAY_DERIVED


@pytest.mark.parametrize("bad_correlation_id", ["", "   ", "\t\n"])
def test_empty_correlation_id_rejected(bad_correlation_id: str) -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    with pytest.raises(CompositionInternalError):
        _compose(request, correlation_id=bad_correlation_id)


def test_request_model_has_no_correlation_id_field() -> None:
    """The caller cannot supply correlation_id through the PR 3 model at all."""
    assert "correlation_id" not in OperationAwareEvaluateRequest.model_fields


def test_request_id_provenance_differs_caller_vs_gateway() -> None:
    caller_supplied = OperationAwareEvaluateRequest(action="read:ahu", request_id="caller-1")
    absent = OperationAwareEvaluateRequest(action="read:ahu")

    composed_caller = _compose(caller_supplied)
    composed_absent = _compose(absent)

    assert composed_caller.provenance["request_id"] != composed_absent.provenance["request_id"]


# ---------------------------------------------------------------------------
# 9. Evaluation time
# ---------------------------------------------------------------------------


def test_clock_called_exactly_once() -> None:
    calls = []

    def counting_clock() -> datetime:
        calls.append(1)
        return _FIXED_TIME

    request = OperationAwareEvaluateRequest(action="read:ahu")
    _compose(request, clock=counting_clock)
    assert len(calls) == 1


def test_evaluation_time_exact_value_preserved() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    composed = _compose(request, clock=_fixed_clock(_FIXED_TIME))
    assert composed.evaluation_time == _FIXED_TIME


def test_evaluation_time_is_timezone_aware() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    composed = _compose(request, clock=_fixed_clock(_FIXED_TIME))
    assert composed.evaluation_time.tzinfo is not None
    assert composed.evaluation_time.utcoffset() is not None


def test_naive_datetime_from_clock_rejected() -> None:
    naive = datetime(2026, 8, 1, 12, 0, 0)  # no tzinfo
    request = OperationAwareEvaluateRequest(action="read:ahu")
    with pytest.raises(CompositionInternalError):
        _compose(request, clock=_fixed_clock(naive))


def test_request_input_cannot_influence_evaluation_time() -> None:
    """OperationAwareEvaluateRequest has no field the caller could use to try."""
    assert "evaluation_time" not in OperationAwareEvaluateRequest.model_fields


# ---------------------------------------------------------------------------
# 10. Missing context remains missing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field_name", OPERATION_PRODUCER_ONLY_FIELDS)
def test_omitted_field_remains_none_with_unavailable_provenance(field_name: str) -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    composed = _compose(request)
    assert getattr(composed, field_name) is None
    assert composed.provenance[field_name] is ProvenanceClassification.UNAVAILABLE


def test_present_operation_producer_only_fields_empty_for_bare_request() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    assert present_operation_producer_only_fields(request) == ()


def test_present_operation_producer_only_fields_deterministic_order() -> None:
    request = OperationAwareEvaluateRequest(
        action="read:ahu",
        adapter_evidence_reference=_adapter_evidence_reference_payload(),
        operation_intent=OperationIntent.READ_ONLY.value,
    )
    assert present_operation_producer_only_fields(request) == (
        "operation_intent",
        "adapter_evidence_reference",
    )


# ---------------------------------------------------------------------------
# 11. Free-form context
#
# PR 5 (basis-core v0.2.1 correction): a caller can no longer supply
# non-empty free-form context at all (rejected upstream by PR 3's own
# validator — see test_operation_aware_input_model.py). The tests below
# prove what actually reaches composition now: an always-empty caller
# context, combined only with gateway-owned composition evidence.
# ---------------------------------------------------------------------------


def test_no_arbitrary_caller_key_reaches_composed_result() -> None:
    """A caller cannot get any non-reserved key into composed.context —
    there is no longer a validated construction path that produces a
    non-empty caller context at all."""
    request = OperationAwareEvaluateRequest(action="read", resource_type="ahu")
    composed = _compose(request)
    assert all(key.startswith(RESERVED_CONTEXT_PREFIX) for key in composed.context)


def test_composed_context_keys_always_use_reserved_prefix_when_non_empty() -> None:
    """Structural proof: whenever composed.context is non-empty, every key
    present uses the reserved basis_gateway.* namespace — covering action
    composition alone, resource composition alone, and both together."""
    scenarios = [
        OperationAwareEvaluateRequest(action="read", resource_type="ahu"),
        OperationAwareEvaluateRequest(action="read", resource_type="ahu", resource_id="rooftop-1"),
        OperationAwareEvaluateRequest(action="read:ahu"),
    ]
    for request in scenarios:
        composed = _compose(request)
        for key in composed.context:
            assert key.startswith(RESERVED_CONTEXT_PREFIX), (
                f"unexpected non-reserved composed-context key: {key!r}"
            )


def test_original_request_context_remains_empty() -> None:
    request = OperationAwareEvaluateRequest(action="read", resource_type="ahu")
    assert request.context == {}
    _compose(request)
    assert request.context == {}


def test_original_input_dict_not_mutated() -> None:
    payload = {
        "action": "read",
        "resource_type": "ahu",
        "resource_id": "rooftop-1",
    }
    original = copy.deepcopy(payload)
    request = OperationAwareEvaluateRequest(**payload)
    request_context_before = dict(request.context)

    _compose(request)

    assert payload == original
    assert request.context == request_context_before


def test_composed_context_mapping_cannot_be_mutated() -> None:
    request = OperationAwareEvaluateRequest(action="read", resource_type="ahu")
    composed = _compose(request)
    assert composed.context  # non-empty: contains gateway composition evidence
    key = next(iter(composed.context))
    with pytest.raises(TypeError):
        composed.context[key] = "hacked"  # type: ignore[index]


def test_composition_evidence_added_to_new_copy_not_original() -> None:
    request = OperationAwareEvaluateRequest(action="read", resource_type="ahu")
    original_context = request.context
    composed = _compose(request)
    assert f"{RESERVED_CONTEXT_PREFIX}action_composed" not in original_context
    assert f"{RESERVED_CONTEXT_PREFIX}action_composed" in composed.context
    # The gateway evidence is generated in a new mapping, never the same
    # object as (or written back into) the original request's context.
    assert composed.context is not request.context


def test_composite_action_no_generated_context_yields_unavailable_provenance() -> None:
    """A composite action with no resource composition produces no
    composition evidence at all — composed.context is empty, and its
    provenance is UNAVAILABLE (never VERIFIED, never
    UNTRUSTED_CALLER_ASSERTED — arbitrary caller context can no longer
    reach this function)."""
    request = OperationAwareEvaluateRequest(action="read:ahu")
    composed = _compose(request)
    assert composed.context == {}
    assert composed.provenance["context"] is ProvenanceClassification.UNAVAILABLE


def test_bare_action_plus_resource_type_yields_gateway_derived_context_provenance() -> None:
    """Bare-verb action composition generates basis_gateway.* evidence —
    composed.context is non-empty, and its provenance is GATEWAY_DERIVED."""
    request = OperationAwareEvaluateRequest(action="read", resource_type="ahu")
    composed = _compose(request)
    assert composed.context
    assert all(key.startswith(RESERVED_CONTEXT_PREFIX) for key in composed.context)
    assert composed.provenance["context"] is ProvenanceClassification.GATEWAY_DERIVED


def test_resource_composition_evidence_yields_gateway_derived_context_provenance() -> None:
    """Local-resource-id + resource_type composition likewise generates
    basis_gateway.* evidence and GATEWAY_DERIVED context provenance."""
    request = OperationAwareEvaluateRequest(
        action="read", resource_type="ahu", resource_id="rooftop-1"
    )
    composed = _compose(request)
    assert composed.context
    assert f"{RESERVED_CONTEXT_PREFIX}resource_composed" in composed.context
    assert composed.provenance["context"] is ProvenanceClassification.GATEWAY_DERIVED


def test_no_normal_validated_request_can_produce_untrusted_caller_asserted_context() -> None:
    """Across every normal, validly-constructed request shape (no
    composition, action composition only, resource composition only, and
    both together), composed.provenance["context"] is never
    UNTRUSTED_CALLER_ASSERTED — that classification is structurally
    unreachable now that arbitrary caller context is rejected upstream by
    OperationAwareEvaluateRequest's own validator."""
    scenarios = [
        OperationAwareEvaluateRequest(action="read:ahu"),
        OperationAwareEvaluateRequest(action="read", resource_type="ahu"),
        OperationAwareEvaluateRequest(action="read", resource_type="ahu", resource_id="rooftop-1"),
    ]
    for request in scenarios:
        composed = _compose(request)
        assert (
            composed.provenance["context"] is not ProvenanceClassification.UNTRUSTED_CALLER_ASSERTED
        )
        assert composed.provenance["context"] in (
            ProvenanceClassification.UNAVAILABLE,
            ProvenanceClassification.GATEWAY_DERIVED,
        )


def test_context_provenance_never_verified() -> None:
    """Gateway-generated composition evidence is GATEWAY_DERIVED, never
    upgraded to VERIFIED — it is not independently authenticated the way
    authorization_subject_* fields are."""
    request = OperationAwareEvaluateRequest(action="read", resource_type="ahu")
    composed = _compose(request)
    assert composed.provenance["context"] is not ProvenanceClassification.VERIFIED


# ---------------------------------------------------------------------------
# 12. Immutable result
# ---------------------------------------------------------------------------


def test_composed_result_is_frozen_dataclass() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    composed = _compose(request)
    with pytest.raises(AttributeError):
        composed.action = "write:ahu"  # type: ignore[misc]


def test_composed_provenance_mapping_cannot_be_mutated() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    composed = _compose(request)
    with pytest.raises(TypeError):
        composed.provenance["action"] = ProvenanceClassification.VERIFIED  # type: ignore[index]


def test_modifying_request_context_after_composition_does_not_alter_result() -> None:
    """``dict(request.context)`` is copied at composition time — mutating
    the request's context dict afterward (even though it starts empty,
    per PR 5) cannot alter an already-returned composed result."""
    request = OperationAwareEvaluateRequest(action="read:ahu")
    composed = _compose(request)
    request.context["basis_gateway.forged"] = "mutated-after-the-fact"
    assert "basis_gateway.forged" not in composed.context


# ---------------------------------------------------------------------------
# 13. No kernel construction
# ---------------------------------------------------------------------------


def test_composition_module_does_not_import_kernel_construction_symbols() -> None:
    """Structural boundary check: no kernel-invocation symbol is imported.

    The module's own namespace (its bound globals) must not include any of
    the kernel-construction/evaluation entry points this PR explicitly
    excludes, and its ``import`` statements must not name any of them
    either. Prose in the module's docstring is free to *discuss* these
    names (explaining what the module does not do) — this check inspects
    only actual `import`/`from ... import` statements via the AST, not
    comments or docstrings, so it cannot be defeated by documentation text
    but also does not false-positive on it.
    """
    import ast

    import basis_gateway.core.operation_aware_composition as module

    forbidden_names = {
        "OperationAwareDecisionRequest",
        "OperationAwareEnforcementPoint",
        "OperationAwareEvaluationEngine",
        "PolicyBundle",
    }

    # 1. No forbidden symbol is bound in the module's own namespace.
    module_globals = set(vars(module))
    assert forbidden_names.isdisjoint(module_globals)

    # 2. No forbidden symbol is named in any import statement in the source.
    source = inspect.getsource(module)
    tree = ast.parse(source)
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            imported_names.update(alias.asname or alias.name for alias in node.names)
    assert forbidden_names.isdisjoint(imported_names)


def test_compose_operation_aware_input_never_returns_kernel_request_type() -> None:
    request = OperationAwareEvaluateRequest(action="read:ahu")
    composed = _compose(request)
    assert type(composed) is ComposedOperationAwareInput
    assert composed.__class__.__module__ == "basis_gateway.core.operation_aware_composition"


# ---------------------------------------------------------------------------
# 14. Identity-consistency invariants
#
# subject, identity_context, and producer_trust are three independently
# constructed inputs. compose_operation_aware_input() must reject any
# internally inconsistent combination of the three before producer-only
# context is accepted and before any ComposedOperationAwareInput is
# constructed — never silently reconcile, replace, or normalize a mismatch.
#
# Malformed OperationProducerTrust objects are constructed directly here
# (bypassing classify_operation_producer()) specifically to exercise
# invariants that the classifier itself would never produce — that is the
# point of these tests: compose_operation_aware_input() must not blindly
# trust its inputs just because classify_operation_producer() normally
# would not misbehave this way.
# ---------------------------------------------------------------------------


def test_identity_context_subject_id_mismatch_rejected() -> None:
    subject = _subject("human-1")
    mismatched_identity_context = _identity_context("someone-else")
    trust = classify_operation_producer(subject, frozenset())
    request = OperationAwareEvaluateRequest(action="read:ahu")

    with pytest.raises(CompositionInternalError):
        _compose(
            request,
            subject=subject,
            identity_context=mismatched_identity_context,
            producer_trust=trust,
        )


def test_producer_trust_authorization_subject_id_mismatch_rejected() -> None:
    subject = _subject("human-1")
    identity_context = _identity_context("human-1")
    malformed_trust = OperationProducerTrust(
        status=OperationProducerTrustStatus.UNTRUSTED,
        source=OperationProducerTrustSource.NOT_CONFIGURED,
        authorization_subject_id="someone-else",
        operation_producer_subject_id=None,
    )
    request = OperationAwareEvaluateRequest(action="read:ahu")

    with pytest.raises(CompositionInternalError):
        _compose(
            request,
            subject=subject,
            identity_context=identity_context,
            producer_trust=malformed_trust,
        )


def test_trusted_producer_subject_id_mismatch_rejected() -> None:
    subject = _subject("adapter-1")
    identity_context = _identity_context("adapter-1")
    malformed_trust = OperationProducerTrust(
        status=OperationProducerTrustStatus.TRUSTED,
        source=OperationProducerTrustSource.CONFIGURED_SUBJECT_ID_ALLOWLIST,
        authorization_subject_id="adapter-1",
        operation_producer_subject_id="a-different-adapter",
    )
    request = OperationAwareEvaluateRequest(action="read:ahu")

    with pytest.raises(CompositionInternalError):
        _compose(
            request,
            subject=subject,
            identity_context=identity_context,
            producer_trust=malformed_trust,
        )


def test_untrusted_result_with_non_none_producer_subject_id_rejected() -> None:
    subject = _subject("human-1")
    identity_context = _identity_context("human-1")
    malformed_trust = OperationProducerTrust(
        status=OperationProducerTrustStatus.UNTRUSTED,
        source=OperationProducerTrustSource.SUBJECT_ID_NOT_ALLOWED,
        authorization_subject_id="human-1",
        operation_producer_subject_id="human-1",  # invalid: untrusted but carries an id
    )
    request = OperationAwareEvaluateRequest(action="read:ahu")

    with pytest.raises(CompositionInternalError):
        _compose(
            request,
            subject=subject,
            identity_context=identity_context,
            producer_trust=malformed_trust,
        )


def _identity_context_subject_id_differs() -> tuple[
    NormalizedSubject, IdentityContext, OperationProducerTrust
]:
    subject = _subject("human-1")
    return (
        subject,
        _identity_context("someone-else"),
        classify_operation_producer(subject, frozenset()),
    )


def _authorization_subject_id_differs() -> tuple[
    NormalizedSubject, IdentityContext, OperationProducerTrust
]:
    return (
        _subject("human-1"),
        _identity_context("human-1"),
        OperationProducerTrust(
            status=OperationProducerTrustStatus.UNTRUSTED,
            source=OperationProducerTrustSource.NOT_CONFIGURED,
            authorization_subject_id="someone-else",
            operation_producer_subject_id=None,
        ),
    )


def _trusted_producer_subject_id_differs() -> tuple[
    NormalizedSubject, IdentityContext, OperationProducerTrust
]:
    return (
        _subject("adapter-1"),
        _identity_context("adapter-1"),
        OperationProducerTrust(
            status=OperationProducerTrustStatus.TRUSTED,
            source=OperationProducerTrustSource.CONFIGURED_SUBJECT_ID_ALLOWLIST,
            authorization_subject_id="adapter-1",
            operation_producer_subject_id="a-different-adapter",
        ),
    )


def _untrusted_with_producer_subject_id() -> tuple[
    NormalizedSubject, IdentityContext, OperationProducerTrust
]:
    return (
        _subject("human-1"),
        _identity_context("human-1"),
        OperationProducerTrust(
            status=OperationProducerTrustStatus.UNTRUSTED,
            source=OperationProducerTrustSource.SUBJECT_ID_NOT_ALLOWED,
            authorization_subject_id="human-1",
            operation_producer_subject_id="human-1",
        ),
    )


@pytest.mark.parametrize(
    "build_bad_inputs",
    [
        _identity_context_subject_id_differs,
        _authorization_subject_id_differs,
        _trusted_producer_subject_id_differs,
        _untrusted_with_producer_subject_id,
    ],
    ids=[
        "identity_context_subject_id_differs",
        "authorization_subject_id_differs",
        "trusted_producer_subject_id_differs",
        "untrusted_with_producer_subject_id",
    ],
)
def test_identity_mismatch_raises_and_leaves_inputs_unmodified(
    build_bad_inputs: Callable[
        [], tuple[NormalizedSubject, IdentityContext, OperationProducerTrust]
    ],
) -> None:
    """Every mismatch raises CompositionInternalError and mutates nothing.

    Covers all four combinations in one parametrized test: the exception
    propagates (so no ComposedOperationAwareInput is ever returned), and the
    request plus every input identity object is byte-for-byte unchanged
    afterward — frozen dataclasses compare equal to a pre-call deep copy.
    """
    subject, identity_context, producer_trust = build_bad_inputs()
    request = OperationAwareEvaluateRequest(action="read:ahu")

    subject_before = copy.deepcopy(subject)
    identity_context_before = copy.deepcopy(identity_context)
    producer_trust_before = copy.deepcopy(producer_trust)
    request_context_before = dict(request.context)

    with pytest.raises(CompositionInternalError):
        _compose(
            request,
            subject=subject,
            identity_context=identity_context,
            producer_trust=producer_trust,
        )

    assert subject == subject_before
    assert identity_context == identity_context_before
    assert producer_trust == producer_trust_before
    assert request.context == request_context_before


def test_identity_mismatch_error_omits_roles_attributes_and_claims() -> None:
    """The exception message carries only the minimal subject-id identifiers.

    Never roles, attributes, or claims — even when the mismatched subject
    carries sensitive-looking attribute data.
    """
    subject = NormalizedSubject(
        subject_id="human-1",
        name="human-1",
        roles=("admin", "super-secret-role"),
        attributes={"email": "very-secret@example.com"},
    )
    identity_context = _identity_context("someone-else")
    trust = classify_operation_producer(subject, frozenset())
    request = OperationAwareEvaluateRequest(action="read:ahu")

    with pytest.raises(CompositionInternalError) as exc_info:
        _compose(
            request,
            subject=subject,
            identity_context=identity_context,
            producer_trust=trust,
        )

    message = str(exc_info.value)
    assert "super-secret-role" not in message
    assert "very-secret@example.com" not in message
