"""Operation-aware trust and composition boundary for basis-gateway.

Part of the operation-aware gateway integration
(``docs/implementation/operation-aware-gateway-integration-plan.md``, §5,
§6, §7, §16 PR 4). This module takes:

- a validated ``OperationAwareEvaluateRequest`` (PR 3 — shape validation
  only),
- the already-authenticated ``NormalizedSubject`` and verified
  ``IdentityContext`` (``auth/subject_mapper.py``, unchanged),
- an ``OperationProducerTrust`` classification
  (``auth/operation_producer.py``, PR 4),
- the gateway-generated correlation ID (middleware, unchanged),

and produces an immutable ``ComposedOperationAwareInput`` — the set of
values ``basis_gateway.core.operation_aware_evaluator`` uses to construct
``basis_core.decisions.OperationAwareDecisionRequest``. This module itself
still does **not** construct that kernel request, does not load a
``PolicyBundle``, does not construct ``OperationAwareEnforcementPoint``, and
does not invoke ``basis-core`` at all — those remain
``operation_aware_evaluator``'s responsibility. As of PR 6, this module's
``compose_operation_aware_input`` is reachable at request time via
``POST /v1/evaluate/operation-aware`` (``api.routes.evaluate_operation_aware``),
which calls it after authentication and before invoking the kernel
evaluator.

Reused, not reinvented
------------------------
- Action composition reuses ``core/actions.py``'s ``compose_action()``
  unchanged.
- Resource composition reuses ``core/resources.py``'s
  ``compose_resource_id()`` unchanged.
- Reserved-namespace context rejection reuses ``core/actions.py``'s
  ``reserved_key_collisions()`` unchanged.

There is exactly one action/resource composition grammar in this
repository; this module does not define a second one.

Missing context stays missing
-------------------------------
Every optional operation-aware field (``operation_intent``, ``location``,
``device``, ``protocol_context``, ``safety_context``,
``environment_context``, ``risk_context``, ``identity_evidence_reference``,
``adapter_evidence_reference``) is passed through unchanged when present and
left as ``None`` when absent. This module never synthesizes an
empty-but-present value for any of them.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType

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

from basis_gateway.api.operation_aware_schemas import OperationAwareEvaluateRequest
from basis_gateway.auth.operation_producer import (
    OperationProducerTrust,
    OperationProducerTrustStatus,
)
from basis_gateway.auth.subject_mapper import IdentityContext, NormalizedSubject
from basis_gateway.core.actions import (
    RESERVED_CONTEXT_PREFIX,
    build_composition_evidence,
    compose_action,
    reserved_key_collisions,
)
from basis_gateway.core.resources import (
    build_resource_composition_evidence,
    compose_resource_id,
)

__all__ = [
    "OPERATION_PRODUCER_ONLY_FIELDS",
    "ComposedOperationAwareInput",
    "CompositionInternalError",
    "OperationAwareCompositionError",
    "ProvenanceClassification",
    "ReservedContextKeyError",
    "UntrustedOperationProducerContextError",
    "compose_operation_aware_input",
    "present_operation_producer_only_fields",
    "utc_now",
]

# Authoritative list of producer-only fields on ``OperationAwareEvaluateRequest``.
# A field is "present" when its value is not None (an empty-but-valid nested
# model, e.g. ``safety_context={}``, still counts as present). Import this
# constant rather than repeating the list.
OPERATION_PRODUCER_ONLY_FIELDS: tuple[str, ...] = (
    "operation_intent",
    "location",
    "device",
    "protocol_context",
    "safety_context",
    "environment_context",
    "risk_context",
    "identity_evidence_reference",
    "adapter_evidence_reference",
)


class ProvenanceClassification(str, Enum):
    """Closed vocabulary of field-level trust classifications.

    See the integration plan §5 "Provenance table" for the authoritative
    definition of each value. This module does not add categories beyond
    what that table justifies.
    """

    VERIFIED = "verified"
    GATEWAY_DERIVED = "gateway_derived"
    TRUSTED_PRODUCER_ASSERTED = "trusted_producer_asserted"
    UNTRUSTED_CALLER_ASSERTED = "untrusted_caller_asserted"
    CONFIGURATION_DERIVED = "configuration_derived"
    UNAVAILABLE = "unavailable"


class OperationAwareCompositionError(ValueError):
    """Base class for caller-facing rejections raised by this module.

    Distinct from ``CompositionInternalError``: instances of this class (and
    its subclasses) are reachable from caller-controlled request content and
    are safe to surface in an error response. A later PR maps these to HTTP
    ``400``; this module does not perform that mapping itself.
    """


class UntrustedOperationProducerContextError(OperationAwareCompositionError):
    """Raised when a non-producer caller's request carries producer-only fields.

    ``offending_fields`` is a deterministically ordered (per
    ``OPERATION_PRODUCER_ONLY_FIELDS``) tuple of field *names* only. Field
    *values* are never included here or in the exception message — per the
    integration plan §5a/§11, the rejection reason itself ("this caller is
    not a classified operation producer") is safe to state, but the
    operational content the caller attempted to assert is not echoed back.
    """

    def __init__(self, offending_fields: tuple[str, ...]) -> None:
        self.offending_fields = offending_fields
        joined = ", ".join(offending_fields)
        super().__init__(
            "caller is not a classified operation producer and may not supply "
            f"operation-producer-only field(s): {joined}"
        )


class ReservedContextKeyError(OperationAwareCompositionError):
    """Raised when caller-supplied context uses the reserved gateway namespace.

    A narrow wrapper around the existing ``core/actions.py``
    ``reserved_key_collisions()`` check — this module reuses that boundary
    rather than reimplementing it. ``offending_keys`` lists the colliding
    context key names only.
    """

    def __init__(self, offending_keys: tuple[str, ...]) -> None:
        self.offending_keys = offending_keys
        joined = ", ".join(offending_keys)
        super().__init__(
            f"context keys use the reserved {RESERVED_CONTEXT_PREFIX!r} namespace "
            f"and must not be supplied by the caller: {joined}"
        )


class CompositionInternalError(RuntimeError):
    """Raised for a gateway-internal programming error, never a caller fault.

    Reserved for conditions that indicate ``compose_operation_aware_input``
    was called incorrectly by other gateway code — an empty/blank
    gateway-owned ``correlation_id``, or an injected ``clock`` that returned
    a naive (non-timezone-aware) ``datetime``. No caller-controlled request
    content can trigger this exception.
    """


def utc_now() -> datetime:
    """Gateway clock: the sole source of ``evaluation_time`` for composition.

    Timezone-aware, UTC, gateway-generated. Never derived from request
    input. The default value of ``compose_operation_aware_input``'s
    ``clock`` parameter — tests inject a fixed/fake clock instead of calling
    this function directly.
    """
    return datetime.now(timezone.utc)


def present_operation_producer_only_fields(
    request: OperationAwareEvaluateRequest,
) -> tuple[str, ...]:
    """Return the producer-only fields present (non-``None``) on *request*.

    Deterministic ordering: ``OPERATION_PRODUCER_ONLY_FIELDS`` order, not
    request/dict iteration order. An empty-but-valid nested model (e.g.
    ``safety_context={}``) still counts as present — only ``None`` counts as
    absent.
    """
    return tuple(
        field_name
        for field_name in OPERATION_PRODUCER_ONLY_FIELDS
        if getattr(request, field_name) is not None
    )


@dataclass(frozen=True, slots=True)
class ComposedOperationAwareInput:
    """Immutable, gateway-owned composition result.

    **Not** a ``basis-core`` request. This module does not subclass, wrap,
    or construct ``basis_core.decisions.OperationAwareDecisionRequest`` —
    that remains a later PR's responsibility, deliberately kept separate so
    this composition logic is testable without a live ``PolicyBundle`` or
    kernel evaluator.

    ``context`` and ``provenance`` are immutable mappings
    (``MappingProxyType``) over copies made during composition — mutating
    the original request's context dict or the caller-supplied trust inputs
    after construction cannot alter this object.
    """

    request_id: str
    correlation_id: str
    authorization_subject: NormalizedSubject
    identity_context: IdentityContext
    operation_producer_trust: OperationProducerTrust
    action: str
    resource_id: str | None
    resource_type: str | None
    context: Mapping[str, str]
    operation_intent: OperationIntent | None
    location: OperationAwareLocation | None
    device: OperationAwareDevice | None
    protocol_context: OperationAwareProtocolContext | None
    safety_context: OperationAwareSafetyContext | None
    environment_context: OperationAwareEnvironmentContext | None
    risk_context: OperationAwareRiskContext | None
    identity_evidence_reference: IdentityEvidenceReference | None
    adapter_evidence_reference: AdapterEvidenceReference | None
    evaluation_time: datetime
    provenance: Mapping[str, ProvenanceClassification]


def compose_operation_aware_input(
    request: OperationAwareEvaluateRequest,
    *,
    subject: NormalizedSubject,
    identity_context: IdentityContext,
    producer_trust: OperationProducerTrust,
    correlation_id: str,
    clock: Callable[[], datetime] = utc_now,
) -> ComposedOperationAwareInput:
    """Compose validated input + verified identity + producer trust.

    Required sequence (integration plan §7, §16 PR 4):

    1. Validate *correlation_id* (gateway-owned; empty/blank is an internal
       composition error, not a caller-facing one).
    2. Validate identity-consistency invariants across *subject*,
       *identity_context*, and *producer_trust* (``CompositionInternalError``
       on any mismatch) — before producer-only context is accepted and
       before any composed result is constructed.
    3. Reject producer-only fields present on *request* when
       *producer_trust* is not ``TRUSTED``
       (``UntrustedOperationProducerContextError``) — before any other work.
    4. Reject reserved (``basis_gateway.*``) free-form context keys
       (``ReservedContextKeyError``, reusing ``reserved_key_collisions()``).
    5. Compose the canonical action (``compose_action()``, reused unchanged;
       ``ActionCompositionError`` propagates unchanged).
    6. Compose the canonical resource identifier (``compose_resource_id()``,
       reused unchanged; ``ResourceCompositionError`` propagates unchanged).
    7. Combine free-form context with composition evidence into a new,
       independent mapping.
    8. Resolve ``request_id`` (caller-supplied, else *correlation_id*).
    9. Generate ``evaluation_time`` via *clock*, called exactly once;
       reject a naive result as ``CompositionInternalError``.
    10. Pass optional operation-aware context through unchanged — absent
        stays absent, nothing is synthesized.
    11. Build the full, immutable field-level provenance mapping.

    Raises:
        CompositionInternalError: *correlation_id* is empty/blank, one of
            the identity-consistency invariants (step 2) does not hold, or
            *clock* returned a naive ``datetime``. Gateway-internal
            programming errors only — never triggered by caller-controlled
            request content.
        UntrustedOperationProducerContextError: *request* carries one or
            more producer-only fields and *producer_trust.status* is not
            ``TRUSTED``.
        ReservedContextKeyError: *request.context* contains a key in the
            reserved ``basis_gateway.*`` namespace.
        basis_gateway.core.actions.ActionCompositionError: propagated
            unchanged from ``compose_action()``.
        basis_gateway.core.resources.ResourceCompositionError: propagated
            unchanged from ``compose_resource_id()``.
    """
    # 1. Correlation ID is gateway-owned and must already be valid by the
    # time it reaches this internal function — this function does not (and
    # must not) generate a second one.
    if not correlation_id or not correlation_id.strip():
        raise CompositionInternalError(
            "correlation_id must be a non-empty, non-whitespace string; it is "
            "gateway-owned and must be supplied by middleware before "
            "compose_operation_aware_input() is called."
        )

    # 2. Identity-consistency invariants. subject, identity_context, and
    # producer_trust are three independently-constructed inputs that must
    # already agree on which authenticated caller they describe by the time
    # they reach this function. A mismatch indicates calling code assembled
    # inconsistent identity facts — a gateway-internal programming error,
    # never something a caller's request content can trigger. This function
    # does not attempt to silently reconcile, replace, or normalize a
    # mismatch; it rejects outright, before producer-only context is
    # accepted and before any ComposedOperationAwareInput is constructed.
    # Messages carry only the minimal identifiers needed to diagnose the
    # mismatch (subject IDs) — never roles, attributes, claims, or tokens.
    if identity_context.subject_id != subject.subject_id:
        raise CompositionInternalError(
            f"identity_context.subject_id ({identity_context.subject_id!r}) does not "
            f"match subject.subject_id ({subject.subject_id!r}); the verified identity "
            "context and the normalized subject must describe the same authenticated "
            "caller."
        )
    if producer_trust.authorization_subject_id != subject.subject_id:
        raise CompositionInternalError(
            f"producer_trust.authorization_subject_id "
            f"({producer_trust.authorization_subject_id!r}) does not match "
            f"subject.subject_id ({subject.subject_id!r}); the producer-trust "
            "classification must have been derived from this same authenticated "
            "subject."
        )
    if producer_trust.status is OperationProducerTrustStatus.TRUSTED:
        if producer_trust.operation_producer_subject_id != subject.subject_id:
            raise CompositionInternalError(
                "producer_trust.status is TRUSTED but "
                f"operation_producer_subject_id "
                f"({producer_trust.operation_producer_subject_id!r}) does not match "
                f"subject.subject_id ({subject.subject_id!r})."
            )
    elif producer_trust.operation_producer_subject_id is not None:
        raise CompositionInternalError(
            f"producer_trust.status is {producer_trust.status.value!r} (not TRUSTED) "
            "but operation_producer_subject_id is not None "
            f"({producer_trust.operation_producer_subject_id!r}); an untrusted result "
            "must never carry a producer subject id."
        )

    # 3. Producer-only context trust gate — before any other work, and
    # before any composed result is constructed or returned.
    offending_fields = present_operation_producer_only_fields(request)
    if offending_fields and producer_trust.status is not OperationProducerTrustStatus.TRUSTED:
        raise UntrustedOperationProducerContextError(offending_fields)

    # 4. Reserved free-form context namespace — reuses the existing
    # core/actions.py boundary rather than a second implementation.
    collisions = tuple(reserved_key_collisions(request.context))
    if collisions:
        raise ReservedContextKeyError(collisions)

    # 5. Canonical action composition — reused unchanged. Composition
    # occurred iff a resource_type was supplied (a composite action
    # combined with a resource_type is already rejected inside
    # compose_action(), so this is unambiguous), mirroring routes.py's
    # existing v0.1 call-site logic.
    composed_action = compose_action(request.action, request.resource_type)
    action_was_composed = request.resource_type is not None

    # 6. Canonical resource identifier composition — reused unchanged.
    resource_result = compose_resource_id(request.resource_type, request.resource_id)

    # 7. Combine free-form context with composition evidence into a new,
    # independent dict. The caller's original request.context is never
    # mutated — dict(...) copies it first.
    combined_context: dict[str, str] = dict(request.context)
    if action_was_composed:
        assert request.resource_type is not None  # narrowed by action_was_composed
        combined_context.update(
            build_composition_evidence(
                original_action=request.action,
                resource_type=request.resource_type,
                composed_action=composed_action,
            )
        )
    if resource_result.composed:
        assert resource_result.original_resource_id is not None  # narrowed by composed
        assert resource_result.resource_type is not None  # narrowed by composed
        assert resource_result.resource_id is not None  # narrowed by composed
        combined_context.update(
            build_resource_composition_evidence(
                original_resource_id=resource_result.original_resource_id,
                resource_type=resource_result.resource_type,
                composed_resource_id=resource_result.resource_id,
            )
        )

    # 8. Request ID — caller-supplied value, else fall back to the
    # gateway-owned correlation ID. No second UUID is generated here.
    request_id_caller_supplied = request.request_id is not None
    request_id: str = request.request_id if request.request_id is not None else correlation_id

    # 9. Evaluation time — generated exactly once, via the injectable clock.
    evaluation_time = clock()
    if evaluation_time.tzinfo is None or evaluation_time.utcoffset() is None:
        raise CompositionInternalError(
            "clock() returned a naive datetime; evaluation_time must always be "
            "timezone-aware. This indicates a gateway-internal programming "
            "error in the injected clock, never caller input."
        )

    # 10. Optional operation-aware context passes through unchanged — absent
    # (None) stays None; nothing here is synthesized into an empty-but-present
    # object.

    # 11. Field-level provenance.
    resource_id_provenance: ProvenanceClassification
    if resource_result.composed:
        resource_id_provenance = ProvenanceClassification.GATEWAY_DERIVED
    elif resource_result.resource_id is not None:
        # Pass-through: caller supplied an already-typed resource_id.
        resource_id_provenance = ProvenanceClassification.UNTRUSTED_CALLER_ASSERTED
    else:
        resource_id_provenance = ProvenanceClassification.UNAVAILABLE

    resource_type_provenance = (
        ProvenanceClassification.UNTRUSTED_CALLER_ASSERTED
        if request.resource_type is not None
        else ProvenanceClassification.UNAVAILABLE
    )

    action_provenance = (
        ProvenanceClassification.GATEWAY_DERIVED
        if action_was_composed
        else ProvenanceClassification.UNTRUSTED_CALLER_ASSERTED
    )

    request_id_provenance = (
        ProvenanceClassification.UNTRUSTED_CALLER_ASSERTED
        if request_id_caller_supplied
        else ProvenanceClassification.GATEWAY_DERIVED
    )

    # context: derived from the final, already-copied combined_context (step
    # 7), after action/resource composition has finished — never from
    # request.context directly. request.context is validated empty-only by
    # OperationAwareEvaluateRequest (operation_aware_schemas.py), so an
    # ordinary caller can never populate combined_context with anything but
    # gateway-generated basis_gateway.* composition evidence. There is
    # therefore no remaining case in which this context is
    # caller-supplied/untrusted: it is either empty (no composition
    # occurred) or entirely gateway-derived (composition evidence was
    # added) — never VERIFIED (it is not independently authenticated the
    # way authorization_subject_* fields are) and never
    # UNTRUSTED_CALLER_ASSERTED (arbitrary caller context can no longer
    # reach this function at all).
    context_provenance = (
        ProvenanceClassification.GATEWAY_DERIVED
        if combined_context
        else ProvenanceClassification.UNAVAILABLE
    )

    operation_producer_subject_id_provenance = (
        ProvenanceClassification.VERIFIED
        if producer_trust.operation_producer_subject_id is not None
        else ProvenanceClassification.UNAVAILABLE
    )

    def _producer_only_field_provenance(value: object) -> ProvenanceClassification:
        return (
            ProvenanceClassification.TRUSTED_PRODUCER_ASSERTED
            if value is not None
            else ProvenanceClassification.UNAVAILABLE
        )

    provenance: dict[str, ProvenanceClassification] = {
        "authorization_subject_id": ProvenanceClassification.VERIFIED,
        "authorization_subject_roles": ProvenanceClassification.VERIFIED,
        "authorization_subject_attributes": ProvenanceClassification.VERIFIED,
        "operation_producer_subject_id": operation_producer_subject_id_provenance,
        "operation_producer_trust": ProvenanceClassification.CONFIGURATION_DERIVED,
        "action": action_provenance,
        "resource_id": resource_id_provenance,
        "resource_type": resource_type_provenance,
        "context": context_provenance,
        "operation_intent": _producer_only_field_provenance(request.operation_intent),
        "location": _producer_only_field_provenance(request.location),
        "device": _producer_only_field_provenance(request.device),
        "protocol_context": _producer_only_field_provenance(request.protocol_context),
        "safety_context": _producer_only_field_provenance(request.safety_context),
        "environment_context": _producer_only_field_provenance(request.environment_context),
        "risk_context": _producer_only_field_provenance(request.risk_context),
        "identity_evidence_reference": _producer_only_field_provenance(
            request.identity_evidence_reference
        ),
        "adapter_evidence_reference": _producer_only_field_provenance(
            request.adapter_evidence_reference
        ),
        "evaluation_time": ProvenanceClassification.GATEWAY_DERIVED,
        "request_id": request_id_provenance,
        "correlation_id": ProvenanceClassification.GATEWAY_DERIVED,
    }

    return ComposedOperationAwareInput(
        request_id=request_id,
        correlation_id=correlation_id,
        authorization_subject=subject,
        identity_context=identity_context,
        operation_producer_trust=producer_trust,
        action=composed_action,
        resource_id=resource_result.resource_id,
        resource_type=request.resource_type,
        context=MappingProxyType(combined_context),
        operation_intent=request.operation_intent,
        location=request.location,
        device=request.device,
        protocol_context=request.protocol_context,
        safety_context=request.safety_context,
        environment_context=request.environment_context,
        risk_context=request.risk_context,
        identity_evidence_reference=request.identity_evidence_reference,
        adapter_evidence_reference=request.adapter_evidence_reference,
        evaluation_time=evaluation_time,
        provenance=MappingProxyType(provenance),
    )
