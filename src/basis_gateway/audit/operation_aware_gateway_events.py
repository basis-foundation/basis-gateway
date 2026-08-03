"""Operation-aware gateway audit-event assembly (PR 7).

Implements the operation-aware gateway enforcement-boundary evidence
described in the PR 7 work item: for every request through
``POST /v1/evaluate/operation-aware``, produce and durably record one
gateway audit record combining:

  - a small, contract-shaped ``GatewayAuditEvent`` (this module's own
    narrowly-scoped model — *not* a ``basis-schemas`` contract, and not the
    v0.1 ``basis_core.audit.AuditEvent``), and
  - the complete, unmodified kernel-produced
    ``basis_core.audit.AuditEvidence`` for that same evaluation.

Both artifacts are written *beside* each other inside one outer,
gateway-owned ``AuditEvent.detail`` — never one embedded inside the other,
and never a bare ``audit_evidence_id`` reference without the corresponding
``AuditEvidence`` present in the same durable record. See this module's
``build_operation_aware_audit_detail`` for the exact shape.

Ownership boundary
-------------------
This module never constructs, mutates, reorders, or reinterprets any
``AuditEvidence`` field. ``matched_rule_ids`` order, evidence references,
``outcome``/``failure_reason`` nullability, and every other kernel-produced
value are serialized exactly as returned by
``OperationAwareEnforcementResult``. The only new information this module
adds is gateway-owned: enforcement action (copied verbatim from
``result.disposition``, never recomputed from ``outcome``), HTTP status
actually selected, operation-producer trust classification, and field-level
provenance (also gateway-produced, by
``basis_gateway.core.operation_aware_composition``).

Mirrors, extends, does not replace
------------------------------------
This module is a sibling of ``audit/gateway_events.py`` — it reuses the same
``AuditWriter``/``GatewayAuditWriter`` instance, the same
``AuditEvent(event_type=SYSTEM_EVENT, ...)`` pattern, and the same
"catch, log, never propagate" write-failure discipline. It does not modify
``audit/gateway_events.py`` or any v0.1 gateway event.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from basis_core.audit import AuditEvent, AuditEventType, AuditOutcome, AuditWriter
from basis_core.enforcement import EnforcementDisposition, OperationAwareEnforcementResult

if TYPE_CHECKING:
    from basis_core.audit import AuditEvidence

    from basis_gateway.core.operation_aware_composition import (
        ComposedOperationAwareInput,
        ProvenanceClassification,
    )

log = logging.getLogger(__name__)

__all__ = [
    "AUTHENTICATION_FAILED",
    "AUTHORIZATION_COMPLETED",
    "COMPOSITION_REJECTED",
    "EVALUATION_FAILED_CLOSED",
    "EVALUATOR_UNAVAILABLE",
    "EVIDENCE_MISSING",
    "GATEWAY_AUDIT_EVENT_TYPE",
    "OA_AUDIT_RECOVERY_PROBE",
    "REASON_ACTION_OR_RESOURCE_COMPOSITION_FAILED",
    "REASON_COMPOSITION_INTERNAL_ERROR",
    "REASON_EVALUATION_EXCEPTION",
    "REASON_EVALUATOR_NOT_INITIALIZED",
    "REASON_IDENTITY_NORMALIZATION_FAILED",
    "REASON_INVALID_DECISION_REQUEST",
    "REASON_INVALID_FIELDS",
    "REASON_INVALID_TOKEN",
    "REASON_MALFORMED_BODY",
    "REASON_MISSING_AUDIT_EVIDENCE",
    "REASON_MISSING_TOKEN",
    "REASON_PRODUCER_CONTEXT_REJECTED",
    "REASON_RESERVED_CONTEXT_KEY",
    "REASON_VERIFIER_NOT_CONFIGURED",
    "VALIDATION_FAILED",
    "GatewayAuditEvent",
    "assemble_gateway_audit_event",
    "emit_operation_aware_completed_event",
    "emit_operation_aware_missing_evidence_event",
    "emit_operation_aware_system_event",
    "serialize_audit_evidence",
    "serialize_provenance",
]

# ---------------------------------------------------------------------------
# Stable operation-aware gateway action vocabulary
# ---------------------------------------------------------------------------
# Gateway-local action names for the outer AuditEvent.action field — not a
# basis-schemas contract, mirroring audit/gateway_events.py's own stable
# vocabulary convention, extended with an "operation_aware_" segment so the
# two families are never confused in a shared log stream.

#: Request body failed shape validation before authentication was attempted.
VALIDATION_FAILED = "gateway.operation_aware_validation_failed"

#: Authentication failed before any kernel decision could be produced.
AUTHENTICATION_FAILED = "gateway.operation_aware_authentication_failed"

#: Provenance-gated composition rejected the request (untrusted producer
#: context, reserved context key, action/resource composition failure, or
#: kernel-request construction failure) — a gateway-owned, pre-kernel
#: rejection.
COMPOSITION_REJECTED = "gateway.operation_aware_composition_rejected"

#: The operation-aware evaluator is not initialized; request failed closed
#: without kernel evaluation.
EVALUATOR_UNAVAILABLE = "gateway.operation_aware_evaluator_unavailable"

#: A gateway-internal invariant violation or unexpected exception occurred;
#: request failed closed.
EVALUATION_FAILED_CLOSED = "gateway.operation_aware_evaluation_failed_closed"

#: Lightweight strict-mode (AUDIT_FAIL_CLOSED=true) recovery probe — mirrors
#: audit/gateway_events.py's AUDIT_RECOVERY_PROBE, kept as a distinct action
#: name for this endpoint's own audit trail.
OA_AUDIT_RECOVERY_PROBE = "gateway.operation_aware_audit_recovery_probe"

#: The kernel was invoked and produced a trustworthy, complete result
#: (AuditEvidence present) — the "real" completed evaluation record.
AUTHORIZATION_COMPLETED = "gateway.operation_aware_authorization_completed"

#: The kernel was invoked but did not produce AuditEvidence (the enforcement
#: point's own catastrophic-internal-error fallback) — an integration-failure
#: system event, never a fabricated completed record.
EVIDENCE_MISSING = "gateway.operation_aware_evidence_missing"

# ---------------------------------------------------------------------------
# Stable reason category vocabulary
# ---------------------------------------------------------------------------
# Reuses v0.1's category names where the underlying category is identical in
# meaning (malformed body, invalid fields, missing token, ...); adds new
# categories only for genuinely new operation-aware rejection reasons.

REASON_MALFORMED_BODY = "malformed_request_body"
REASON_INVALID_FIELDS = "invalid_request_fields"
REASON_MISSING_TOKEN = "missing_bearer_token"
REASON_INVALID_TOKEN = "invalid_token"
REASON_VERIFIER_NOT_CONFIGURED = "verifier_not_configured"
REASON_IDENTITY_NORMALIZATION_FAILED = "identity_normalization_failed"
REASON_EVALUATOR_NOT_INITIALIZED = "evaluator_not_initialized"
REASON_EVALUATION_EXCEPTION = "unexpected_evaluation_exception"
REASON_INVALID_DECISION_REQUEST = "invalid_decision_request"

#: New for operation-aware: a non-producer-classified caller asserted one or
#: more operation-producer-only fields.
REASON_PRODUCER_CONTEXT_REJECTED = "producer_context_rejected"

#: New for operation-aware: caller-supplied context used the reserved
#: gateway namespace.
REASON_RESERVED_CONTEXT_KEY = "reserved_context_key"

#: New for operation-aware: action or resource identifier composition failed.
REASON_ACTION_OR_RESOURCE_COMPOSITION_FAILED = "action_or_resource_composition_failed"

#: New: a gateway-internal composition invariant was violated (never
#: caller-triggered).
REASON_COMPOSITION_INTERNAL_ERROR = "composition_internal_error"

#: New: OperationAwareEnforcementResult.audit_evidence was None despite a
#: real kernel invocation (the enforcement point's internal-error fallback).
REASON_MISSING_AUDIT_EVIDENCE = "missing_audit_evidence"

# ---------------------------------------------------------------------------
# GatewayAuditEvent — the contract-shaped, gateway-local audit artifact
# ---------------------------------------------------------------------------

#: Required, fixed event_type value for every GatewayAuditEvent this module
#: produces (distinct from the outer basis-core AuditEvent.event_type, which
#: remains AuditEventType.SYSTEM_EVENT per the existing gateway convention).
GATEWAY_AUDIT_EVENT_TYPE = "gateway_authorization"

_VALID_EVALUATION_STATUSES = frozenset({"completed", "failed"})
_VALID_ENFORCEMENT_ACTIONS = frozenset({"allow", "deny"})


@dataclass(frozen=True, slots=True)
class GatewayAuditEvent:
    """Narrowly-scoped, gateway-local contract-shaped audit artifact.

    Not a ``basis-schemas`` contract and not a superset/subset of the v0.1
    ``basis_core.audit.AuditEvent`` — a small, independent, immutable record
    combining the kernel's evaluation-state facts (preserved exactly) with a
    reference (``audit_evidence_id``) to the kernel's ``AuditEvidence``. The
    complete ``AuditEvidence`` itself is never a field of this class — see
    this module's docstring and ``build_operation_aware_audit_detail`` for
    where it is durably recorded instead.

    Every field is copied verbatim from
    ``OperationAwareEnforcementResult.response``/``.disposition``/
    ``.audit_evidence.evidence_id`` — none is recomputed, derived from a
    different field, or gateway-synthesized. ``__post_init__`` validates
    internal consistency defensively (the same evaluation-state invariants
    the kernel's own models enforce), so a contradictory, manually
    constructed instance is rejected at construction time rather than
    silently accepted.
    """

    event_type: str
    request_id: str
    evaluation_status: str
    outcome: str | None
    failure_reason: str | None
    audit_evidence_id: str
    enforcement_action: str

    def __post_init__(self) -> None:
        if self.event_type != GATEWAY_AUDIT_EVENT_TYPE:
            raise ValueError(
                f"GatewayAuditEvent.event_type must be {GATEWAY_AUDIT_EVENT_TYPE!r}, "
                f"got {self.event_type!r}."
            )
        if not self.request_id or not self.request_id.strip():
            raise ValueError("GatewayAuditEvent.request_id must not be empty.")
        if self.evaluation_status not in _VALID_EVALUATION_STATUSES:
            raise ValueError(
                "GatewayAuditEvent.evaluation_status must be one of "
                f"{sorted(_VALID_EVALUATION_STATUSES)}, got {self.evaluation_status!r}."
            )
        if self.evaluation_status == "failed":
            if self.outcome is not None:
                raise ValueError(
                    "GatewayAuditEvent.outcome must be null when evaluation_status is "
                    "'failed'; a failed evaluation must never carry a substantive outcome."
                )
            if not self.failure_reason:
                raise ValueError(
                    "GatewayAuditEvent.failure_reason must be non-null when "
                    "evaluation_status is 'failed'."
                )
        else:  # "completed"
            if self.outcome is None:
                raise ValueError(
                    "GatewayAuditEvent.outcome must be non-null when evaluation_status "
                    "is 'completed'."
                )
            if self.failure_reason is not None:
                raise ValueError(
                    "GatewayAuditEvent.failure_reason must be null when evaluation_status "
                    "is 'completed'."
                )
        if not self.audit_evidence_id or not self.audit_evidence_id.strip():
            raise ValueError("GatewayAuditEvent.audit_evidence_id must not be empty.")
        if self.enforcement_action not in _VALID_ENFORCEMENT_ACTIONS:
            raise ValueError(
                "GatewayAuditEvent.enforcement_action must be one of "
                f"{sorted(_VALID_ENFORCEMENT_ACTIONS)}, got {self.enforcement_action!r}."
            )

    def to_dict(self) -> dict[str, Any]:
        """Deterministic, JSON-safe mapping of this event's fields.

        A plain ``dict`` literal — every value here is already a JSON
        primitive (``str`` or ``None``), so no further serialization step is
        required.
        """
        return {
            "event_type": self.event_type,
            "request_id": self.request_id,
            "evaluation_status": self.evaluation_status,
            "outcome": self.outcome,
            "failure_reason": self.failure_reason,
            "audit_evidence_id": self.audit_evidence_id,
            "enforcement_action": self.enforcement_action,
        }


def assemble_gateway_audit_event(
    result: OperationAwareEnforcementResult,
) -> GatewayAuditEvent | None:
    """Build the contract-shaped ``GatewayAuditEvent`` for *result*.

    Returns ``None`` when ``result.audit_evidence`` is ``None`` — this
    function never fabricates an ``audit_evidence_id`` and never claims a
    completed, auditable evaluation occurred when the kernel could not
    produce trustworthy evidence. Callers must route that case to
    ``emit_operation_aware_missing_evidence_event`` instead.

    Every value below is copied verbatim from *result* — ``NOT_APPLICABLE``
    stays ``"not_applicable"``, a failed evaluation keeps ``outcome=None``,
    and ``enforcement_action`` is always ``result.disposition.value`` (never
    derived from ``outcome``).
    """
    if result.audit_evidence is None:
        return None

    response = result.response
    return GatewayAuditEvent(
        event_type=GATEWAY_AUDIT_EVENT_TYPE,
        request_id=response.request_id,
        evaluation_status=response.evaluation_status.value,
        outcome=response.outcome.value if response.outcome is not None else None,
        failure_reason=(
            response.failure_reason.value if response.failure_reason is not None else None
        ),
        audit_evidence_id=result.audit_evidence.evidence_id,
        enforcement_action=result.disposition.value,
    )


# ---------------------------------------------------------------------------
# Safe serialization
# ---------------------------------------------------------------------------


def serialize_audit_evidence(evidence: AuditEvidence) -> dict[str, Any]:
    """Deterministic, JSON-safe serialization of *evidence*.

    Uses the model's own public serialization interface
    (``model_dump(mode="json")``) — never ``repr()``, never a hand-rolled
    field walk. ``AuditEvidence`` is itself frozen (``ConfigDict(frozen=True)``)
    and ``model_dump`` never mutates the source model, so *evidence* is
    unchanged by this call. Enum members serialize to their governed string
    values; ``recorded_at`` serializes to a stable ISO 8601 string;
    ``matched_rule_ids`` order is preserved exactly; required-nullable
    fields (``outcome``, ``failure_reason``) remain explicit ``null`` when
    absent (the model's own wrap-serializer already guarantees this even
    though ``exclude_none`` is not requested here).
    """
    return evidence.model_dump(mode="json")


def serialize_provenance(provenance: Mapping[str, ProvenanceClassification]) -> dict[str, str]:
    """Deterministic, JSON-safe serialization of a provenance mapping.

    Preserves every key exactly as supplied and serializes each
    ``ProvenanceClassification`` enum member to its governed string value —
    never upgrades a producer assertion to "verified," never infers
    provenance from a value's apparent plausibility, and never mutates the
    source mapping (a new ``dict`` is always returned).
    """
    return {key: value.value for key, value in provenance.items()}


# ---------------------------------------------------------------------------
# Durable envelope assembly
# ---------------------------------------------------------------------------


def build_operation_aware_audit_detail(
    *,
    gateway_audit_event: GatewayAuditEvent,
    audit_evidence: AuditEvidence,
    http_method: str,
    request_path: str,
    http_status: int,
    operation_producer_subject_id: str | None,
    operation_producer_trust_status: str,
    operation_producer_trust_source: str,
    provenance: Mapping[str, ProvenanceClassification],
) -> dict[str, Any]:
    """Build the outer durable record's ``detail`` payload.

    Contains the two clearly separated artifacts required by the central
    persistence rule — ``gateway_audit_event`` (the contract-shaped
    reference-carrying event) and ``audit_evidence`` (the complete kernel
    evidence, serialized in full) — beside the gateway-owned enforcement
    facts already available at the route boundary. ``audit_evidence`` is
    never nested inside ``gateway_audit_event``, and ``gateway_audit_event``
    is never written without ``audit_evidence`` present in this same dict.
    """
    return {
        "http_method": http_method,
        "request_path": request_path,
        "http_status": http_status,
        "operation_producer_subject_id": operation_producer_subject_id,
        "operation_producer_trust_status": operation_producer_trust_status,
        "operation_producer_trust_source": operation_producer_trust_source,
        "enforcement_action": gateway_audit_event.enforcement_action,
        "provenance": serialize_provenance(provenance),
        "gateway_audit_event": gateway_audit_event.to_dict(),
        "audit_evidence": serialize_audit_evidence(audit_evidence),
    }


# ---------------------------------------------------------------------------
# Emission helpers
# ---------------------------------------------------------------------------

_OA_REQUEST_PATH = "/v1/evaluate/operation-aware"


def emit_operation_aware_system_event(
    writer: AuditWriter | None,
    *,
    action: str,
    correlation_id: str | None = None,
    request_path: str = _OA_REQUEST_PATH,
    http_method: str = "POST",
    reason: str | None = None,
    http_status: int | None = None,
    subject_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Emit a pre-kernel/system operation-aware gateway audit event.

    Mirrors ``audit/gateway_events.py``'s ``emit_gateway_event`` exactly in
    spirit — always safe to call (no-ops on a ``None`` writer, catches and
    logs any write exception rather than propagating it) — extended with an
    ``http_status`` field so the actual HTTP result selected is always
    recorded alongside the gateway's own action/reason classification.

    Never includes raw tokens, claims, request bodies, policy bundles, or
    exception text — *detail* is caller-supplied structured context only.
    """
    if writer is None:
        return

    event_detail: dict[str, object] = {
        "http_method": http_method,
        "request_path": request_path,
    }
    if http_status is not None:
        event_detail["http_status"] = http_status
    if detail:
        event_detail.update(detail)

    try:
        event = AuditEvent(
            event_type=AuditEventType.SYSTEM_EVENT,
            action=action,
            reason=reason,
            correlation_id=correlation_id,
            subject_id=subject_id,
            detail=event_detail,
        )
        writer.write(event)
    except Exception as exc:
        log.error(
            "Operation-aware gateway audit write failed (action=%s, correlation_id=%s): %s",
            action,
            correlation_id,
            exc,
        )


def emit_operation_aware_completed_event(
    writer: AuditWriter | None,
    *,
    result: OperationAwareEnforcementResult,
    composed: ComposedOperationAwareInput,
    http_status: int,
    request_path: str = _OA_REQUEST_PATH,
    http_method: str = "POST",
) -> None:
    """Emit the one completed durable operation-aware gateway record.

    Requires ``result.audit_evidence is not None`` — callers must check this
    themselves (or simply call ``emit_operation_aware_missing_evidence_event``
    when it is ``None``); this function defends against being called with
    missing evidence by routing to that same missing-evidence path rather
    than fabricating anything.

    Never rewrites ``response.outcome``/``failure_reason``, never reorders
    ``matched_rule_ids``, never recomputes ``enforcement_action`` from
    ``outcome`` — every kernel fact is copied through ``assemble_gateway_
    audit_event``/``serialize_audit_evidence`` unchanged.
    """
    if writer is None:
        return

    gateway_event = assemble_gateway_audit_event(result)
    if gateway_event is None or result.audit_evidence is None:
        emit_operation_aware_missing_evidence_event(
            writer,
            composed=composed,
            http_status=http_status,
            request_path=request_path,
            http_method=http_method,
        )
        return

    detail = build_operation_aware_audit_detail(
        gateway_audit_event=gateway_event,
        audit_evidence=result.audit_evidence,
        http_method=http_method,
        request_path=request_path,
        http_status=http_status,
        operation_producer_subject_id=composed.operation_producer_trust.operation_producer_subject_id,
        operation_producer_trust_status=composed.operation_producer_trust.status.value,
        operation_producer_trust_source=composed.operation_producer_trust.source.value,
        provenance=composed.provenance,
    )

    outcome = (
        AuditOutcome.ALLOWED
        if result.disposition is EnforcementDisposition.ALLOW
        else AuditOutcome.DENIED
    )

    try:
        event = AuditEvent(
            event_type=AuditEventType.SYSTEM_EVENT,
            action=AUTHORIZATION_COMPLETED,
            outcome=outcome,
            correlation_id=composed.correlation_id,
            subject_id=composed.authorization_subject.subject_id,
            request_id=gateway_event.request_id,
            detail=detail,
        )
        writer.write(event)
    except Exception as exc:
        log.error(
            "Operation-aware completed gateway audit write failed (request_id=%s, "
            "correlation_id=%s): %s",
            gateway_event.request_id,
            composed.correlation_id,
            exc,
        )


def emit_operation_aware_missing_evidence_event(
    writer: AuditWriter | None,
    *,
    composed: ComposedOperationAwareInput,
    http_status: int,
    request_path: str = _OA_REQUEST_PATH,
    http_method: str = "POST",
) -> None:
    """Emit the integration-failure system event for a missing ``AuditEvidence``.

    Used only when the kernel was actually invoked
    (``OperationAwareGatewayEvaluator.evaluate()`` returned normally) but
    ``result.audit_evidence`` is ``None`` — the enforcement point's own
    catastrophic-internal-error fallback (never reachable through an
    ordinary governed failure, which always carries evidence). Never
    constructs a ``GatewayAuditEvent``, never fabricates an
    ``audit_evidence_id``, and never claims a completed auditable evaluation
    occurred.
    """
    if writer is None:
        return

    producer_trust = composed.operation_producer_trust
    detail: dict[str, object] = {
        "http_method": http_method,
        "request_path": request_path,
        "http_status": http_status,
        "operation_producer_subject_id": producer_trust.operation_producer_subject_id,
        "operation_producer_trust_status": producer_trust.status.value,
    }

    try:
        event = AuditEvent(
            event_type=AuditEventType.SYSTEM_EVENT,
            action=EVIDENCE_MISSING,
            reason=REASON_MISSING_AUDIT_EVIDENCE,
            correlation_id=composed.correlation_id,
            subject_id=composed.authorization_subject.subject_id,
            request_id=composed.request_id,
            detail=detail,
        )
        writer.write(event)
    except Exception as exc:
        log.error(
            "Operation-aware missing-evidence gateway audit write failed (request_id=%s, "
            "correlation_id=%s): %s",
            composed.request_id,
            composed.correlation_id,
            exc,
        )
