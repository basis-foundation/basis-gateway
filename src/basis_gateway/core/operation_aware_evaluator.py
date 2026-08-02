"""Operation-aware kernel request construction and enforcement-point wrapper.

Part of the operation-aware gateway integration
(``docs/implementation/operation-aware-gateway-integration-plan.md``, §7, §8,
§8a, §16 PR 5). This module connects the trusted, gateway-composed
``ComposedOperationAwareInput`` (PR 4,
``basis_gateway.core.operation_aware_composition``) to the released public
``basis-core`` v0.2.1 operation-aware surface:

- ``build_operation_aware_decision_request`` maps a ``ComposedOperationAwareInput``
  into the public ``basis_core.decisions.OperationAwareDecisionRequest``
  without reinterpreting any composed value.
- ``OperationAwareGatewayEvaluator`` wraps one real, process-lifetime public
  ``basis_core.enforcement.OperationAwareEnforcementPoint``, generating
  fresh ``trace_id``/``evidence_id``/``recorded_at`` metadata for every real
  evaluation call and returning the kernel's result unchanged.
- ``preflight_operation_aware_evaluator`` runs the startup semantic
  preflight (§8a) against a synthetic, reserved request through the same
  real public enforcement path — never ``validate_policy_bundle`` or any
  other internal ``basis_core.evaluation.*``/``basis_core.policy.operation_aware.validation``
  symbol.
- ``build_operation_aware_evaluator``/``load_and_build_operation_aware_evaluator``
  compose loading, construction, and preflight into the one sequence that
  must complete before a usable evaluator is ever returned.

This module does not register an HTTP route, does not emit operational
audit events, and does not classify a kernel result into an HTTP status —
those are PR 6/PR 7's responsibilities.

Field mapping notes (§7, §8)
-----------------------------
``ComposedOperationAwareInput.context`` (PR 4's combined free-form
context + composition evidence dict) has **no corresponding field** on the
public ``OperationAwareDecisionRequest`` — that contract deliberately
replaces the v0.1-era ``context: dict[str, str]`` catch-all with governed,
explicit, named context categories instead (see
``basis_core.decisions.operation_aware``'s module docstring, "Deliberately
absent fields"; the model's ``extra="forbid"`` configuration would reject an
invented field even if this module tried). This is a structural fact about
the released public contract, not a silent gateway-side drop: there is no
kernel field to populate. The bounded caller-facing correction for this gap
(a caller may not supply non-empty free-form ``context`` on the
operation-aware path at all) lives in
``basis_gateway.api.operation_aware_schemas.OperationAwareEvaluateRequest``,
not here — this module only ever sees an already-composed input whose
``context`` is either empty or gateway composition evidence.

``identity_source``/``authority_mode`` are likewise left unset. Per the
integration plan's provenance table (§5), both are "Gateway-derived /
configuration-derived ... Absent — never guessed," and PR 4's
``ComposedOperationAwareInput`` carries no field for either (no
``AuthMode``-derived or ``basis-identity``-sourced value has been composed
in this rollout) — there is nothing populated to map, so both stay ``None``
rather than being invented from an unrelated value (e.g. the raw JWT
``iss`` claim, which this module does not repurpose as ``identity_source``).

``expected_policy_version`` is left unset per §5b — this rollout does not
accept, derive, or compare it.

``correlation_id`` **is** mapped: unlike the fields above, the public
request model explicitly defines a ``correlation_id`` field ("passed
through verbatim; no format constraint beyond string-or-None"), so the
gateway-generated correlation ID PR 4 already carries on
``ComposedOperationAwareInput`` populates it directly — it is not invented,
and it is not one of the gateway-only facts (producer-trust classification,
provenance map, HTTP/route information, audit-writer state) this module
keeps out of the kernel request.

Import boundary (§8) — resolved by basis-core v0.2.1's public factory
------------------------------------------------------------------------
``basis-core`` v0.2.0 had no public factory or default constructor for
``OperationAwareEnforcementPoint`` that did not require directly
instantiating ``OperationAwareEvaluationEngine`` — an internal
``basis_core.evaluation.*`` symbol §8 designates as off-limits to this
repository. ``basis-core`` v0.2.1 (`fix/public-operation-aware-enforcement-
factory`) closes that gap with
``OperationAwareEnforcementPoint.for_bundle(bundle)``: a documented public
classmethod that constructs the internal engine *inside basis-core* and
returns a fully-constructed enforcement point, without this module ever
importing, naming, or otherwise knowing that ``OperationAwareEvaluationEngine``
exists. This module now imports only from ``basis_core.decisions``,
``basis_core.enforcement``, and ``basis_core.policy`` — every one of them a
documented public package path — and constructs every
``OperationAwareEnforcementPoint`` (real evaluation, semantic preflight, and
evaluator-factory construction alike) exclusively through ``for_bundle()``.
There is no fallback to the direct ``__init__(engine=..., bundle=...)``
constructor anywhere in this module.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from basis_core.decisions import OperationAwareDecisionRequest
from basis_core.decisions.operation_aware import (
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)
from basis_core.enforcement import OperationAwareEnforcementPoint, OperationAwareEnforcementResult
from basis_core.policy import PolicyBundle
from pydantic import ValidationError

from basis_gateway.core.actions import RESERVED_CONTEXT_PREFIX
from basis_gateway.core.operation_aware_composition import ComposedOperationAwareInput
from basis_gateway.policy.operation_aware_loader import load_operation_aware_policy_bundle

log = logging.getLogger(__name__)

__all__ = [
    "OperationAwareEvaluatorInternalError",
    "OperationAwareGatewayEvaluator",
    "OperationAwarePreflightError",
    "OperationAwareRequestConstructionError",
    "build_operation_aware_decision_request",
    "build_operation_aware_evaluator",
    "load_and_build_operation_aware_evaluator",
    "preflight_operation_aware_evaluator",
]


# ---------------------------------------------------------------------------
# Kernel request construction
# ---------------------------------------------------------------------------


class OperationAwareRequestConstructionError(Exception):
    """Raised when a public-model ``ValidationError`` occurs while
    constructing ``OperationAwareDecisionRequest`` from an already-composed
    ``ComposedOperationAwareInput``.

    A gateway-owned, pre-kernel construction failure (§8) — never raised by
    kernel evaluation itself. The full composed input and the underlying
    ``ValidationError``'s field-level detail are never included in the
    message; only a bounded error count.
    """


def _reject_unexpected_composed_context_keys(context: Mapping[str, str]) -> None:
    """Internal-invariant guard (§8): every key in an already-composed
    ``ComposedOperationAwareInput.context`` must be gateway-owned
    composition evidence (the reserved ``basis_gateway.*`` namespace).

    PR 3's ``OperationAwareEvaluateRequest.context`` is validated empty-only
    (``operation_aware_schemas.OperationAwareEvaluateRequest``), so an
    ordinary caller-originated request can never reach this function with a
    non-reserved key present — reserved-namespace composition evidence
    (``core/actions.py``'s ``build_composition_evidence``,
    ``core/resources.py``'s ``build_resource_composition_evidence``) is the
    only thing PR 4's ``compose_operation_aware_input`` ever adds to an
    empty caller context. This check exists as defense-in-depth for a
    ``ComposedOperationAwareInput`` constructed some other way (directly, by
    a test, or by future gateway code) that carries an unexpected key: that
    is a gateway-internal contract violation, never silently discarded here.
    """
    unexpected = sorted(key for key in context if not key.startswith(RESERVED_CONTEXT_PREFIX))
    if unexpected:
        raise OperationAwareRequestConstructionError(
            "composed operation-aware context contains key(s) outside the reserved "
            f"{RESERVED_CONTEXT_PREFIX!r} gateway namespace ({len(unexpected)} unexpected "
            "key(s)); this is a gateway-internal contract violation, not caller input, "
            "and is never silently discarded."
        )


def build_operation_aware_decision_request(
    composed: ComposedOperationAwareInput,
) -> OperationAwareDecisionRequest:
    """Construct the public ``OperationAwareDecisionRequest`` from *composed*.

    Maps every ``ComposedOperationAwareInput`` field that has a
    corresponding public kernel field, unchanged — never reinterpreting,
    never gateway-recomputing. Fields PR 4 preserved as absent (``None``)
    stay absent here; no empty-but-present object is synthesized for any of
    them. See this module's docstring for the two fields (``context``,
    ``identity_source``/``authority_mode``) that have no composed-to-kernel
    mapping at all, and for why ``correlation_id`` *is* mapped despite being
    gateway-generated.

    Before construction, verifies every ``composed.context`` key uses the
    reserved gateway namespace (see ``_reject_unexpected_composed_context_keys``)
    — an unexpected key is a gateway-internal contract violation, never
    silently dropped.

    Does not mutate *composed*.

    Raises:
        OperationAwareRequestConstructionError: the public model's own
            construction-time validation rejects the composed values (a
            gateway-owned, pre-kernel failure — see this module's
            docstring), or *composed.context* contains a key outside the
            reserved gateway namespace.
    """
    _reject_unexpected_composed_context_keys(composed.context)

    # Subject attributes: OperationAwareDecisionRequest.subject_attrs is
    # dict[str, str]; NormalizedSubject.attributes is dict[str, Any].
    # Mirrors the existing gateway subject-mapping convention already
    # established by core/evaluator.py's _build_subject() — only string
    # values are forwarded, non-string values are silently dropped (they
    # cannot losslessly become subject_attrs entries), never coerced with
    # str() (which would fabricate string content for a non-string claim).
    subject_attrs: dict[str, str] = {
        key: value
        for key, value in composed.authorization_subject.attributes.items()
        if isinstance(value, str)
    }

    try:
        return OperationAwareDecisionRequest(
            request_id=composed.request_id,
            correlation_id=composed.correlation_id,
            subject_id=composed.authorization_subject.subject_id,
            subject_roles=list(composed.authorization_subject.roles),
            subject_attrs=subject_attrs,
            identity_evidence_reference=composed.identity_evidence_reference,
            action=composed.action,
            resource=composed.resource_id,
            resource_type=composed.resource_type,
            location=composed.location,
            device=composed.device,
            protocol_context=composed.protocol_context,
            operation_intent=composed.operation_intent,
            adapter_evidence_reference=composed.adapter_evidence_reference,
            safety_context=composed.safety_context,
            environment_context=composed.environment_context,
            risk_context=composed.risk_context,
            evaluation_time=composed.evaluation_time,
        )
    except ValidationError as exc:
        raise OperationAwareRequestConstructionError(
            "Failed to construct OperationAwareDecisionRequest from composed "
            f"operation-aware input ({exc.error_count()} validation error(s))."
        ) from exc


# ---------------------------------------------------------------------------
# Per-call metadata generation
# ---------------------------------------------------------------------------


class OperationAwareEvaluatorInternalError(RuntimeError):
    """Raised for a gateway-internal programming error in the evaluator
    wrapper — reserved for an injected ``clock`` factory that returned a
    naive (non-timezone-aware) ``datetime``. No caller-controlled request
    content can trigger this exception.
    """


def _default_trace_id() -> str:
    return str(uuid.uuid4())


def _default_evidence_id() -> str:
    return str(uuid.uuid4())


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


def _require_tz_aware(value: datetime, *, source: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OperationAwareEvaluatorInternalError(
            f"{source} returned a naive datetime; recorded_at must always be "
            "timezone-aware. This indicates a gateway-internal programming error in the "
            "injected clock, never caller input."
        )


# ---------------------------------------------------------------------------
# OperationAwareGatewayEvaluator
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OperationAwareGatewayEvaluator:
    """Process-lifetime wrapper around a real public
    ``OperationAwareEnforcementPoint``.

    Constructed once at startup (via ``build_operation_aware_evaluator``),
    after the wrapped enforcement point has already passed the startup
    semantic preflight (§8a). Holds no mutable state: ``evaluate()`` reads
    only its arguments and the injected factories, and never retains
    caller-specific context between calls.

    The three factories (``trace_id_factory``, ``evidence_id_factory``,
    ``clock``) are each called exactly once per ``evaluate()`` call, never
    reused across calls, and never influenced by caller-supplied request
    content — per §8's "fresh per-call values" requirement. Defaults use
    UUIDv4 (``uuid.uuid4()``) and a timezone-aware UTC clock
    (``datetime.now(timezone.utc)``); tests may inject deterministic
    factories.
    """

    _enforcement_point: OperationAwareEnforcementPoint
    _trace_id_factory: Callable[[], str]
    _evidence_id_factory: Callable[[], str]
    _clock: Callable[[], datetime]

    def evaluate(self, composed: ComposedOperationAwareInput) -> OperationAwareEnforcementResult:
        """Build the kernel request from *composed* and evaluate it.

        Returns the real public ``OperationAwareEnforcementResult``
        unchanged — status, outcome, failure reason, trace, evidence, and
        disposition are never rewritten, recomputed, or reinterpreted here.
        Never mutates *composed*.

        Raises:
            OperationAwareRequestConstructionError: request construction
                failed (a gateway-owned, pre-kernel failure — see
                ``build_operation_aware_decision_request``).
            OperationAwareEvaluatorInternalError: the injected clock
                returned a naive ``datetime`` (gateway-internal programming
                error, never caller-triggered).
        """
        request = build_operation_aware_decision_request(composed)

        trace_id = self._trace_id_factory()
        evidence_id = self._evidence_id_factory()
        recorded_at = self._clock()
        _require_tz_aware(recorded_at, source="clock()")

        return self._evaluate_with_metadata(
            request=request,
            trace_id=trace_id,
            evidence_id=evidence_id,
            recorded_at=recorded_at,
        )

    def _evaluate_with_metadata(
        self,
        *,
        request: OperationAwareDecisionRequest,
        trace_id: str,
        evidence_id: str,
        recorded_at: datetime,
    ) -> OperationAwareEnforcementResult:
        """Shared kernel-invocation path for both real evaluation
        (``evaluate()``) and the startup semantic preflight
        (``preflight_operation_aware_evaluator``). Never called with
        caller-influenced ``trace_id``/``evidence_id``/``recorded_at`` from
        ``evaluate()`` itself — only from within this class or from the
        preflight function's own fixed, reserved values.
        """
        return self._enforcement_point.evaluate(
            request=request,
            trace_id=trace_id,
            evidence_id=evidence_id,
            recorded_at=recorded_at,
        )


# ---------------------------------------------------------------------------
# Startup semantic preflight (§8a)
# ---------------------------------------------------------------------------

#: Reserved, clearly-synthetic identifiers for the preflight-only request —
#: never a live caller identity, never reused for a real evaluation.
_PREFLIGHT_REQUEST_ID = "basis-gateway:operation-aware-preflight"
_PREFLIGHT_SUBJECT_ID = "basis-gateway:preflight-subject"
#: A syntactically valid action (matches OperationAwareDecisionRequest's
#: `{verb}:{domain}` pattern) reserved for preflight use and unlikely to
#: match deployment policy — the preflight does not require or expect a
#: particular outcome (§8a: any *completed* result proves the bundle passed
#: semantic validation, regardless of which outcome the synthetic request
#: happens to produce).
_PREFLIGHT_ACTION = "read:basis_gateway_preflight"
#: Distinctly namespaced so preflight evidence/trace identifiers can never
#: collide with, or be mistaken for, a real request's identifiers.
_PREFLIGHT_TRACE_ID = "preflight-trace-basis-gateway-operation-aware"
_PREFLIGHT_EVIDENCE_ID = "preflight-evidence-basis-gateway-operation-aware"


class OperationAwarePreflightError(Exception):
    """Raised when the startup semantic preflight (§8a) does not reach a
    completed evaluation for the synthetic preflight request.

    Exposes only safe, closed-vocabulary scalar fields —
    ``evaluation_status``/``failure_reason`` — never the full kernel
    request, policy bundle, trace, or evidence.
    """

    def __init__(
        self,
        message: str,
        *,
        evaluation_status: OperationAwareEvaluationStatus | None,
        failure_reason: OperationAwareFailureReason | None,
    ) -> None:
        self.evaluation_status = evaluation_status
        self.failure_reason = failure_reason
        super().__init__(message)


def _build_preflight_request(*, evaluation_time: datetime) -> OperationAwareDecisionRequest:
    """Build the fixed, reserved, structurally-valid synthetic preflight
    request. Carries no live caller identity, no real operational context,
    and no fabricated "safe"/"normal" context — every optional
    operation-aware field is left absent, exactly as an ordinary request
    that supplies none of them would be (§8a).
    """
    return OperationAwareDecisionRequest(
        request_id=_PREFLIGHT_REQUEST_ID,
        subject_id=_PREFLIGHT_SUBJECT_ID,
        action=_PREFLIGHT_ACTION,
        evaluation_time=evaluation_time,
    )


def preflight_operation_aware_evaluator(
    evaluator: OperationAwareGatewayEvaluator,
) -> OperationAwareEnforcementResult:
    """Run the startup semantic preflight (§8a) against *evaluator*.

    Evaluates one deterministic, synthetic, reserved request through the
    same real public ``OperationAwareEnforcementPoint``/
    ``OperationAwareDecisionRequest`` path used for real evaluations —
    never ``validate_policy_bundle`` or any other internal symbol. Because
    policy-bundle semantic validation is the unconditional first step of
    ``OperationAwareEvaluationEngine.evaluate()``, *any* completed result
    (``ALLOW``, explicit ``DENY``, default deny, or ``NOT_APPLICABLE``)
    proves the loaded bundle passed semantic validation, regardless of the
    synthetic request's own outcome.

    A result whose ``evaluation_status`` is not
    ``OperationAwareEvaluationStatus.COMPLETED`` fails the preflight —
    conservatively, for *every* governed failure reason, not only
    ``invalid_policy_bundle``/``policy_validation_failure`` (§8a step 5: an
    unexpected failure reason from the gateway's own synthetic request is
    itself unexpected and is not treated as an ordinary policy-authoring
    result).

    This function never writes to the operational audit stream — it takes
    no ``AuditWriter``/``GatewayAuditWriter`` dependency at all, and the
    preflight's own ``OperationAwareEnforcementResult`` (response, audit
    evidence, disposition) is returned to the caller only for logging, not
    persisted anywhere.

    Returns:
        The preflight's ``OperationAwareEnforcementResult``, on success —
        callers may log it (with an explicit preflight marker) but must
        not treat it as a real evaluation.

    Raises:
        OperationAwarePreflightError: the preflight did not reach a
            completed evaluation.
    """
    recorded_at = datetime.now(timezone.utc)
    request = _build_preflight_request(evaluation_time=recorded_at)

    result = evaluator._evaluate_with_metadata(  # noqa: SLF001 - same-module cooperating function
        request=request,
        trace_id=_PREFLIGHT_TRACE_ID,
        evidence_id=_PREFLIGHT_EVIDENCE_ID,
        recorded_at=recorded_at,
    )

    response = result.response
    if response.evaluation_status is not OperationAwareEvaluationStatus.COMPLETED:
        failure_reason_repr = (
            response.failure_reason.value if response.failure_reason is not None else None
        )
        raise OperationAwarePreflightError(
            "Operation-aware policy bundle failed startup semantic preflight "
            f"(evaluation_status={response.evaluation_status.value!r}, "
            f"failure_reason={failure_reason_repr!r}).",
            evaluation_status=response.evaluation_status,
            failure_reason=response.failure_reason,
        )

    log.info(
        "Operation-aware policy bundle passed startup semantic preflight "
        "(evaluation_status=%r, outcome=%r) [preflight: true]",
        response.evaluation_status.value,
        response.outcome.value if response.outcome is not None else None,
    )
    return result


# ---------------------------------------------------------------------------
# Evaluator factory
# ---------------------------------------------------------------------------


def build_operation_aware_evaluator(
    bundle: PolicyBundle,
    *,
    trace_id_factory: Callable[[], str] = _default_trace_id,
    evidence_id_factory: Callable[[], str] = _default_evidence_id,
    clock: Callable[[], datetime] = _default_clock,
) -> OperationAwareGatewayEvaluator:
    """Construct the real enforcement point, wrap it, and run the semantic
    preflight — in that order. A usable evaluator is never returned before
    preflight succeeds.

    Args:
        bundle: an already-loaded, structurally-valid public
            ``PolicyBundle`` (see ``load_operation_aware_policy_bundle``).
        trace_id_factory: called once per real ``evaluate()`` call. Default
            generates a fresh UUIDv4 string.
        evidence_id_factory: called once per real ``evaluate()`` call.
            Default generates a fresh UUIDv4 string.
        clock: called once per real ``evaluate()`` call. Default returns
            ``datetime.now(timezone.utc)``.

    Returns:
        An initialized ``OperationAwareGatewayEvaluator`` that has already
        passed the startup semantic preflight.

    Raises:
        OperationAwarePreflightError: the startup semantic preflight
            failed — see ``preflight_operation_aware_evaluator``.
    """
    enforcement_point = OperationAwareEnforcementPoint.for_bundle(bundle)
    evaluator = OperationAwareGatewayEvaluator(
        _enforcement_point=enforcement_point,
        _trace_id_factory=trace_id_factory,
        _evidence_id_factory=evidence_id_factory,
        _clock=clock,
    )
    preflight_operation_aware_evaluator(evaluator)
    return evaluator


def load_and_build_operation_aware_evaluator(
    path: str | Path,
    *,
    trace_id_factory: Callable[[], str] = _default_trace_id,
    evidence_id_factory: Callable[[], str] = _default_evidence_id,
    clock: Callable[[], datetime] = _default_clock,
) -> OperationAwareGatewayEvaluator:
    """Load the bundle from *path* and build a preflighted evaluator.

    Composes ``load_operation_aware_policy_bundle`` and
    ``build_operation_aware_evaluator`` — kept as two separately-callable
    functions (this one is a thin convenience wrapper) so file loading and
    evaluator construction each remain independently testable.

    Raises:
        OperationAwarePolicyLoadError: structural bundle loading failed.
        OperationAwarePreflightError: the startup semantic preflight
            failed.
    """
    bundle = load_operation_aware_policy_bundle(path)
    return build_operation_aware_evaluator(
        bundle,
        trace_id_factory=trace_id_factory,
        evidence_id_factory=evidence_id_factory,
        clock=clock,
    )
