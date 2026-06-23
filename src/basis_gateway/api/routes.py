"""Route definitions for basis-gateway.

Endpoints:
  GET  /health         — liveness probe
  GET  /ready          — readiness probe
  POST /v1/evaluate    — authorization evaluation
"""

from __future__ import annotations

import logging
from typing import Any

from basis_core.decisions import DecisionOutcome
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from basis_gateway.api.schemas import ErrorResponse, EvaluateRequest, EvaluateResponse
from basis_gateway.audit.gateway_events import (
    AUDIT_RECOVERY_PROBE,
    AUTHENTICATION_FAILED,
    EVALUATION_FAILED_CLOSED,
    EVALUATION_REQUESTED,
    EVALUATOR_UNAVAILABLE,
    REASON_EVALUATION_EXCEPTION,
    REASON_EVALUATOR_NOT_INITIALIZED,
    REASON_IDENTITY_NORMALIZATION_FAILED,
    REASON_INVALID_DECISION_REQUEST,
    REASON_INVALID_FIELDS,
    REASON_INVALID_TOKEN,
    REASON_MALFORMED_BODY,
    REASON_MISSING_TOKEN,
    REASON_VERIFIER_NOT_CONFIGURED,
    VALIDATION_FAILED,
    emit_gateway_event,
)
from basis_gateway.auth.errors import AuthenticationError, SubjectMappingError, TokenExtractionError
from basis_gateway.auth.oidc import extract_bearer_token
from basis_gateway.auth.subject_mapper import map_claims
from basis_gateway.core.actions import (
    RESERVED_CONTEXT_PREFIX,
    ActionCompositionError,
    build_composition_evidence,
    compose_action,
    reserved_key_collisions,
)
from basis_gateway.core.evaluator import GatewayEvaluator
from basis_gateway.core.resources import (
    ResourceCompositionError,
    build_resource_composition_evidence,
    compose_resource_id,
)
from basis_gateway.readiness import get_readiness_state

log = logging.getLogger(__name__)
router = APIRouter()

_SERVICE_NAME = "basis-gateway"


# ---------------------------------------------------------------------------
# Operational endpoints
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str
    service: str


class ReadyResponse(BaseModel):
    status: str
    service: str
    components: dict[str, bool] | None = None
    reason: str | None = None
    reasons: dict[str, str] | None = None
    correlation_id: str | None = None


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
def health() -> HealthResponse:
    return HealthResponse(status="ok", service=_SERVICE_NAME)


@router.get(
    "/ready",
    summary="Readiness probe",
    response_model=ReadyResponse,
    responses={503: {"model": ReadyResponse}},
)
def ready(request: Request) -> JSONResponse:
    state = get_readiness_state()
    components = state.components or None
    if state.is_ready:
        return JSONResponse(
            status_code=200,
            content=ReadyResponse(
                status="ready",
                service=_SERVICE_NAME,
                components=components or None,
            ).model_dump(exclude_none=True),
        )
    all_reasons = state.all_reasons or None
    correlation_id: str = request.state.correlation_id
    return JSONResponse(
        status_code=503,
        content=ReadyResponse(
            status="not_ready",
            service=_SERVICE_NAME,
            components=components or None,
            reason=state.reason or "application not initialized",
            reasons=all_reasons or None,
            correlation_id=correlation_id,
        ).model_dump(exclude_none=True),
    )


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------
# Each helper accepts a correlation_id so the response body and the
# X-Correlation-ID header (set by CorrelationMiddleware) are consistent.
# ---------------------------------------------------------------------------


def _authentication_required(message: str, correlation_id: str) -> JSONResponse:
    """401 — no Bearer token was presented or the Authorization header is malformed."""
    return JSONResponse(
        status_code=401,
        content=ErrorResponse(
            error="authentication_required",
            message=message,
            correlation_id=correlation_id,
        ).model_dump(exclude_none=True),
    )


def _authentication_failed(message: str, correlation_id: str) -> JSONResponse:
    """401 — a Bearer token was present but could not be verified or mapped."""
    return JSONResponse(
        status_code=401,
        content=ErrorResponse(
            error="authentication_failed",
            message=message,
            correlation_id=correlation_id,
        ).model_dump(exclude_none=True),
    )


def _validation_failed(message: str, correlation_id: str) -> JSONResponse:
    """400 — request body failed schema validation."""
    return JSONResponse(
        status_code=400,
        content=ErrorResponse(
            error="validation_failed",
            message=message,
            correlation_id=correlation_id,
        ).model_dump(exclude_none=True),
    )


def _evaluator_unavailable(correlation_id: str) -> JSONResponse:
    """503 — the evaluator is not initialized; the service is not ready to evaluate."""
    return JSONResponse(
        status_code=503,
        content=ErrorResponse(
            error="evaluator_unavailable",
            message="Evaluator not initialized",
            correlation_id=correlation_id,
        ).model_dump(exclude_none=True),
    )


def _audit_fail_closed(correlation_id: str) -> JSONResponse:
    """503 — audit pipeline degraded and AUDIT_FAIL_CLOSED=true; evaluation suspended."""
    return JSONResponse(
        status_code=503,
        content=ErrorResponse(
            error="audit_fail_closed",
            message="Audit pipeline degraded; evaluation suspended (fail-closed mode)",
            correlation_id=correlation_id,
        ).model_dump(exclude_none=True),
    )


def _evaluation_failed_closed(correlation_id: str) -> JSONResponse:
    """500 — unexpected error during evaluation; request failed closed."""
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="evaluation_failed_closed",
            message="Evaluation failed; request denied (fail-closed)",
            correlation_id=correlation_id,
        ).model_dump(exclude_none=True),
    )


def _internal_error(correlation_id: str) -> JSONResponse:
    """500 — unexpected internal error not otherwise classified."""
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="internal_error",
            correlation_id=correlation_id,
        ).model_dump(exclude_none=True),
    )


# ---------------------------------------------------------------------------
# POST /v1/evaluate
# ---------------------------------------------------------------------------


@router.post(
    "/v1/evaluate",
    summary="Authorization evaluation",
    description=(
        "Evaluate an authorization request against the configured policy. "
        "Subject identity is derived exclusively from the Bearer token — "
        "do not provide subject_id or subject_roles in the request body. "
        "Accepts both a direct composite action (e.g. action='read:ahu') and an "
        "adapter-normalized bare verb plus resource_type (e.g. action='read', "
        "resource_type='ahu'), which the gateway composes into 'read:ahu' before "
        "evaluation. Resource identity is composed the same way: a local "
        "resource_id (e.g. 'rooftop-1') plus resource_type is composed into the "
        "typed 'ahu:rooftop-1'; an already-typed resource_id is passed through. "
        "Supplying a resource_type alongside an already-typed resource_id, or a "
        "local resource_id with no resource_type, is rejected."
    ),
    response_model=EvaluateResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": EvaluateResponse},
        500: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
async def evaluate(
    request: Request,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """Full evaluation lifecycle:
    Bearer extraction → JWT verification → subject mapping →
    DecisionRequest construction → EnforcementPoint → HTTP response.

    Fails closed on every error path. Raw token contents never appear
    in responses or logs.

    Gateway audit events are emitted at every significant outcome, including
    failures that occur before the kernel can produce a decision:
      - VALIDATION_FAILED     — request body invalid before auth
      - AUTHENTICATION_FAILED — token missing/invalid or subject unmappable
      - EVALUATOR_UNAVAILABLE — evaluator not initialized
      - EVALUATION_REQUESTED  — authenticated request received, evaluation starting
      - EVALUATION_FAILED_CLOSED — unexpected error during kernel evaluation
    """
    # Correlation ID is generated by CorrelationMiddleware and attached to
    # request.state before this handler is called. Reading it here ensures
    # the same ID is used in the evaluation path and returned in the response
    # header (also set by the middleware).
    correlation_id: str = request.state.correlation_id

    # Resolve shared context used by all gateway audit events.
    audit_writer = getattr(request.app.state, "audit_writer", None)
    http_method = request.method
    request_path = request.url.path

    # ── 0. Strict fail-closed check ──────────────────────────────────────────
    # When AUDIT_FAIL_CLOSED=true and the audit writer is degraded, we first
    # emit a lightweight probe event (no request content — correlation ID and
    # path only).  If the probe write succeeds the writer self-heals and the
    # request continues normally.  If the probe fails the writer stays degraded
    # and we return 503.
    #
    # The probe is what makes strict-mode recovery automatic: without it, no
    # audit write would ever fire in strict mode, so the writer could never
    # exit the degraded state without a process restart.  The probe contains no
    # authentication material and makes no authorization decision.
    config = getattr(request.app.state, "config", None)
    if (
        config is not None
        and getattr(config, "audit_fail_closed", False)
        and audit_writer is not None
        and getattr(audit_writer, "degraded", False)
    ):
        # Probe: attempt a safe write that carries no request secrets.
        emit_gateway_event(
            audit_writer,
            action=AUDIT_RECOVERY_PROBE,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
        )

        if getattr(audit_writer, "degraded", True):
            # Probe failed — writer still degraded; block the request.
            log.error(
                "Audit writer degraded and AUDIT_FAIL_CLOSED=true; rejecting /v1/evaluate request"
            )
            return _audit_fail_closed(correlation_id)
        # Probe succeeded — writer recovered; fall through to normal evaluation.
        log.info(
            "Audit writer recovered via fail-closed probe; proceeding with /v1/evaluate request"
        )

    # ── 1. Parse and validate request body ──────────────────────────────────
    try:
        body_bytes = await request.body()
        eval_request = EvaluateRequest.model_validate_json(body_bytes)
    except ValidationError as exc:
        errors = exc.errors(include_url=False)
        message = "; ".join(f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in errors)
        # Pydantic v2 wraps JSON parse errors as ValidationError with type
        # "json_invalid". Distinguish these from field-level schema errors so
        # the audit reason accurately reflects the failure category.
        is_json_error = any(e.get("type") == "json_invalid" for e in errors)
        emit_gateway_event(
            audit_writer,
            action=VALIDATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_MALFORMED_BODY if is_json_error else REASON_INVALID_FIELDS,
        )
        return _validation_failed(message, correlation_id)
    except Exception:
        emit_gateway_event(
            audit_writer,
            action=VALIDATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_MALFORMED_BODY,
        )
        return _validation_failed("Malformed request body", correlation_id)

    # ── 1b. Action composition boundary ──────────────────────────────────────
    # The gateway is the runtime boundary between adapter-normalized operations
    # (bare verb + resource_type) and kernel-compatible requests (composite
    # action). Composition is request *assembly* — it makes no authorization
    # decision and defines no vocabulary; basis-core remains the authority that
    # validates the resulting action.
    #
    # Done before authentication so an ambiguous or malformed request is rejected
    # consistently with the body-schema validation above (both emit
    # VALIDATION_FAILED before auth).
    #
    # First, refuse any caller-supplied context key in the gateway's reserved
    # namespace, so composition evidence can never be forged or overwritten.
    collisions = reserved_key_collisions(eval_request.context)
    if collisions:
        emit_gateway_event(
            audit_writer,
            action=VALIDATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_INVALID_FIELDS,
        )
        return _validation_failed(
            f"context keys {collisions} use the reserved '{RESERVED_CONTEXT_PREFIX}' "
            "namespace and must not be supplied by the caller",
            correlation_id,
        )

    try:
        composed_action = compose_action(eval_request.action, eval_request.resource_type)
    except ActionCompositionError as exc:
        emit_gateway_event(
            audit_writer,
            action=VALIDATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_INVALID_FIELDS,
        )
        return _validation_failed(str(exc), correlation_id)

    # Composition occurred iff a resource_type was supplied (a composite action
    # with a resource_type is rejected above, so this is unambiguous).
    did_compose = eval_request.resource_type is not None
    effective_context: dict[str, str] = dict(eval_request.context)
    if did_compose:
        assert eval_request.resource_type is not None  # narrowed by did_compose
        effective_context.update(
            build_composition_evidence(
                original_action=eval_request.action,
                resource_type=eval_request.resource_type,
                composed_action=composed_action,
            )
        )

    # ── 1c. Resource identifier composition boundary ─────────────────────────
    # The companion to action composition: adapters emit a local resource_id
    # (e.g. 'rooftop-1') plus a separate resource_type, while basis-core expects
    # a typed '{type}:{qualifier}' identifier (e.g. 'ahu:rooftop-1'). The gateway
    # composes the two. Like action composition this is request *assembly* — it
    # makes no authorization decision and defines no resource taxonomy.
    #
    # A resource_type without a resource_id is NOT a resource-specific request:
    # it is resource-independent (or domain-level) and composes no resource_id.
    # Resource composition is rejected only when the request is resource-specific
    # but cannot be made canonical (local id without a type, or an already-typed
    # id presented alongside a redundant/ambiguous resource_type).
    try:
        resource_result = compose_resource_id(eval_request.resource_type, eval_request.resource_id)
    except ResourceCompositionError as exc:
        emit_gateway_event(
            audit_writer,
            action=VALIDATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_INVALID_FIELDS,
        )
        return _validation_failed(str(exc), correlation_id)

    effective_resource_id = resource_result.resource_id
    if resource_result.composed:
        assert resource_result.original_resource_id is not None  # narrowed by composed
        assert resource_result.resource_type is not None  # narrowed by composed
        assert resource_result.resource_id is not None  # narrowed by composed
        effective_context.update(
            build_resource_composition_evidence(
                original_resource_id=resource_result.original_resource_id,
                resource_type=resource_result.resource_type,
                composed_resource_id=resource_result.resource_id,
            )
        )

    # ── 2. Bearer extraction ─────────────────────────────────────────────────
    try:
        token = extract_bearer_token(authorization)
    except TokenExtractionError as exc:
        # Missing or malformed Authorization header — no token was presented.
        emit_gateway_event(
            audit_writer,
            action=AUTHENTICATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_MISSING_TOKEN,
        )
        return _authentication_required(str(exc), correlation_id)
    except AuthenticationError as exc:
        emit_gateway_event(
            audit_writer,
            action=AUTHENTICATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_MISSING_TOKEN,
        )
        return _authentication_required(str(exc), correlation_id)

    # ── 3. JWT verification ──────────────────────────────────────────────────
    verifier = getattr(request.app.state, "verifier", None)
    if verifier is None:
        log.error("OIDC verifier not initialized; rejecting request")
        emit_gateway_event(
            audit_writer,
            action=AUTHENTICATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_VERIFIER_NOT_CONFIGURED,
        )
        return _authentication_failed("Authentication not configured", correlation_id)

    try:
        claims: dict[str, Any] = verifier.verify(token)
    except AuthenticationError as exc:
        log.info("JWT verification failed: %s", exc)
        emit_gateway_event(
            audit_writer,
            action=AUTHENTICATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_INVALID_TOKEN,
        )
        return _authentication_failed("Token verification failed", correlation_id)
    except Exception:
        log.exception("Unexpected error during JWT verification")
        emit_gateway_event(
            audit_writer,
            action=AUTHENTICATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_INVALID_TOKEN,
        )
        return _authentication_failed("Token verification failed", correlation_id)

    # ── 4. Subject mapping ───────────────────────────────────────────────────
    try:
        normalized_subject, _identity_ctx = map_claims(claims)
    except SubjectMappingError as exc:
        log.info("Subject mapping failed: %s", exc)
        emit_gateway_event(
            audit_writer,
            action=AUTHENTICATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_IDENTITY_NORMALIZATION_FAILED,
        )
        return _authentication_failed("Identity normalization failed", correlation_id)
    except Exception:
        log.exception("Unexpected error during subject mapping")
        emit_gateway_event(
            audit_writer,
            action=AUTHENTICATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_IDENTITY_NORMALIZATION_FAILED,
        )
        return _authentication_failed("Identity normalization failed", correlation_id)

    # ── 5. Get evaluator ─────────────────────────────────────────────────────
    evaluator: GatewayEvaluator | None = getattr(request.app.state, "evaluator", None)
    if evaluator is None:
        emit_gateway_event(
            audit_writer,
            action=EVALUATOR_UNAVAILABLE,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_EVALUATOR_NOT_INITIALIZED,
            subject_id=normalized_subject.subject_id,
        )
        return _evaluator_unavailable(correlation_id)

    # ── 6. Build request ID ──────────────────────────────────────────────────
    request_id = eval_request.request_id or correlation_id

    # ── 7. Pre-evaluation receipt ────────────────────────────────────────────
    # Emitted after authentication succeeds and before calling the kernel.
    # Proves the gateway received an authenticated evaluation request and
    # preserves evidence even if evaluation later fails or raises.
    policy_version: str | None = evaluator.policy_version
    emit_gateway_event(
        audit_writer,
        action=EVALUATION_REQUESTED,
        correlation_id=correlation_id,
        http_method=http_method,
        request_path=request_path,
        policy_version=policy_version,
        subject_id=normalized_subject.subject_id,
        detail={"request_id": request_id},
    )

    # ── 8. Evaluate ──────────────────────────────────────────────────────────
    try:
        decision = evaluator.evaluate(
            normalized_subject=normalized_subject,
            raw_token=token,
            claims=claims,
            action=composed_action,
            resource_id=effective_resource_id,
            request_id=request_id,
            correlation_id=correlation_id,
            context=effective_context,
        )
    except ValidationError as exc:
        # DecisionRequest validation failed (invalid action/resource_id format).
        errors = exc.errors(include_url=False)
        message = "; ".join(f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in errors)
        emit_gateway_event(
            audit_writer,
            action=EVALUATION_FAILED_CLOSED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_INVALID_DECISION_REQUEST,
            policy_version=policy_version,
            subject_id=normalized_subject.subject_id,
        )
        return _validation_failed(message, correlation_id)
    except Exception:
        log.exception("Unexpected error during evaluation")
        emit_gateway_event(
            audit_writer,
            action=EVALUATION_FAILED_CLOSED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_EVALUATION_EXCEPTION,
            policy_version=policy_version,
            subject_id=normalized_subject.subject_id,
        )
        return _evaluation_failed_closed(correlation_id)

    # ── 9. Map outcome to HTTP response ──────────────────────────────────────
    outcome = decision.outcome

    response_body = EvaluateResponse(
        request_id=decision.request_id,
        outcome=outcome.value,
        reason=decision.reason,
        policy_version=decision.policy_version,
        correlation_id=correlation_id,
    )

    status_code = 200 if outcome == DecisionOutcome.ALLOW else 403

    # X-Correlation-ID is added to all responses by CorrelationMiddleware.
    return JSONResponse(
        status_code=status_code,
        content=response_body.model_dump(exclude_none=True),
    )
