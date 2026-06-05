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
from basis_gateway.core.evaluator import GatewayEvaluator
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


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
def health() -> HealthResponse:
    return HealthResponse(status="ok", service=_SERVICE_NAME)


@router.get("/ready", summary="Readiness probe")
def ready() -> JSONResponse:
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
    return JSONResponse(
        status_code=503,
        content=ReadyResponse(
            status="not_ready",
            service=_SERVICE_NAME,
            components=components or None,
            reason=state.reason or "application not initialized",
        ).model_dump(exclude_none=True),
    )


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _auth_error(detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content=ErrorResponse(error="authentication_failed", detail=detail).model_dump(
            exclude_none=True
        ),
    )


def _bad_request(detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content=ErrorResponse(error="bad_request", detail=detail).model_dump(exclude_none=True),
    )


def _service_unavailable(detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content=ErrorResponse(error="service_unavailable", detail=detail).model_dump(
            exclude_none=True
        ),
    )


def _internal_error() -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(error="internal_error").model_dump(exclude_none=True),
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
        "do not provide subject_id or subject_roles in the request body."
    ),
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

    # ── 1. Parse and validate request body ──────────────────────────────────
    try:
        body_bytes = await request.body()
        eval_request = EvaluateRequest.model_validate_json(body_bytes)
    except ValidationError as exc:
        errors = exc.errors(include_url=False)
        detail = "; ".join(f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in errors)
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
        return _bad_request(detail)
    except Exception:
        emit_gateway_event(
            audit_writer,
            action=VALIDATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_MALFORMED_BODY,
        )
        return _bad_request("Malformed request body")

    # ── 2. Bearer extraction ─────────────────────────────────────────────────
    try:
        token = extract_bearer_token(authorization)
    except TokenExtractionError as exc:
        emit_gateway_event(
            audit_writer,
            action=AUTHENTICATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_MISSING_TOKEN,
        )
        return _auth_error(str(exc))
    except AuthenticationError as exc:
        emit_gateway_event(
            audit_writer,
            action=AUTHENTICATION_FAILED,
            correlation_id=correlation_id,
            http_method=http_method,
            request_path=request_path,
            reason=REASON_MISSING_TOKEN,
        )
        return _auth_error(str(exc))

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
        return _auth_error("Authentication not configured")

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
        return _auth_error("Token verification failed")
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
        return _auth_error("Token verification failed")

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
        return _auth_error("Identity normalization failed")
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
        return _auth_error("Identity normalization failed")

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
        return _service_unavailable("Evaluator not initialized")

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
            action=eval_request.action,
            resource_id=eval_request.resource_id,
            request_id=request_id,
            correlation_id=correlation_id,
            context=eval_request.context,
        )
    except ValidationError as exc:
        # DecisionRequest validation failed (invalid action/resource_id format).
        errors = exc.errors(include_url=False)
        detail = "; ".join(f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in errors)
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
        return _bad_request(detail)
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
        return _internal_error()

    # ── 9. Map outcome to HTTP response ──────────────────────────────────────
    outcome = decision.outcome

    response_body = EvaluateResponse(
        request_id=decision.request_id,
        outcome=outcome.value,
        reason=decision.reason,
        policy_version=decision.policy_version,
    )

    status_code = 200 if outcome == DecisionOutcome.ALLOW else 403

    # X-Correlation-ID is added to all responses by CorrelationMiddleware.
    return JSONResponse(
        status_code=status_code,
        content=response_body.model_dump(exclude_none=True),
    )
