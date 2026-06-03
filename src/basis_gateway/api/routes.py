"""Route definitions for basis-gateway.

Endpoints:
  GET  /health         — liveness probe
  GET  /ready          — readiness probe
  POST /v1/evaluate    — authorization evaluation
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from basis_core.decisions import DecisionOutcome
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from basis_gateway.api.schemas import ErrorResponse, EvaluateRequest, EvaluateResponse
from basis_gateway.auth.errors import AuthenticationError, SubjectMappingError
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
    """
    correlation_id = str(uuid.uuid4())

    # ── 1. Parse and validate request body ──────────────────────────────────
    try:
        body_bytes = await request.body()
        eval_request = EvaluateRequest.model_validate_json(body_bytes)
    except ValidationError as exc:
        errors = exc.errors(include_url=False)
        detail = "; ".join(f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in errors)
        return _bad_request(detail)
    except Exception:
        return _bad_request("Malformed request body")

    # ── 2. Bearer extraction ─────────────────────────────────────────────────
    try:
        token = extract_bearer_token(authorization)
    except AuthenticationError as exc:
        return _auth_error(str(exc))

    # ── 3. JWT verification ──────────────────────────────────────────────────
    verifier = getattr(request.app.state, "verifier", None)
    if verifier is None:
        log.error("OIDC verifier not initialized; rejecting request")
        return _auth_error("Authentication not configured")

    try:
        claims: dict[str, Any] = verifier.verify(token)
    except AuthenticationError as exc:
        log.info("JWT verification failed: %s", exc)
        return _auth_error("Token verification failed")
    except Exception:
        log.exception("Unexpected error during JWT verification")
        return _auth_error("Token verification failed")

    # ── 4. Subject mapping ───────────────────────────────────────────────────
    try:
        normalized_subject, _identity_ctx = map_claims(claims)
    except SubjectMappingError as exc:
        log.info("Subject mapping failed: %s", exc)
        return _auth_error("Identity normalization failed")
    except Exception:
        log.exception("Unexpected error during subject mapping")
        return _auth_error("Identity normalization failed")

    # ── 5. Get evaluator ─────────────────────────────────────────────────────
    evaluator: GatewayEvaluator | None = getattr(request.app.state, "evaluator", None)
    if evaluator is None:
        return _service_unavailable("Evaluator not initialized")

    # ── 6. Build request ID ──────────────────────────────────────────────────
    request_id = eval_request.request_id or correlation_id

    # ── 7. Evaluate ──────────────────────────────────────────────────────────
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
        return _bad_request(detail)
    except Exception:
        log.exception("Unexpected error during evaluation")
        return _internal_error()

    # ── 8. Map outcome to HTTP response ──────────────────────────────────────
    outcome = decision.outcome

    response_body = EvaluateResponse(
        request_id=decision.request_id,
        outcome=outcome.value,
        reason=decision.reason,
        policy_version=decision.policy_version,
    )

    status_code = 200 if outcome == DecisionOutcome.ALLOW else 403

    response = JSONResponse(
        status_code=status_code,
        content=response_body.model_dump(exclude_none=True),
    )
    response.headers["X-Correlation-ID"] = correlation_id
    return response
