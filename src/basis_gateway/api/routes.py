"""Route definitions for basis-gateway.

Phase 1 implements:
  GET /health  — liveness probe
  GET /ready   — readiness probe

Future phases will add POST /v1/evaluate.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from basis_gateway.readiness import get_readiness_state

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    service: str


class ReadyResponse(BaseModel):
    status: str
    service: str
    reason: str | None = None


_SERVICE_NAME = "basis-gateway"


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness probe",
    description="Returns 200 OK when the gateway process is running.",
)
def health() -> HealthResponse:
    return HealthResponse(status="ok", service=_SERVICE_NAME)


@router.get(
    "/ready",
    summary="Readiness probe",
    description=(
        "Returns 200 when the gateway is initialised and ready to serve requests. "
        "Returns 503 when not ready."
    ),
)
def ready() -> JSONResponse:
    state = get_readiness_state()
    if state.is_ready:
        return JSONResponse(
            status_code=200,
            content=ReadyResponse(status="ready", service=_SERVICE_NAME).model_dump(
                exclude_none=True
            ),
        )
    return JSONResponse(
        status_code=503,
        content=ReadyResponse(
            status="not_ready",
            service=_SERVICE_NAME,
            reason=state.reason or "application not initialized",
        ).model_dump(exclude_none=True),
    )
