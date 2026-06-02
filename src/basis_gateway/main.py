"""FastAPI application entrypoint for basis-gateway.

Lifespan:
  1. Load and validate configuration.
  2. Initialize the OIDC verifier (if OIDC_ISSUER is configured).
  3. Initialize the GatewayEvaluator (EnforcementPoint + demo policy).
  4. Mark the app ready.

app.state holds:
  config   — GatewayConfig
  verifier — OIDCVerifier | None
  evaluator — GatewayEvaluator
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from basis_gateway.api.routes import router
from basis_gateway.api.schemas import ErrorResponse
from basis_gateway.audit.writer import build_audit_writer
from basis_gateway.config import configure_logging, load_config
from basis_gateway.core.evaluator import build_evaluator
from basis_gateway.readiness import get_readiness_state

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup and shutdown for basis-gateway."""
    state = get_readiness_state()

    try:
        # ── Config ──────────────────────────────────────────────────────────
        config = load_config()
        configure_logging(config.log_level)
        app.state.config = config
        log.info(
            "basis-gateway starting service=%s env=%s",
            config.service_name,
            config.environment,
        )
        state.mark_ready("app")

        # ── OIDC verifier ────────────────────────────────────────────────────
        if config.oidc_issuer:
            from basis_gateway.auth.oidc import OIDCVerifier

            verifier = OIDCVerifier.from_config(
                issuer=config.oidc_issuer,
                audience=config.oidc_audience,
                jwks_uri_override=config.oidc_jwks_uri,
                cache_ttl_seconds=config.jwks_cache_ttl_seconds,
            )
            verifier.initialize()
            app.state.verifier = verifier
            state.mark_ready("oidc")
            log.info("OIDC verifier initialized issuer=%s", config.oidc_issuer)
        else:
            # No OIDC issuer configured — verifier is absent.
            # POST /v1/evaluate will reject all requests (fail-closed).
            app.state.verifier = None
            log.warning("OIDC_ISSUER not configured; /v1/evaluate will reject all requests")

        # ── Evaluator ────────────────────────────────────────────────────────
        audit_writer = build_audit_writer()
        evaluator = build_evaluator(
            audit_writer=audit_writer,
            policy_version=config.policy_version,
        )
        app.state.evaluator = evaluator
        state.mark_ready("evaluator")
        log.info("GatewayEvaluator ready policy_version=%s", config.policy_version)

        log.info("basis-gateway ready")

    except Exception as exc:
        log.error("Startup failed: %s", exc)
        state.mark_not_ready(reason=str(exc))
        # Still yield so the app serves /health (process is running).
        # /ready will return 503.

    yield

    state.mark_not_ready(reason="application shutting down")
    log.info("basis-gateway shutdown complete")


def create_app() -> FastAPI:
    app = FastAPI(
        title="basis-gateway",
        description="Authentication, identity normalization, and HTTP enforcement boundary.",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(router)

    # Convert Pydantic validation errors to 400 instead of 422.
    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = exc.errors()
        detail = "; ".join(f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in errors)
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(error="bad_request", detail=detail).model_dump(exclude_none=True),
        )

    return app


app = create_app()
