"""FastAPI application entrypoint for basis-gateway.

Lifespan (Phase 4):
  1. Load and validate configuration.           → marks "configuration_loaded"
  2. Validate evaluation config (fail-early).
  3. Initialize the OIDC verifier (if enabled). → marks "oidc_configured"
  4. Load policy from POLICY_PATH.              → marks "policy_loaded"
  5. Initialize GatewayEvaluator.               → marks "evaluator_initialized"

Startup fails predictably when evaluation is enabled and required dependencies
are unavailable. The service still starts (so /health responds), but /ready
returns 503 until all components are ready.

app.state holds:
  config    — GatewayConfig
  verifier  — OIDCVerifier | None
  evaluator — GatewayEvaluator | None
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
from basis_gateway.config import (
    EvaluationConfigError,
    configure_logging,
    load_config,
    validate_evaluation_config,
)
from basis_gateway.core.evaluator import build_evaluator
from basis_gateway.middleware.correlation import CorrelationMiddleware
from basis_gateway.policy.loader import PolicyLoadError, load_policy_engine
from basis_gateway.readiness import get_readiness_state

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup and shutdown for basis-gateway."""
    state = get_readiness_state()

    try:
        # ── 1. Configuration ─────────────────────────────────────────────────
        config = load_config()
        configure_logging(config.log_level)
        app.state.config = config
        app.state.verifier = None
        app.state.evaluator = None
        log.info(
            "basis-gateway starting service=%s env=%s",
            config.service_name,
            config.environment,
        )
        state.mark_ready("configuration_loaded")

        # ── 2. Fail-early validation ─────────────────────────────────────────
        # Raises EvaluationConfigError when evaluation is enabled but required
        # config (OIDC_ISSUER, POLICY_PATH) is missing.
        try:
            validate_evaluation_config(config)
        except EvaluationConfigError as exc:
            log.error("Configuration validation failed: %s", exc)
            state.mark_not_ready(reason=str(exc), component="configuration_loaded")
            # Do not yield further — the caller catches all exceptions below.
            raise

        # ── 3. OIDC verifier ─────────────────────────────────────────────────
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
            state.mark_ready("oidc_configured")
            state.mark_ready("jwks_available")
            log.info("OIDC verifier initialized issuer=%s", config.oidc_issuer)
        else:
            # Evaluation disabled — OIDC/JWKS components are not required.
            log.warning("OIDC_ISSUER not configured; /v1/evaluate will reject all requests")

        # ── 4. Policy loading ────────────────────────────────────────────────
        if config.policy_path:
            try:
                engine = load_policy_engine(config.policy_path)
            except PolicyLoadError as exc:
                log.error("Policy loading failed: %s", exc)
                state.mark_not_ready(reason=str(exc), component="policy_loaded")
                raise
            state.mark_ready("policy_loaded")
            log.info("Policy loaded path=%s", config.policy_path)

            # ── 5. Evaluator ─────────────────────────────────────────────────
            audit_writer = build_audit_writer()
            evaluator = build_evaluator(
                engine=engine,
                audit_writer=audit_writer,
                policy_version=config.policy_version,
            )
            app.state.evaluator = evaluator
            state.mark_ready("evaluator_initialized")
            log.info("GatewayEvaluator ready policy_version=%s", config.policy_version)
        else:
            # No policy path — evaluator stays None.
            # /v1/evaluate will return 503 if called.
            log.warning("POLICY_PATH not configured; evaluator not initialized")

        log.info("basis-gateway ready")

    except Exception as exc:
        log.error("Startup failed: %s", exc)
        # Mark app-level not-ready only if no component-level reason was set.
        if not any(not v for v in state.components.values()):
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
    app.add_middleware(CorrelationMiddleware)

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
