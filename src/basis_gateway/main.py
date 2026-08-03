"""FastAPI application entrypoint for basis-gateway.

Lifespan:
  1. Load and validate the GatewayConfig object itself.     → marks "configuration_loaded"
  1a. Register the operation-aware router (PR 6), from this same config,
      when OPERATION_AWARE_ENABLED=true — before any step below that can
      fail, so "enabled but a later step fails" still leaves the endpoint
      registered (returning 503 at request time), not 404.
  1b. Construct the shared GatewayAuditWriter (PR 7).       → marks "audit_writer"
       Built whenever POLICY_PATH is set OR
       OPERATION_AWARE_ENABLED=true — exactly one instance,
       shared by the v0.1 evaluator (step 5) and the
       operation-aware endpoint (api.routes) alike. Not
       built when neither path is enabled. Deliberately
       placed immediately after config load/router
       registration and *before* every step below that can
       itself fail (evaluation-config validation, auth
       initialization, v0.1 policy loading, operation-aware
       validation/evaluator construction) — the writer must
       remain available on app.state even when one of those
       later steps aborts startup, since the operation-aware
       endpoint's own audit recording (routes.py) needs it at
       request time regardless of which later component ends
       up ready.
  2. Validate evaluation config (fail-early).
  3. Initialize the auth_mode-selected verifier:
       - "oidc" (default): OIDC verifier             → marks "oidc_configured", "jwks_available"
       - "basis_local_token": BASIS-local trust config → marks "basis_local_token_configured"
  4. Load policy from POLICY_PATH.                         → marks "policy_loaded"
  5. Initialize GatewayEvaluator (reuses the step 1b writer). → marks "evaluator_initialized"
  6. Operation-aware evaluator construction (PR 5, additive, feature-flagged).
       Only runs when OPERATION_AWARE_ENABLED=true          → marks "operation_aware_evaluator"

Startup fails predictably when evaluation is enabled and required dependencies
are unavailable. The service still starts (so /health responds), but /ready
returns 503 until all components are ready.

Only the components for the configured auth_mode are registered: in "oidc"
mode, "basis_local_token_configured" is never registered (and vice versa),
so the inactive mode's readiness never blocks the active one. Likewise,
"operation_aware_evaluator" is only registered when OPERATION_AWARE_ENABLED
is true — a deployment that does not enable the feature sees no readiness
behavior change at all. Step 6's single readiness component is a narrow,
temporary integration for this PR only; PR 8 replaces it with the full
four-component readiness model described in the integration plan's §13
(``operation_aware_bundle_loaded``, ``operation_aware_evaluator_initialized``,
``operation_aware_policy_semantically_valid``, plus the informational
``operation_aware_mode_enabled``).

app.state holds:
  config                          — GatewayConfig
  verifier                        — OIDCVerifier | None (auth_mode="oidc")
  basis_local_token_trust_config  — BasisLocalTokenTrustConfig | None
                                     (auth_mode="basis_local_token")
  evaluator                       — GatewayEvaluator | None
  audit_writer                    — GatewayAuditWriter | None (PR 7: shared by
                                     the v0.1 evaluator and the
                                     operation-aware endpoint; built whenever
                                     either path is enabled, see step 4a)
  operation_aware_evaluator       — OperationAwareGatewayEvaluator | None
                                     (populated only when
                                     OPERATION_AWARE_ENABLED=true and startup
                                     succeeds; reachable via
                                     POST /v1/evaluate/operation-aware,
                                     registered per step 1a above whenever
                                     OPERATION_AWARE_ENABLED=true, regardless
                                     of whether this evaluator itself ends up
                                     initialized — see
                                     api.routes.evaluate_operation_aware's
                                     own 503-when-unavailable handling)
  operation_aware_router_registered — bool, guards against this router
                                     being registered with FastAPI more than
                                     once for a given app instance (step 1a)
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from basis_gateway.api.routes import operation_aware_router, router
from basis_gateway.api.schemas import ErrorResponse
from basis_gateway.audit.writer import build_audit_writer
from basis_gateway.config import (
    AuthMode,
    EvaluationConfigError,
    OperationAwareConfigError,
    configure_logging,
    load_config,
    validate_evaluation_config,
    validate_operation_aware_config,
)
from basis_gateway.core.evaluator import build_evaluator
from basis_gateway.core.operation_aware_evaluator import (
    OperationAwarePreflightError,
    OperationAwareRequestConstructionError,
    load_and_build_operation_aware_evaluator,
)
from basis_gateway.middleware.correlation import CorrelationMiddleware
from basis_gateway.policy.loader import PolicyLoadError, load_policy_engine
from basis_gateway.policy.operation_aware_loader import OperationAwarePolicyLoadError
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
        app.state.basis_local_token_trust_config = None
        app.state.evaluator = None
        app.state.audit_writer = None
        app.state.operation_aware_evaluator = None
        log.info(
            "basis-gateway starting service=%s env=%s log_level=%s",
            config.service_name,
            config.environment,
            config.log_level,
        )
        state.mark_ready("configuration_loaded")
        log.info("Configuration loaded")

        # ── 1a. Operation-aware router registration (PR 6, §12) ─────────────
        # Registered from this same successfully-loaded `config` — the sole
        # authoritative configuration load for this startup — immediately
        # after configuration loads and before any step below that can fail
        # (the step 1b audit writer, fail-early validation, auth-mode
        # initialization, policy loading, operation-aware evaluator
        # construction). This guarantees the route's registration state
        # depends only on
        # `OPERATION_AWARE_ENABLED`, never on whether a later startup step
        # succeeds: "enabled but evaluator unavailable" must still route to
        # this handler and return 503 at request time, not 404. Guarded by
        # `app.state.operation_aware_router_registered` so re-entering this
        # lifespan against the same `FastAPI` app instance never registers
        # the router with FastAPI more than once. `app.openapi_schema` is
        # invalidated so the generated schema reflects the endpoint the
        # first time it is registered on this app instance.
        if config.operation_aware_enabled and not getattr(
            app.state, "operation_aware_router_registered", False
        ):
            app.include_router(operation_aware_router)
            app.state.operation_aware_router_registered = True
            app.openapi_schema = None
            log.info("Operation-aware endpoint registered path=/v1/evaluate/operation-aware")

        # ── 1b. Shared audit writer (PR 7) ───────────────────────────────────
        # Exactly one GatewayAuditWriter is constructed per application
        # instance, shared by the v0.1 evaluator and the operation-aware
        # evaluator/endpoint alike, whenever *either* runtime path requires
        # one: v0.1's POLICY_PATH is configured, OR operation-aware
        # integration is enabled (OPERATION_AWARE_ENABLED=true) — regardless
        # of whether evaluation-config validation (step 2), authentication
        # initialization (step 3), v0.1 policy loading (step 4), or
        # operation-aware validation/evaluator construction (step 6)
        # ultimately succeeds. Placed here, immediately after configuration
        # loads and router registration and before any of those steps, so a
        # later failure in any of them can never leave app.state.audit_writer
        # unset while the operation-aware route remains registered. Neither
        # path enabled -> no writer is constructed and app.state.audit_writer
        # stays None.
        audit_writer = None
        if config.policy_path or config.operation_aware_enabled:
            audit_writer = build_audit_writer(
                readiness_state=state,
                failure_threshold=config.audit_failure_threshold,
            )
            app.state.audit_writer = audit_writer
            state.mark_ready("audit_writer")
            log.info(
                "Audit writer initialized threshold=%d fail_closed=%s",
                config.audit_failure_threshold,
                config.audit_fail_closed,
            )

        # ── 2. Fail-early validation ─────────────────────────────────────────
        # Raises EvaluationConfigError when evaluation is enabled but required
        # config (OIDC_ISSUER, POLICY_PATH) is missing.
        try:
            validate_evaluation_config(config)
        except EvaluationConfigError as exc:
            log.error(
                "Configuration validation failed [configuration_loaded]: %s — "
                "check OIDC_ISSUER and POLICY_PATH environment variables",
                exc,
            )
            state.mark_not_ready(reason=str(exc), component="configuration_loaded")
            # Do not yield further — the caller catches all exceptions below.
            raise

        # ── 3. Runtime authentication ────────────────────────────────────────
        # Which verifier initializes here is selected by config.auth_mode.
        # The other mode's fields are neither required nor consulted. At
        # request time, basis_gateway.auth.runtime.authenticate() dispatches
        # on this same auth_mode to decide which of app.state.verifier /
        # app.state.basis_local_token_trust_config to use — there is no
        # fallback between modes.
        if config.auth_mode == AuthMode.OIDC:
            if config.oidc_issuer:
                from basis_gateway.auth.errors import JWKSFetchError, OIDCDiscoveryError
                from basis_gateway.auth.oidc import OIDCVerifier

                log.info("Initializing OIDC verifier issuer=%s", config.oidc_issuer)
                verifier = OIDCVerifier.from_config(
                    issuer=config.oidc_issuer,
                    audience=config.oidc_audience,
                    jwks_uri_override=config.oidc_jwks_uri,
                    cache_ttl_seconds=config.jwks_cache_ttl_seconds,
                )
                try:
                    verifier.initialize()
                except OIDCDiscoveryError as exc:
                    log.error(
                        "OIDC discovery failed [oidc_configured]: %s — "
                        "check that OIDC_ISSUER is reachable and the discovery endpoint "
                        "(%s/.well-known/openid-configuration) returns a valid document",
                        exc,
                        config.oidc_issuer,
                    )
                    state.mark_not_ready(reason=str(exc), component="oidc_configured")
                    raise
                except JWKSFetchError as exc:
                    log.error(
                        "JWKS fetch failed [jwks_available]: %s — "
                        "check that the JWKS endpoint is reachable from this host; "
                        "set OIDC_JWKS_URI to override the discovered endpoint",
                        exc,
                    )
                    state.mark_not_ready(reason=str(exc), component="jwks_available")
                    raise
                app.state.verifier = verifier
                state.mark_ready("oidc_configured")
                state.mark_ready("jwks_available")
                log.info("OIDC verifier initialized issuer=%s", config.oidc_issuer)
            else:
                # Evaluation disabled — OIDC/JWKS components are not required.
                log.warning(
                    "OIDC_ISSUER not set — evaluation disabled; "
                    "set OIDC_ISSUER to enable /v1/evaluate"
                )
        elif config.auth_mode == AuthMode.BASIS_LOCAL_TOKEN:
            from basis_gateway.auth.basis_local_token import BasisLocalTokenConfigError
            from basis_gateway.auth.runtime import build_basis_local_token_trust_config

            log.info("Initializing BASIS-local token trust configuration")
            try:
                trust_config = build_basis_local_token_trust_config(config)
            except (EvaluationConfigError, BasisLocalTokenConfigError) as exc:
                log.error(
                    "BASIS-local token trust configuration failed "
                    "[basis_local_token_configured]: %s — check BASIS_LOCAL_TOKEN_ISSUER, "
                    "BASIS_LOCAL_TOKEN_AUDIENCE, and BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON",
                    exc,
                )
                state.mark_not_ready(reason=str(exc), component="basis_local_token_configured")
                raise
            app.state.basis_local_token_trust_config = trust_config
            state.mark_ready("basis_local_token_configured")
            log.info("BASIS-local token trust configured issuer=%s", trust_config.issuer)

        # ── 4. Policy loading ────────────────────────────────────────────────
        engine = None
        if config.policy_path:
            log.info("Loading policy from %s", config.policy_path)
            try:
                engine = load_policy_engine(config.policy_path)
            except PolicyLoadError as exc:
                log.error(
                    "Policy loading failed [policy_loaded]: %s — "
                    "check that POLICY_PATH points to a valid JSON policy file",
                    exc,
                )
                state.mark_not_ready(reason=str(exc), component="policy_loaded")
                raise
            state.mark_ready("policy_loaded")
            log.info("Policy loaded path=%s", config.policy_path)
        else:
            # No policy path — evaluator stays None.
            # /v1/evaluate will return 503 if called.
            log.warning(
                "POLICY_PATH not set — evaluator not initialized; "
                "set POLICY_PATH to enable authorization evaluation"
            )

        # ── 5. v0.1 evaluator ─────────────────────────────────────────────
        if config.policy_path:
            assert engine is not None  # guaranteed by step 4 above
            assert audit_writer is not None  # guaranteed by step 1b above (policy_path is set)
            evaluator = build_evaluator(
                engine=engine,
                audit_writer=audit_writer,
                policy_version=config.policy_version,
            )
            app.state.evaluator = evaluator
            state.mark_ready("evaluator_initialized")
            log.info("Evaluator initialized policy_version=%s", config.policy_version)

        # ── 6. Operation-aware integration (PR 5, additive) ───────────────
        # Disabled by default (OPERATION_AWARE_ENABLED unset or "false"):
        # no bundle load, no evaluator construction, no semantic preflight,
        # and no readiness component is registered — existing v0.1 startup
        # behavior above is completely unaffected. This is a separate
        # feature flag, separate configuration, separate loader, and
        # separate evaluator instance from the v0.1 path; it never
        # replaces or mutates app.state.evaluator/app.state.policy_engine.
        if config.operation_aware_enabled:
            try:
                validate_operation_aware_config(config)
            except OperationAwareConfigError as exc:
                log.error(
                    "Operation-aware configuration validation failed "
                    "[operation_aware_evaluator]: %s — check "
                    "OPERATION_AWARE_POLICY_BUNDLE_PATH",
                    exc,
                )
                state.mark_not_ready(reason=str(exc), component="operation_aware_evaluator")
                raise

            bundle_path = config.operation_aware_policy_bundle_path
            assert bundle_path is not None  # guaranteed by validate_operation_aware_config
            log.info("Loading operation-aware policy bundle from %s", bundle_path)
            try:
                operation_aware_evaluator = load_and_build_operation_aware_evaluator(bundle_path)
            except (
                OperationAwarePolicyLoadError,
                OperationAwareRequestConstructionError,
                OperationAwarePreflightError,
            ) as exc:
                log.error(
                    "Operation-aware evaluator initialization failed "
                    "[operation_aware_evaluator, %s]: %s — check "
                    "OPERATION_AWARE_POLICY_BUNDLE_PATH and the bundle's structural/semantic "
                    "validity",
                    type(exc).__name__,
                    exc,
                )
                state.mark_not_ready(reason=str(exc), component="operation_aware_evaluator")
                raise

            app.state.operation_aware_evaluator = operation_aware_evaluator
            state.mark_ready("operation_aware_evaluator")
            log.info(
                "Operation-aware evaluator initialized and passed startup semantic preflight "
                "bundle_path=%s",
                bundle_path,
            )
        else:
            log.info(
                "OPERATION_AWARE_ENABLED not set — operation-aware integration disabled; "
                "set OPERATION_AWARE_ENABLED=true and OPERATION_AWARE_POLICY_BUNDLE_PATH to "
                "enable it"
            )

        log.info("basis-gateway ready")

    except Exception as exc:
        log.error("Startup failed [%s]: %s", type(exc).__name__, exc)
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

    # The operation-aware endpoint (PR 6, §12 compatibility strategy) is NOT
    # registered here. Route registration is decided inside `lifespan()`
    # (see "1a. Operation-aware router registration" above), from the same
    # `GatewayConfig` the lifespan loads once and treats as authoritative —
    # never from a second, throwaway `load_config()` call at app-construction
    # time. That keeps `create_app()` itself free of configuration loading
    # (a malformed environment must still allow the app to be constructed
    # and `/health` to respond, with `/ready` reporting `503` — the
    # pre-existing startup-failure contract this repository already relies
    # on) and guarantees route registration and runtime initialization
    # observe exactly one configuration snapshot, not two. A deployment that
    # does not enable the feature never has `POST
    # /v1/evaluate/operation-aware` registered at all, and a request to it
    # receives FastAPI's ordinary, unmodified 404. `router`/`/v1/evaluate`
    # above are completely unaffected by this and are always registered
    # synchronously here, as before.
    app.add_middleware(CorrelationMiddleware)

    # Convert FastAPI/Pydantic validation errors to 400 instead of 422.
    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = exc.errors()
        message = "; ".join(f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in errors)
        correlation_id: str | None = getattr(request.state, "correlation_id", None)
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(
                error="validation_failed",
                message=message,
                correlation_id=correlation_id,
            ).model_dump(exclude_none=True),
        )

    return app


app = create_app()
