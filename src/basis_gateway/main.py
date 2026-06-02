"""FastAPI application entrypoint for basis-gateway.

Initialises configuration and readiness state during the lifespan context.
Future phases will add OIDC verifier and EnforcementPoint startup here.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from basis_gateway.api.routes import router
from basis_gateway.config import configure_logging, load_config
from basis_gateway.readiness import get_readiness_state

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage startup and shutdown for basis-gateway."""
    state = get_readiness_state()

    try:
        config = load_config()
        configure_logging(config.log_level)
        log.info(
            "basis-gateway starting",
            extra={
                "service": config.service_name,
                "environment": config.environment,
                "host": config.host,
                "port": config.port,
            },
        )
        state.mark_ready()
        log.info("basis-gateway ready")
    except Exception as exc:
        log.error("Startup failed: %s", exc)
        state.mark_not_ready(reason=str(exc))

    yield

    state.mark_not_ready(reason="application shutting down")
    log.info("basis-gateway shutdown complete")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="basis-gateway",
        description=(
            "Authentication, identity normalization, and HTTP enforcement boundary "
            "for basis-core. Phase 1 skeleton."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(router)
    return app


app = create_app()
