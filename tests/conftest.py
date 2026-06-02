"""Shared pytest fixtures for basis-gateway tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from basis_gateway.main import create_app
from basis_gateway.readiness import get_readiness_state, reset_readiness_state


@pytest.fixture()
def app():
    """Return a FastAPI app instance with readiness state reset."""
    reset_readiness_state()
    return create_app()


@pytest.fixture()
def client(app):
    """Return a TestClient backed by a fully initialized app (lifespan runs)."""
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture()
def unready_client(app):
    """Return a TestClient where the lifespan has NOT run (readiness not set)."""
    # Use raise_server_exceptions=False so 503s are returned, not raised.
    with TestClient(app, raise_server_exceptions=False) as c:
        # Force not-ready after lifespan marks it ready.
        get_readiness_state().mark_not_ready("forced not-ready for test")
        yield c
