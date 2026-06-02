"""Tests for GET /ready (readiness probe)."""

from __future__ import annotations

from basis_gateway.readiness import get_readiness_state


def test_ready_returns_200_when_initialized(client):
    response = client.get("/ready")
    assert response.status_code == 200


def test_ready_status_ready(client):
    response = client.get("/ready")
    assert response.json()["status"] == "ready"


def test_ready_service_name(client):
    response = client.get("/ready")
    assert response.json()["service"] == "basis-gateway"


def test_ready_returns_503_when_not_ready(client):
    # Manually mark not-ready after startup.
    get_readiness_state().mark_not_ready("kernel not initialized")
    response = client.get("/ready")
    assert response.status_code == 503


def test_ready_503_includes_status_not_ready(client):
    get_readiness_state().mark_not_ready("no policy loaded")
    response = client.get("/ready")
    assert response.json()["status"] == "not_ready"


def test_ready_503_includes_reason(client):
    get_readiness_state().mark_not_ready("no policy loaded")
    response = client.get("/ready")
    assert "reason" in response.json()
    assert response.json()["reason"] == "no policy loaded"


def test_ready_recovers_after_mark_ready(client):
    state = get_readiness_state()
    state.mark_not_ready("temporary")
    assert client.get("/ready").status_code == 503
    state.mark_ready()
    assert client.get("/ready").status_code == 200
