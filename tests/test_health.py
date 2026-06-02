"""Tests for GET /health (liveness probe)."""

from __future__ import annotations


def test_health_returns_200(client):
    response = client.get("/health")
    assert response.status_code == 200


def test_health_status_ok(client):
    response = client.get("/health")
    assert response.json()["status"] == "ok"


def test_health_service_name(client):
    response = client.get("/health")
    assert response.json()["service"] == "basis-gateway"
