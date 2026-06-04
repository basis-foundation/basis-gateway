"""Tests for Phase 7 correlation ID hardening.

Verifies that X-Correlation-ID is present on every gateway response,
that the same ID is consistent across the request lifecycle, and that
caller-supplied correlation IDs are not trusted.
"""

from __future__ import annotations

import re

from basis_core.domain import action as actions

from basis_gateway.auth.errors import JWTVerificationError

UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _is_uuid4(value: str) -> bool:
    return bool(UUID4_RE.match(value))


# ---------------------------------------------------------------------------
# Header presence — operational endpoints
# ---------------------------------------------------------------------------


def test_health_returns_correlation_id(client):
    resp = client.get("/health")
    assert "x-correlation-id" in resp.headers


def test_health_correlation_id_is_uuid4(client):
    resp = client.get("/health")
    assert _is_uuid4(resp.headers["x-correlation-id"])


def test_ready_returns_correlation_id(client):
    resp = client.get("/ready")
    assert "x-correlation-id" in resp.headers


def test_ready_correlation_id_is_uuid4(client):
    resp = client.get("/ready")
    assert _is_uuid4(resp.headers["x-correlation-id"])


# ---------------------------------------------------------------------------
# Header presence — evaluate pre-evaluation failure paths
# ---------------------------------------------------------------------------


def test_evaluate_auth_failure_returns_correlation_id(evaluate_client):
    """Authentication failure (401) must include X-Correlation-ID."""
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": actions.READ_SENSOR_TELEMETRY},
        # No Authorization header → auth failure
    )
    assert resp.status_code == 401
    assert "x-correlation-id" in resp.headers


def test_evaluate_auth_failure_correlation_id_is_uuid4(evaluate_client):
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": actions.READ_SENSOR_TELEMETRY},
    )
    assert _is_uuid4(resp.headers["x-correlation-id"])


def test_evaluate_jwt_verification_failure_returns_correlation_id(evaluate_client, mock_verifier):
    """JWT verification failure (401) must include X-Correlation-ID."""
    mock_verifier.set_raise(JWTVerificationError("expired"))
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": actions.READ_SENSOR_TELEMETRY},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 401
    assert "x-correlation-id" in resp.headers


def test_evaluate_validation_failure_returns_correlation_id(evaluate_client):
    """Request body validation failure (400) must include X-Correlation-ID."""
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"resource_id": "sensor:ahu-1"},  # missing required 'action'
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 400
    assert "x-correlation-id" in resp.headers


def test_evaluate_malformed_body_returns_correlation_id(evaluate_client):
    """Malformed JSON body (400) must include X-Correlation-ID."""
    resp = evaluate_client.post(
        "/v1/evaluate",
        content=b"not-json",
        headers={"Authorization": "Bearer fake", "Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert "x-correlation-id" in resp.headers


def test_evaluate_evaluator_unavailable_returns_correlation_id(evaluate_client):
    """Evaluator-unavailable (503) must include X-Correlation-ID."""
    evaluate_client.app.state.evaluator = None
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": actions.READ_SENSOR_TELEMETRY},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 503
    assert "x-correlation-id" in resp.headers


def test_evaluate_success_returns_correlation_id(evaluate_client):
    """Successful evaluation (200) must include X-Correlation-ID."""
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": actions.READ_SENSOR_TELEMETRY, "resource_id": "sensor:ahu-1"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 200
    assert "x-correlation-id" in resp.headers


def test_evaluate_deny_returns_correlation_id(evaluate_client, mock_verifier):
    """Denied evaluation (403) must include X-Correlation-ID."""
    mock_verifier._claims["realm_access"] = {"roles": ["viewer"]}
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": actions.WRITE_HVAC_SETPOINT, "resource_id": "hvac:ahu-1"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 403
    assert "x-correlation-id" in resp.headers


# ---------------------------------------------------------------------------
# Correlation ID consistency
# ---------------------------------------------------------------------------


def test_correlation_id_is_unique_per_request(client):
    """Each request gets a distinct correlation ID."""
    r1 = client.get("/health")
    r2 = client.get("/health")
    assert r1.headers["x-correlation-id"] != r2.headers["x-correlation-id"]


def test_evaluate_correlation_id_matches_audit_path(capture_client, captured_events):
    """The correlation ID in the response header matches the one in the audit event."""
    resp = capture_client.post(
        "/v1/evaluate",
        json={"action": actions.READ_SENSOR_TELEMETRY, "resource_id": "sensor:ahu-1"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 200
    assert len(captured_events) == 1
    event = captured_events[0]
    assert event.correlation_id == resp.headers["x-correlation-id"]


# ---------------------------------------------------------------------------
# Caller-supplied correlation ID is ignored
# ---------------------------------------------------------------------------


def test_caller_supplied_correlation_id_is_not_used(client):
    """Gateway generates its own correlation ID; caller-supplied value is not trusted."""
    caller_value = "caller-supplied-value-that-should-be-ignored"
    resp = client.get("/health", headers={"X-Correlation-ID": caller_value})
    assert "x-correlation-id" in resp.headers
    assert resp.headers["x-correlation-id"] != caller_value


def test_caller_supplied_correlation_id_is_not_used_on_evaluate(evaluate_client):
    """X-Correlation-ID from caller must not appear in the response."""
    caller_value = "00000000-0000-4000-8000-000000000000"
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": actions.READ_SENSOR_TELEMETRY, "resource_id": "sensor:ahu-1"},
        headers={"Authorization": "Bearer fake", "X-Correlation-ID": caller_value},
    )
    # The gateway must return its own generated UUID, not the caller's value.
    assert resp.headers["x-correlation-id"] != caller_value
    assert _is_uuid4(resp.headers["x-correlation-id"])
