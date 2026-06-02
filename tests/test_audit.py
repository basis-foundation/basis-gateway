"""Tests for audit behavior at the gateway layer.

Verifies that audit events are emitted for every evaluated request,
that correlation IDs are present, and that the gateway uses basis-core's
AuditWriter protocol without defining a parallel schema.
"""

from __future__ import annotations

from basis_core.audit import AuditEvent, AuditOutcome
from basis_core.domain import action as actions


def _post_evaluate(client, action: str = None, resource_id: str = "sensor:ahu-1"):
    if action is None:
        action = actions.READ_SENSOR_TELEMETRY
    return client.post(
        "/v1/evaluate",
        json={"action": action, "resource_id": resource_id},
        headers={"Authorization": "Bearer fake"},
    )


# ---------------------------------------------------------------------------
# Audit event emission
# ---------------------------------------------------------------------------


def test_audit_event_emitted_for_allow(capture_client, captured_events):
    resp = _post_evaluate(capture_client, actions.READ_SENSOR_TELEMETRY)
    assert resp.status_code == 200
    assert len(captured_events) == 1
    event = captured_events[0]
    assert isinstance(event, AuditEvent)
    assert event.outcome == AuditOutcome.ALLOWED


def test_audit_event_emitted_for_deny(capture_client, captured_events, mock_verifier):
    mock_verifier._claims["realm_access"] = {"roles": ["viewer"]}
    resp = _post_evaluate(capture_client, actions.WRITE_HVAC_SETPOINT)
    assert resp.status_code == 403
    assert len(captured_events) == 1
    event = captured_events[0]
    assert event.outcome == AuditOutcome.DENIED


def test_audit_event_emitted_for_not_applicable(capture_client, captured_events):
    """NOT_APPLICABLE → audit outcome is DENIED (per evaluation-semantics.md)."""
    # READ_AUDIT_LOG is not in the test-rbac capturing evaluator's role table
    resp = _post_evaluate(capture_client, actions.READ_AUDIT_LOG)
    assert resp.status_code == 403
    assert len(captured_events) == 1
    assert captured_events[0].outcome == AuditOutcome.DENIED


# ---------------------------------------------------------------------------
# Correlation ID
# ---------------------------------------------------------------------------


def test_correlation_id_in_response_header(capture_client, captured_events):
    resp = _post_evaluate(capture_client)
    assert "x-correlation-id" in resp.headers
    assert resp.headers["x-correlation-id"]  # not empty


# ---------------------------------------------------------------------------
# Schema contract: basis-core AuditEvent, not a gateway-defined type
# ---------------------------------------------------------------------------


def test_audit_event_uses_basis_core_schema(capture_client, captured_events):
    """AuditEvent is basis-core's canonical type; gateway defines no parallel schema."""
    _post_evaluate(capture_client)

    assert len(captured_events) == 1
    event = captured_events[0]

    # Must be basis-core's AuditEvent, not a gateway subclass.
    assert type(event).__module__.startswith("basis_core")

    # Required fields from the basis-core schema must be present.
    assert hasattr(event, "request_id")
    assert hasattr(event, "outcome")
    assert hasattr(event, "subject_id")
    assert hasattr(event, "action")


def test_audit_writer_receives_kernel_generated_event(capture_client, captured_events):
    """The AuditWriter receives the event produced by EnforcementPoint, not the gateway."""
    _post_evaluate(capture_client)
    assert captured_events[0].subject_id == "user1"
    assert captured_events[0].action == actions.READ_SENSOR_TELEMETRY


# ---------------------------------------------------------------------------
# Multiple requests
# ---------------------------------------------------------------------------


def test_multiple_requests_each_produce_one_audit_event(capture_client, captured_events):
    for _ in range(3):
        _post_evaluate(capture_client)
    assert len(captured_events) == 3
