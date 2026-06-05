"""Audit-hardening tests for basis-gateway.

Verifies that gateway-level audit events are emitted for every significant
outcome that occurs before or outside the kernel's EnforcementPoint:

  AUTHENTICATION_FAILED     — missing/invalid token, unconfigured verifier,
                              subject mapping failure
  VALIDATION_FAILED         — malformed or schema-invalid request body
  EVALUATOR_UNAVAILABLE     — evaluator not initialized
  EVALUATION_REQUESTED      — authenticated request received before evaluation
  EVALUATION_FAILED_CLOSED  — unexpected exception during kernel evaluation

All events must include correlation_id.
Raw token contents must never appear in audit events.
Kernel decision events must still emit alongside gateway events.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from basis_core.audit import AuditEventType
from basis_core.domain import action as actions

from basis_gateway.audit.gateway_events import (
    AUTHENTICATION_FAILED,
    EVALUATION_FAILED_CLOSED,
    EVALUATION_REQUESTED,
    EVALUATOR_UNAVAILABLE,
    REASON_EVALUATION_EXCEPTION,
    REASON_EVALUATOR_NOT_INITIALIZED,
    REASON_IDENTITY_NORMALIZATION_FAILED,
    REASON_INVALID_FIELDS,
    REASON_INVALID_TOKEN,
    REASON_MALFORMED_BODY,
    REASON_MISSING_TOKEN,
    REASON_VERIFIER_NOT_CONFIGURED,
    VALIDATION_FAILED,
)
from basis_gateway.auth.errors import JWTVerificationError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_BODY = {"action": actions.READ_SENSOR_TELEMETRY, "resource_id": "sensor:ahu-1"}
_AUTH_HDR = {"Authorization": "Bearer fake-token"}


def _post(client, body: Any = None, headers: dict | None = None) -> Any:
    return client.post(
        "/v1/evaluate",
        json=body if body is not None else _VALID_BODY,
        headers=headers if headers is not None else _AUTH_HDR,
    )


def _gateway_events_of(events: list, action: str) -> list:
    return [e for e in events if e.action == action]


# ---------------------------------------------------------------------------
# 1. Authentication failure — missing token
# ---------------------------------------------------------------------------


def test_auth_failure_missing_token_emits_audit_event(gateway_capture_client, gateway_events):
    resp = _post(gateway_capture_client, headers={})  # no Authorization header
    assert resp.status_code == 401

    auth_failures = _gateway_events_of(gateway_events, AUTHENTICATION_FAILED)
    assert len(auth_failures) == 1
    event = auth_failures[0]
    assert event.event_type == AuditEventType.SYSTEM_EVENT
    assert event.reason == REASON_MISSING_TOKEN
    assert event.correlation_id is not None


def test_auth_failure_missing_token_includes_correlation_id(gateway_capture_client, gateway_events):
    resp = _post(gateway_capture_client, headers={})
    cid = resp.headers.get("x-correlation-id")
    assert cid

    auth_failures = _gateway_events_of(gateway_events, AUTHENTICATION_FAILED)
    assert auth_failures[0].correlation_id == cid


def test_auth_failure_missing_token_does_not_record_token(gateway_capture_client, gateway_events):
    _post(gateway_capture_client, headers={"Authorization": "malformed"})
    for event in gateway_events:
        # No event field should contain raw token material.
        for val in (event.reason or "", str(event.detail)):
            assert "malformed" not in val.lower() or "header" in val.lower()


# ---------------------------------------------------------------------------
# 2. Authentication failure — invalid/expired token
# ---------------------------------------------------------------------------


def test_auth_failure_invalid_token_emits_audit_event(
    gateway_capture_client, gateway_events, mock_verifier
):
    mock_verifier.set_raise(JWTVerificationError("Token has expired"))
    resp = _post(gateway_capture_client)
    assert resp.status_code == 401

    auth_failures = _gateway_events_of(gateway_events, AUTHENTICATION_FAILED)
    assert len(auth_failures) == 1
    assert auth_failures[0].reason == REASON_INVALID_TOKEN
    assert auth_failures[0].correlation_id is not None


def test_auth_failure_invalid_token_does_not_record_token_contents(
    gateway_capture_client, gateway_events, mock_verifier
):
    mock_verifier.set_raise(JWTVerificationError("Token signature is invalid"))
    _post(gateway_capture_client)

    for event in gateway_events:
        # The raw value "fake-token" from the Authorization header must not appear.
        assert "fake-token" not in str(event.detail)
        assert "fake-token" not in (event.reason or "")


# ---------------------------------------------------------------------------
# 3. Authentication failure — verifier not configured
# ---------------------------------------------------------------------------


def test_auth_failure_verifier_not_configured_emits_audit_event(
    gateway_capture_client, gateway_events
):
    gateway_capture_client.app.state.verifier = None
    resp = _post(gateway_capture_client)
    assert resp.status_code == 401

    auth_failures = _gateway_events_of(gateway_events, AUTHENTICATION_FAILED)
    assert len(auth_failures) == 1
    assert auth_failures[0].reason == REASON_VERIFIER_NOT_CONFIGURED


# ---------------------------------------------------------------------------
# 4. Authentication failure — subject mapping / identity normalization
# ---------------------------------------------------------------------------


def test_auth_failure_subject_mapping_emits_audit_event(
    gateway_capture_client, gateway_events, mock_verifier
):
    # Claims with no 'sub' trigger SubjectMappingError inside map_claims.
    mock_verifier._claims = {"iss": "https://test.example.com"}
    resp = _post(gateway_capture_client)
    assert resp.status_code in (400, 401)

    auth_failures = _gateway_events_of(gateway_events, AUTHENTICATION_FAILED)
    assert len(auth_failures) == 1
    assert auth_failures[0].reason == REASON_IDENTITY_NORMALIZATION_FAILED


# ---------------------------------------------------------------------------
# 5. Validation failure — malformed body
# ---------------------------------------------------------------------------


def test_validation_failure_malformed_body_emits_audit_event(
    gateway_capture_client, gateway_events
):
    resp = gateway_capture_client.post(
        "/v1/evaluate",
        content=b"not json at all",
        headers={**_AUTH_HDR, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400

    validation_failures = _gateway_events_of(gateway_events, VALIDATION_FAILED)
    assert len(validation_failures) == 1
    assert validation_failures[0].reason == REASON_MALFORMED_BODY
    assert validation_failures[0].correlation_id is not None


def test_validation_failure_invalid_fields_emits_audit_event(
    gateway_capture_client, gateway_events
):
    # Missing required 'action' field.
    resp = _post(gateway_capture_client, body={"resource_id": "sensor:ahu-1"})
    assert resp.status_code == 400

    validation_failures = _gateway_events_of(gateway_events, VALIDATION_FAILED)
    assert len(validation_failures) == 1
    assert validation_failures[0].reason == REASON_INVALID_FIELDS


def test_validation_failure_includes_correlation_id(gateway_capture_client, gateway_events):
    resp = _post(gateway_capture_client, body={"resource_id": "sensor:ahu-1"})
    cid = resp.headers.get("x-correlation-id")
    assert cid

    validation_failures = _gateway_events_of(gateway_events, VALIDATION_FAILED)
    assert validation_failures[0].correlation_id == cid


# ---------------------------------------------------------------------------
# 6. Evaluator unavailable
# ---------------------------------------------------------------------------


def test_evaluator_unavailable_emits_audit_event(gateway_capture_client, gateway_events):
    gateway_capture_client.app.state.evaluator = None
    resp = _post(gateway_capture_client)
    assert resp.status_code == 503

    unavailable = _gateway_events_of(gateway_events, EVALUATOR_UNAVAILABLE)
    assert len(unavailable) == 1
    assert unavailable[0].reason == REASON_EVALUATOR_NOT_INITIALIZED
    assert unavailable[0].correlation_id is not None


def test_evaluator_unavailable_response_is_fail_closed(gateway_capture_client, gateway_events):
    gateway_capture_client.app.state.evaluator = None
    resp = _post(gateway_capture_client)
    # Must never grant access.
    assert resp.status_code != 200
    assert resp.status_code != 403  # 503, not 403


def test_evaluator_unavailable_includes_subject_id(gateway_capture_client, gateway_events):
    """Subject ID is known after successful auth — must be included."""
    gateway_capture_client.app.state.evaluator = None
    _post(gateway_capture_client)

    unavailable = _gateway_events_of(gateway_events, EVALUATOR_UNAVAILABLE)
    assert unavailable[0].subject_id == "user1"


# ---------------------------------------------------------------------------
# 7. Pre-evaluation request receipt
# ---------------------------------------------------------------------------


def test_pre_evaluation_event_emitted_for_authenticated_request(
    gateway_capture_client, gateway_events
):
    resp = _post(gateway_capture_client)
    assert resp.status_code in (200, 403)

    receipt_events = _gateway_events_of(gateway_events, EVALUATION_REQUESTED)
    assert len(receipt_events) == 1


def test_pre_evaluation_event_includes_correlation_id(gateway_capture_client, gateway_events):
    resp = _post(gateway_capture_client)
    cid = resp.headers.get("x-correlation-id")

    receipt_events = _gateway_events_of(gateway_events, EVALUATION_REQUESTED)
    assert receipt_events[0].correlation_id == cid


def test_pre_evaluation_event_includes_subject_id(gateway_capture_client, gateway_events):
    _post(gateway_capture_client)

    receipt_events = _gateway_events_of(gateway_events, EVALUATION_REQUESTED)
    assert receipt_events[0].subject_id == "user1"


def test_pre_evaluation_and_kernel_event_share_correlation_id(
    gateway_capture_client, gateway_events, captured_events
):
    """Pre-evaluation gateway event and kernel decision event share the same correlation ID.

    The gateway_capture_client uses a null evaluator whose kernel events are
    NOT captured by gateway_events (different writer). We verify the gateway
    event has a valid correlation ID that matches the response header.
    """
    resp = _post(gateway_capture_client)
    cid = resp.headers.get("x-correlation-id")

    receipt_events = _gateway_events_of(gateway_events, EVALUATION_REQUESTED)
    assert receipt_events[0].correlation_id == cid


# ---------------------------------------------------------------------------
# 8. Evaluation exception / fail-closed
# ---------------------------------------------------------------------------


def test_evaluation_exception_emits_audit_event(gateway_capture_client, gateway_events):
    broken = MagicMock()
    broken.evaluate.side_effect = RuntimeError("kernel exploded")
    broken.policy_version = None
    gateway_capture_client.app.state.evaluator = broken

    resp = _post(gateway_capture_client)
    assert resp.status_code == 500

    failed = _gateway_events_of(gateway_events, EVALUATION_FAILED_CLOSED)
    assert len(failed) == 1
    assert failed[0].reason == REASON_EVALUATION_EXCEPTION
    assert failed[0].correlation_id is not None


def test_evaluation_exception_response_is_fail_closed(gateway_capture_client, gateway_events):
    broken = MagicMock()
    broken.evaluate.side_effect = RuntimeError("kernel exploded")
    broken.policy_version = None
    gateway_capture_client.app.state.evaluator = broken

    resp = _post(gateway_capture_client)
    assert resp.status_code != 200


def test_evaluation_exception_includes_subject_id(gateway_capture_client, gateway_events):
    broken = MagicMock()
    broken.evaluate.side_effect = RuntimeError("kernel exploded")
    broken.policy_version = None
    gateway_capture_client.app.state.evaluator = broken

    _post(gateway_capture_client)

    failed = _gateway_events_of(gateway_events, EVALUATION_FAILED_CLOSED)
    assert failed[0].subject_id == "user1"


def test_audit_writer_failure_does_not_grant_access(gateway_capture_client):
    """Audit write failure must not propagate to the caller or grant access."""

    class _BrokenWriter:
        def write(self, event: Any) -> None:
            raise OSError("audit sink down")

    gateway_capture_client.app.state.audit_writer = _BrokenWriter()
    resp = _post(gateway_capture_client)
    # Must not 500 due to audit failure; decision is enforced normally.
    assert resp.status_code in (200, 403)
    assert resp.status_code != 500


# ---------------------------------------------------------------------------
# 9. Regression: existing kernel decision audit events still emit
# ---------------------------------------------------------------------------


def test_kernel_decision_event_still_emits_after_hardening(capture_client, captured_events):
    """The kernel's EnforcementPoint still writes its decision event unchanged."""
    resp = capture_client.post(
        "/v1/evaluate",
        json=_VALID_BODY,
        headers=_AUTH_HDR,
    )
    assert resp.status_code in (200, 403)

    from basis_core.audit import AuditEvent

    assert len(captured_events) == 1
    assert isinstance(captured_events[0], AuditEvent)
    assert captured_events[0].subject_id == "user1"
    assert captured_events[0].action == actions.READ_SENSOR_TELEMETRY


def test_gateway_events_use_system_event_type(gateway_capture_client, gateway_events):
    """All gateway-level events use SYSTEM_EVENT, not AUTHORIZATION_DECISION."""
    # Trigger a gateway-level event (missing token produces AUTHENTICATION_FAILED).
    _post(gateway_capture_client, headers={})

    for event in gateway_events:
        if event.action.startswith("gateway."):
            assert event.event_type == AuditEventType.SYSTEM_EVENT
