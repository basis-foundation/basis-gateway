"""Fail-closed tests for basis-gateway.

Verifies that every error path results in denial — never in authorization.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from basis_core.audit import NullAuditWriter
from basis_core.domain import action as actions
from basis_core.enforcement import EnforcementPoint
from basis_core.policy import PolicyEngine, RolePolicyRule

from basis_gateway.auth.errors import JWKSFetchError, JWTVerificationError
from basis_gateway.core.evaluator import GatewayEvaluator


def _evaluate(client, **overrides):
    body = {"action": actions.READ_SENSOR_TELEMETRY, "resource_id": "sensor:ahu-1"}
    body.update(overrides)
    return client.post("/v1/evaluate", json=body, headers={"Authorization": "Bearer fake"})


# ---------------------------------------------------------------------------
# Authentication failures fail closed
# ---------------------------------------------------------------------------


def test_expired_token_fails_closed(evaluate_client, mock_verifier):
    mock_verifier.set_raise(JWTVerificationError("Token has expired"))
    resp = _evaluate(evaluate_client)
    assert resp.status_code == 401
    assert resp.status_code != 200


def test_jwks_fetch_failure_fails_closed(evaluate_client, mock_verifier):
    mock_verifier.set_raise(JWKSFetchError("JWKS endpoint unreachable"))
    resp = _evaluate(evaluate_client)
    assert resp.status_code == 401


def test_subject_mapping_failure_fails_closed(evaluate_client, mock_verifier):
    # Missing sub → SubjectMappingError
    mock_verifier._claims = {"iss": "https://test.example.com"}  # no sub
    resp = _evaluate(evaluate_client)
    assert resp.status_code in (400, 401)
    assert resp.status_code != 200


def test_no_verifier_configured_fails_closed(evaluate_client):
    """If the OIDC verifier is not configured, all requests are denied."""
    evaluate_client.app.state.verifier = None
    resp = _evaluate(evaluate_client)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Evaluator/kernel failures fail closed
# ---------------------------------------------------------------------------


def test_evaluator_exception_fails_closed(evaluate_client):
    """An unexpected evaluator exception must not grant access."""
    broken = MagicMock()
    broken.evaluate.side_effect = RuntimeError("kernel exploded")
    evaluate_client.app.state.evaluator = broken
    resp = _evaluate(evaluate_client)
    assert resp.status_code == 500
    assert resp.status_code != 200


def test_evaluator_not_initialized_fails_closed(evaluate_client):
    evaluate_client.app.state.evaluator = None
    resp = _evaluate(evaluate_client)
    assert resp.status_code == 503
    assert resp.status_code != 200


# ---------------------------------------------------------------------------
# NOT_APPLICABLE never grants access
# ---------------------------------------------------------------------------


def test_not_applicable_never_returns_200(evaluate_client):
    """NOT_APPLICABLE must map to 403, not 200."""
    engine = PolicyEngine(policies=[])
    ep = EnforcementPoint(engine=engine, audit_writer=NullAuditWriter(), policy_version="t")
    evaluate_client.app.state.evaluator = GatewayEvaluator(_enforcement_point=ep)

    resp = _evaluate(evaluate_client)
    assert resp.status_code == 403
    assert resp.json().get("outcome") != "allow"


# ---------------------------------------------------------------------------
# Audit writer failure does not grant access
# ---------------------------------------------------------------------------


def test_audit_write_failure_does_not_grant_access(evaluate_client):
    """If the audit writer raises, the decision must still be enforced."""
    from basis_core.audit import AuditEvent

    class _FailingWriter:
        def write(self, event: AuditEvent) -> None:
            raise OSError("audit sink down")

    engine = PolicyEngine(
        policies=[RolePolicyRule(role_table={actions.READ_SENSOR_TELEMETRY: {"admin"}})]
    )
    ep = EnforcementPoint(engine=engine, audit_writer=_FailingWriter(), policy_version="t")
    evaluate_client.app.state.evaluator = GatewayEvaluator(_enforcement_point=ep)

    resp = _evaluate(evaluate_client)
    # EnforcementPoint catches audit failures internally.
    # Decision is still enforced; gateway must not 500 due to audit failure.
    assert resp.status_code in (200, 403)
    assert resp.status_code != 500


# ---------------------------------------------------------------------------
# Invalid action/resource_id formats fail with 400
# ---------------------------------------------------------------------------


def test_invalid_action_format_returns_400(evaluate_client):
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": "read"},  # missing domain segment
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 400


def test_invalid_resource_id_format_returns_400(evaluate_client):
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": actions.READ_SENSOR_TELEMETRY, "resource_id": "invalid"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 400
