"""Tests for POST /v1/evaluate.

Uses real basis-core EnforcementPoint with a mock OIDC verifier.
No live IdP required.
"""

from __future__ import annotations

from basis_core.audit import NullAuditWriter
from basis_core.domain import action as actions
from basis_core.enforcement import EnforcementPoint
from basis_core.policy import PolicyEngine, RolePolicyRule

from basis_gateway.core.evaluator import GatewayEvaluator


def _evaluate(client, action: str, resource_id: str | None = "sensor:ahu-1", **kwargs):
    body = {"action": action}
    if resource_id is not None:
        body["resource_id"] = resource_id
    body.update(kwargs)
    return client.post("/v1/evaluate", json=body, headers={"Authorization": "Bearer fake"})


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_allow_returns_200(evaluate_client):
    resp = _evaluate(evaluate_client, actions.READ_SENSOR_TELEMETRY)
    assert resp.status_code == 200


def test_allow_response_body(evaluate_client):
    resp = _evaluate(evaluate_client, actions.READ_SENSOR_TELEMETRY)
    data = resp.json()
    assert data["outcome"] == "allow"
    assert "request_id" in data
    assert "reason" in data


def test_deny_returns_403(evaluate_client, mock_verifier):
    mock_verifier._claims["realm_access"] = {"roles": ["viewer"]}
    resp = _evaluate(evaluate_client, actions.WRITE_HVAC_SETPOINT)
    assert resp.status_code == 403


def test_deny_response_outcome(evaluate_client, mock_verifier):
    mock_verifier._claims["realm_access"] = {"roles": ["viewer"]}
    resp = _evaluate(evaluate_client, actions.WRITE_HVAC_SETPOINT)
    assert resp.json()["outcome"] == "deny"


def test_not_applicable_outcome_never_grants_access(evaluate_client):
    """An action covered by no policy rule → NOT_APPLICABLE → 403."""
    engine = PolicyEngine(
        policies=[
            RolePolicyRule(
                role_table={actions.READ_SENSOR_TELEMETRY: {"admin"}},
                rule_name="narrow-rbac",
            )
        ]
    )
    ep = EnforcementPoint(engine=engine, audit_writer=NullAuditWriter(), policy_version="t")
    evaluate_client.app.state.evaluator = GatewayEvaluator(_enforcement_point=ep)

    # WRITE_HVAC_SETPOINT not in narrow policy → NOT_APPLICABLE → 403
    resp = _evaluate(evaluate_client, actions.WRITE_HVAC_SETPOINT)
    assert resp.status_code == 403
    assert resp.json()["outcome"] != "allow"


def test_not_applicable_response_outcome(evaluate_client):
    """NOT_APPLICABLE outcome should be surfaced in response body (for diagnostics)."""
    engine = PolicyEngine(policies=[])  # nothing matches → NOT_APPLICABLE
    ep = EnforcementPoint(engine=engine, audit_writer=NullAuditWriter(), policy_version="t")
    evaluate_client.app.state.evaluator = GatewayEvaluator(_enforcement_point=ep)

    resp = _evaluate(evaluate_client, actions.READ_SENSOR_TELEMETRY)
    assert resp.status_code == 403
    assert resp.json()["outcome"] == "not_applicable"


# ---------------------------------------------------------------------------
# Authentication failures
# ---------------------------------------------------------------------------


def test_missing_authorization_header_returns_401(evaluate_client):
    resp = evaluate_client.post("/v1/evaluate", json={"action": actions.READ_SENSOR_TELEMETRY})
    assert resp.status_code == 401


def test_malformed_authorization_header_returns_401(evaluate_client):
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": actions.READ_SENSOR_TELEMETRY},
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert resp.status_code == 401


def test_invalid_token_returns_401(evaluate_client, mock_verifier):
    from basis_gateway.auth.errors import JWTVerificationError

    mock_verifier.set_raise(JWTVerificationError("Token has expired"))
    resp = _evaluate(evaluate_client, actions.READ_SENSOR_TELEMETRY)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Request body validation
# ---------------------------------------------------------------------------


def test_malformed_body_returns_400(evaluate_client):
    resp = evaluate_client.post(
        "/v1/evaluate",
        content=b"not-json",
        headers={"Authorization": "Bearer fake", "Content-Type": "application/json"},
    )
    assert resp.status_code == 400


def test_missing_action_returns_400(evaluate_client):
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"resource_id": "sensor:ahu-1"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 400


def test_caller_supplied_subject_id_rejected_400(evaluate_client):
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={
            "action": actions.READ_SENSOR_TELEMETRY,
            "subject_id": "attacker-controlled",
        },
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 400


def test_caller_supplied_subject_roles_rejected_400(evaluate_client):
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={
            "action": actions.READ_SENSOR_TELEMETRY,
            "subject_roles": ["admin"],
        },
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 400


def test_unknown_extra_field_rejected_400(evaluate_client):
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": actions.READ_SENSOR_TELEMETRY, "unknown_field": "value"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Correlation / request ID
# ---------------------------------------------------------------------------


def test_response_includes_request_id(evaluate_client):
    resp = _evaluate(evaluate_client, actions.READ_SENSOR_TELEMETRY)
    assert "request_id" in resp.json()


def test_caller_request_id_is_echoed(evaluate_client):
    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": actions.READ_SENSOR_TELEMETRY, "request_id": "my-req-123"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.json()["request_id"] == "my-req-123"


def test_correlation_id_header_present(evaluate_client):
    resp = _evaluate(evaluate_client, actions.READ_SENSOR_TELEMETRY)
    assert "x-correlation-id" in resp.headers


# ---------------------------------------------------------------------------
# Security: no raw JWT claims in response
# ---------------------------------------------------------------------------


def test_raw_jwt_claims_not_in_response(evaluate_client, mock_verifier):
    mock_verifier._claims["email"] = "secret@example.com"
    resp = _evaluate(evaluate_client, actions.READ_SENSOR_TELEMETRY)
    assert "secret@example.com" not in resp.text
    assert "fake" not in resp.text or "fake.token" not in resp.text


# ---------------------------------------------------------------------------
# Policy version provenance
# ---------------------------------------------------------------------------


def test_policy_version_appears_in_allow_response(evaluate_client):
    """ALLOW response includes the policy_version configured on the evaluator."""
    # build_null_evaluator() uses policy_version="test"; that is what evaluate_client uses.
    resp = _evaluate(evaluate_client, actions.READ_SENSOR_TELEMETRY)
    assert resp.status_code == 200
    assert resp.json()["policy_version"] == "test"


def test_policy_version_appears_in_deny_response(evaluate_client, mock_verifier):
    """DENY response also includes the policy_version."""
    mock_verifier._claims["realm_access"] = {"roles": ["viewer"]}
    resp = _evaluate(evaluate_client, actions.WRITE_HVAC_SETPOINT)
    assert resp.status_code == 403
    assert resp.json()["policy_version"] == "test"


def test_policy_version_null_when_not_configured(evaluate_client):
    """When no policy_version is set, response omits the field (exclude_none=True)."""
    # mock_verifier default roles are ["admin", "viewer"]; use "admin" here.
    ep = EnforcementPoint(
        engine=PolicyEngine(policies=[RolePolicyRule({actions.READ_SENSOR_TELEMETRY: {"admin"}})]),
        audit_writer=NullAuditWriter(),
        # no policy_version
    )
    evaluate_client.app.state.evaluator = GatewayEvaluator(_enforcement_point=ep)
    resp = _evaluate(evaluate_client, actions.READ_SENSOR_TELEMETRY)
    assert resp.status_code == 200
    assert "policy_version" not in resp.json()


def test_gateway_evaluator_policy_version_uses_public_api(evaluate_client):
    """GatewayEvaluator.policy_version must delegate to the kernel public property."""
    evaluator: GatewayEvaluator = evaluate_client.app.state.evaluator
    # The property must exist and return the same value as the kernel's own property.
    assert evaluator.policy_version == evaluator._enforcement_point.policy_version


def test_gateway_evaluator_policy_version_not_private_access():
    """GatewayEvaluator.policy_version must not rely on _policy_version."""
    import inspect

    from basis_gateway.core import evaluator as ev_module

    source = inspect.getsource(ev_module.GatewayEvaluator.policy_version.fget)  # type: ignore[union-attr]
    assert "_policy_version" not in source, (
        "GatewayEvaluator.policy_version must use the public "
        "EnforcementPoint.policy_version API, not _policy_version"
    )
