"""Tests for POST /v1/evaluate/operation-aware (PR 6).

Covers §16 PR 6 of
``docs/implementation/operation-aware-gateway-integration-plan.md``: feature
gating, authentication, shape/provenance validation, composition, evaluator
availability, and unexpected-exception containment. Exercises the real
FastAPI route with a real, real-kernel-backed ``OperationAwareGatewayEvaluator``
(constructed via ``build_operation_aware_evaluator``/`for_bundle`` directly,
bypassing file loading only) — never a mock of the kernel.

§9's full HTTP classification table (including the five canonical scenarios)
is covered separately in ``test_operation_aware_endpoint_canonical_scenarios.py``;
the pure classification function itself is covered exhaustively in
``test_operation_aware_http_classification.py``.
"""

from __future__ import annotations

from typing import Any

import pytest
from basis_core.enforcement import OperationAwareEnforcementPoint
from basis_core.policy import PolicyBundle
from fastapi.testclient import TestClient
from helpers import MockVerifier

from basis_gateway.core.operation_aware_evaluator import (
    OperationAwareGatewayEvaluator,
    build_operation_aware_evaluator,
)
from basis_gateway.main import create_app
from basis_gateway.readiness import reset_readiness_state

# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

VALID_BUNDLE = PolicyBundle(
    bundle_id="oa-endpoint-bundle",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    rules=[
        {"rule_id": "allow-read-ahu", "effect": "allow", "match": {"actions": ["read:ahu"]}},
        {"rule_id": "deny-write-ahu", "effect": "deny", "match": {"actions": ["write:ahu"]}},
    ],
)

_NONEXISTENT_BUNDLE_PATH = "/tmp/basis-gateway-test-oa-bundle-does-not-exist.json"


def _oa_evaluator(
    bundle: PolicyBundle = VALID_BUNDLE, **kwargs: Any
) -> OperationAwareGatewayEvaluator:
    return build_operation_aware_evaluator(bundle, **kwargs)  # type: ignore[arg-type]


def _post_oa(client: TestClient, headers: dict[str, str] | None = None, **body: Any):
    return client.post(
        "/v1/evaluate/operation-aware",
        json=body,
        headers=headers if headers is not None else {"Authorization": "Bearer fake"},
    )


@pytest.fixture()
def oa_client(monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier):
    """TestClient with the operation-aware feature flag enabled at
    app-construction time, a mock OIDC verifier, and a real (non-file-loaded)
    operation-aware evaluator injected after lifespan — mirroring the
    existing ``evaluate_client``/``capture_client`` pattern for the v0.1
    path. ``OPERATION_AWARE_POLICY_BUNDLE_PATH`` points at a file that does
    not exist so lifespan's own file-based load predictably fails (this is
    expected and irrelevant to these tests — they exercise the route's own
    ``app.state.operation_aware_evaluator`` null-check and the injected
    evaluator, not startup).
    """
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        app.state.verifier = mock_verifier
        app.state.operation_aware_evaluator = _oa_evaluator()
        yield c


@pytest.fixture()
def oa_disabled_client():
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Feature gating
# ---------------------------------------------------------------------------


def test_disabled_route_returns_404(oa_disabled_client: TestClient) -> None:
    resp = _post_oa(oa_disabled_client, action="read:ahu")
    assert resp.status_code == 404


def test_disabled_existing_evaluate_route_unaffected(oa_disabled_client: TestClient) -> None:
    """/v1/evaluate remains registered (though unauthenticated here, so 401,
    not 404) when the operation-aware feature is disabled."""
    resp = oa_disabled_client.post(
        "/v1/evaluate", json={"action": "read:ahu"}, headers={"Authorization": "Bearer fake"}
    )
    assert resp.status_code != 404


def test_enabled_route_is_reachable(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu")
    assert resp.status_code != 404


def test_enabled_existing_evaluate_route_still_registered(oa_client: TestClient) -> None:
    resp = oa_client.post(
        "/v1/evaluate", json={"action": "read:ahu"}, headers={"Authorization": "Bearer fake"}
    )
    assert resp.status_code != 404


def test_enabled_existing_evaluate_route_behavior_unchanged(oa_client: TestClient) -> None:
    """/v1/evaluate has no evaluator configured in this fixture (only the
    operation-aware evaluator is set) — its behavior (503, evaluator
    unavailable) is identical to what it would be with the feature
    disabled."""
    resp = oa_client.post(
        "/v1/evaluate", json={"action": "read:ahu"}, headers={"Authorization": "Bearer fake"}
    )
    assert resp.status_code == 503
    assert resp.json()["error"] == "evaluator_unavailable"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_missing_token_returns_401(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, headers={}, action="read:ahu")
    assert resp.status_code == 401


def test_malformed_authorization_header_returns_401(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, headers={"Authorization": "Basic dXNlcjpwYXNz"}, action="read:ahu")
    assert resp.status_code == 401


def test_invalid_token_returns_401(oa_client: TestClient, mock_verifier: MockVerifier) -> None:
    from basis_gateway.auth.errors import JWTVerificationError

    mock_verifier.set_raise(JWTVerificationError("Token has expired"))
    resp = _post_oa(oa_client, action="read:ahu")
    assert resp.status_code == 401


def test_unmappable_subject_returns_401(oa_client: TestClient, mock_verifier: MockVerifier) -> None:
    """A verified token with no 'sub' claim fails subject mapping."""
    del mock_verifier._claims["sub"]
    resp = _post_oa(oa_client, action="read:ahu")
    assert resp.status_code == 401


def test_caller_supplied_subject_id_rejected_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", subject_id="attacker-controlled")
    assert resp.status_code == 400


def test_caller_supplied_subject_roles_rejected_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", subject_roles=["admin"])
    assert resp.status_code == 400


def test_401_kernel_not_invoked_no_kernel_fields_in_body(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, headers={}, action="read:ahu")
    assert resp.status_code == 401
    body = resp.json()
    assert "evaluation_status" not in body
    assert "disposition" not in body


# ---------------------------------------------------------------------------
# Shape validation and gateway-owned-field spoofing
# ---------------------------------------------------------------------------


def test_malformed_json_body_returns_400(oa_client: TestClient) -> None:
    resp = oa_client.post(
        "/v1/evaluate/operation-aware",
        content=b"not-json",
        headers={"Authorization": "Bearer fake", "Content-Type": "application/json"},
    )
    assert resp.status_code == 400


def test_missing_action_returns_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, resource_id="ahu:rooftop-1")
    assert resp.status_code == 400


def test_unknown_extra_field_rejected_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", unknown_field="value")
    assert resp.status_code == 400


def test_expected_policy_version_rejected_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", expected_policy_version="1.0.0")
    assert resp.status_code == 400


def test_nonempty_free_form_context_rejected_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", context={"maintenance_ticket": "CHG-1"})
    assert resp.status_code == 400


def test_empty_context_accepted(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", context={})
    assert resp.status_code == 200


def test_missing_context_accepted(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu")
    assert resp.status_code == 200


def test_gateway_owned_evaluation_time_spoof_rejected_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", evaluation_time="2020-01-01T00:00:00Z")
    assert resp.status_code == 400


def test_gateway_owned_disposition_spoof_rejected_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", disposition="allow")
    assert resp.status_code == 400


def test_gateway_owned_correlation_id_spoof_rejected_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", correlation_id="attacker-supplied")
    assert resp.status_code == 400


def test_caller_cannot_influence_evaluation_time_when_accepted(oa_client: TestClient) -> None:
    """Confirms the request succeeds without evaluation_time (it is
    gateway-generated, never caller-suppliable) — paired with the spoof
    rejection test above, which proves supplying it at all is rejected
    outright (there is no silent-drop path)."""
    resp = _post_oa(oa_client, action="read:ahu")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Operation-producer trust / provenance
# ---------------------------------------------------------------------------


def test_producer_only_field_from_untrusted_caller_rejected_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", operation_intent="read_only")
    assert resp.status_code == 400


def test_producer_only_field_rejection_does_not_invoke_kernel(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", operation_intent="read_only")
    assert resp.status_code == 400
    assert "evaluation_status" not in resp.json()


def test_producer_only_field_from_trusted_producer_reaches_evaluation(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    """mock_verifier's default 'sub' claim is 'user1' (see conftest.py);
    configuring OPERATION_PRODUCER_SUBJECT_IDS=user1 classifies that same
    caller as a trusted operation producer."""
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", "user1")
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        app.state.verifier = mock_verifier
        app.state.operation_aware_evaluator = _oa_evaluator()
        resp = _post_oa(c, action="read:ahu", operation_intent="read_only")
    assert resp.status_code == 200
    assert resp.json()["evaluation_status"] == "completed"


def test_untrusted_producer_by_default_with_no_configuration(oa_client: TestClient) -> None:
    """With OPERATION_PRODUCER_SUBJECT_IDS unset (this fixture's default),
    no caller — including the same subject_id used in the trusted-producer
    test above — is ever classified as a producer."""
    resp = _post_oa(oa_client, action="read:ahu", operation_intent="read_only")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------


def test_bare_action_plus_resource_type_composed(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read", resource_type="ahu")
    assert resp.status_code == 200


def test_already_composite_action_unchanged(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu")
    assert resp.status_code == 200


def test_local_resource_id_composed(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read", resource_type="ahu", resource_id="rooftop-1")
    assert resp.status_code == 200


def test_already_typed_resource_id_unchanged(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", resource_id="ahu:rooftop-1")
    assert resp.status_code == 200


def test_action_composition_error_returns_400(oa_client: TestClient) -> None:
    """Bare verb with no resource_type cannot be composed."""
    resp = _post_oa(oa_client, action="read")
    assert resp.status_code == 400


def test_composite_action_with_resource_type_returns_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", resource_type="ahu")
    assert resp.status_code == 400


def test_resource_composition_error_returns_400(oa_client: TestClient) -> None:
    """Local resource_id with no resource_type cannot be composed."""
    resp = _post_oa(oa_client, action="read:ahu", resource_id="rooftop-1")
    assert resp.status_code == 400


def test_typed_resource_id_with_resource_type_returns_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", resource_id="ahu:rooftop-1", resource_type="ahu")
    assert resp.status_code == 400


def test_reserved_context_key_from_caller_rejected_400(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", context={"basis_gateway.forged": "x"})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Correlation ID / request ID
# ---------------------------------------------------------------------------


def test_correlation_id_header_present(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu")
    assert "x-correlation-id" in resp.headers


def test_correlation_id_header_present_on_error_paths(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, headers={}, action="read:ahu")
    assert resp.status_code == 401
    assert "x-correlation-id" in resp.headers


def test_response_includes_request_id(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu")
    assert "request_id" in resp.json()


def test_caller_request_id_is_echoed(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu", request_id="my-oa-req-123")
    assert resp.json()["request_id"] == "my-oa-req-123"


def test_request_id_defaults_to_correlation_id_when_absent(oa_client: TestClient) -> None:
    resp = _post_oa(oa_client, action="read:ahu")
    assert resp.json()["request_id"] == resp.headers["x-correlation-id"]


def test_caller_supplied_x_correlation_id_header_ignored(oa_client: TestClient) -> None:
    resp = _post_oa(
        oa_client,
        headers={"Authorization": "Bearer fake", "X-Correlation-ID": "attacker-supplied-id"},
        action="read:ahu",
    )
    assert resp.headers["x-correlation-id"] != "attacker-supplied-id"


# ---------------------------------------------------------------------------
# Evaluator availability
# ---------------------------------------------------------------------------


def test_missing_evaluator_returns_503(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        app.state.verifier = mock_verifier
        assert app.state.operation_aware_evaluator is None
        resp = _post_oa(c, action="read:ahu")
    assert resp.status_code == 503


def test_missing_evaluator_kernel_not_invoked(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        app.state.verifier = mock_verifier
        resp = _post_oa(c, action="read:ahu")
    body = resp.json()
    assert "evaluation_status" not in body
    assert "trace_id" not in body
    assert body["error"] == "evaluator_unavailable"


# ---------------------------------------------------------------------------
# Unexpected exception containment (defensive boundary, §11)
# ---------------------------------------------------------------------------


class _ExplodingEvaluator:
    """Stand-in that raises from evaluate() to exercise the route's own
    defensive exception boundary around the evaluator call — never used to
    fake a kernel *result*, only to prove the route fails closed and never
    fabricates a kernel outcome when an unexpected exception occurs."""

    def evaluate(self, composed: object) -> None:
        raise RuntimeError("simulated unexpected integration failure — secret-token-xyz")


def test_unexpected_exception_from_evaluator_returns_500(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        app.state.verifier = mock_verifier
        app.state.operation_aware_evaluator = _ExplodingEvaluator()
        resp = _post_oa(c, action="read:ahu")
    assert resp.status_code == 500


def test_unexpected_exception_does_not_leak_exception_text(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        app.state.verifier = mock_verifier
        app.state.operation_aware_evaluator = _ExplodingEvaluator()
        resp = _post_oa(c, action="read:ahu")
    assert "secret-token-xyz" not in resp.text


def test_unexpected_exception_does_not_fabricate_kernel_result(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        app.state.verifier = mock_verifier
        app.state.operation_aware_evaluator = _ExplodingEvaluator()
        resp = _post_oa(c, action="read:ahu")
    body = resp.json()
    assert "disposition" not in body
    assert "evaluation_status" not in body
    assert body["error"] == "evaluation_failed_closed"


def test_kernel_construction_error_returns_400_not_500(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    """A gateway-owned, pre-kernel OperationAwareRequestConstructionError
    (kernel-request Pydantic construction failure) must be classified as a
    400, distinctly from an unexpected-exception 500 — the kernel was never
    invoked in either case, but this one is a well-understood, gateway-owned
    validation failure category (§7)."""
    from basis_gateway.core.operation_aware_evaluator import (
        OperationAwareRequestConstructionError,
    )

    class _ConstructionFailingEvaluator:
        def evaluate(self, composed: object) -> None:
            raise OperationAwareRequestConstructionError("simulated construction failure")

    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        app.state.verifier = mock_verifier
        app.state.operation_aware_evaluator = _ConstructionFailingEvaluator()
        resp = _post_oa(c, action="read:ahu")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Import-boundary regression (mirrors existing AST-based checks; see
# test_operation_aware_public_api_contract.py for the authoritative version)
# ---------------------------------------------------------------------------


def test_routes_module_does_not_import_kernel_internals() -> None:
    import ast
    import inspect

    from basis_gateway.api import routes

    source = inspect.getsource(routes)
    tree = ast.parse(source)
    forbidden_prefixes = (
        "basis_core.evaluation",
        "basis_core.policy.operation_aware.validation",
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert not any(node.module.startswith(p) for p in forbidden_prefixes), node.module
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not any(alias.name.startswith(p) for p in forbidden_prefixes), alias.name


def test_enforcement_point_constructed_only_via_for_bundle_in_evaluator_module() -> None:
    """Defense-in-depth: confirm the evaluator module (which the route
    depends on) never falls back to OperationAwareEnforcementPoint's direct
    constructor."""
    import inspect

    from basis_gateway.core import operation_aware_evaluator as ev_module

    source = inspect.getsource(ev_module)
    assert "OperationAwareEnforcementPoint(" not in source
    assert OperationAwareEnforcementPoint.for_bundle is not None
