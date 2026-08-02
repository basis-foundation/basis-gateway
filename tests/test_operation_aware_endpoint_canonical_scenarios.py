"""Canonical scenario and HTTP-classification-table conformance for
``POST /v1/evaluate/operation-aware`` (PR 6).

Runs the five canonical ``basis-schemas`` compatibility scenarios —
``allow-basic``, ``deny-precedence``, ``default-deny``, ``not-applicable``,
``invalid-policy-bundle`` — through the real FastAPI route, real
composition, a real ``OperationAwareGatewayEvaluator``, and a real public
``OperationAwareEnforcementPoint``. No kernel behavior is reimplemented or
mocked here; every assertion is against the actual returned result.

A note on failure-reason coverage
----------------------------------
§9's classification table lists six governed ``OperationAwareFailureReason``
values. Of those, only ``policy_validation_failure`` (the
``invalid-policy-bundle`` canonical scenario, per the corrected
basis-schemas v0.2.1 classification — see below) and
``condition_evaluation_error`` are reachable through the real, public
``OperationAwareEnforcementPoint.for_bundle()`` + ``evaluate()`` path with a
structurally valid bundle and a well-formed request. ``invalid_request``,
``unsupported_schema_version``, and ``internal_evaluation_error`` are not
constructible this way: ``basis-core``'s own test suite
(``tests/operation_aware/test_operation_aware_enforcement_point.py``,
``TestGovernedFailureNotReachableThroughRealEngine``) confirms these three
are only reachable by injecting a stub/raising engine through
``OperationAwareEnforcementPoint``'s internal (non-``for_bundle``)
constructor — a kernel-internal test technique this repository must not
reproduce (§8: no import of ``basis_core.evaluation.*`` or any non-public
constructor path). Those three failure reasons' HTTP classification is
still exhaustively covered at the pure-function level in
``test_operation_aware_http_classification.py``; this module covers only
what the real kernel can actually be made to return.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from basis_core.enforcement import EnforcementDisposition, OperationAwareEnforcementPoint
from basis_core.policy import PolicyBundle
from fastapi.testclient import TestClient
from helpers import MockVerifier

from basis_gateway.core.operation_aware_evaluator import (
    OperationAwareGatewayEvaluator,
    build_operation_aware_evaluator,
)
from basis_gateway.main import create_app
from basis_gateway.readiness import reset_readiness_state

_NONEXISTENT_BUNDLE_PATH = "/tmp/basis-gateway-test-oa-canonical-bundle-does-not-exist.json"
_FIXED_TIME = datetime(2026, 8, 1, 12, tzinfo=timezone.utc)


def _post_oa(client: TestClient, **body: Any):
    return client.post(
        "/v1/evaluate/operation-aware",
        json=body,
        headers={"Authorization": "Bearer fake"},
    )


def _client_with_evaluator(
    monkeypatch: pytest.MonkeyPatch,
    mock_verifier: MockVerifier,
    evaluator: OperationAwareGatewayEvaluator,
) -> TestClient:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    reset_readiness_state()
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    client.__enter__()
    app.state.verifier = mock_verifier
    app.state.operation_aware_evaluator = evaluator
    return client


# ---------------------------------------------------------------------------
# allow-basic
# ---------------------------------------------------------------------------


def test_allow_basic(monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier) -> None:
    bundle = PolicyBundle(
        bundle_id="canonical-allow-basic",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[
            {"rule_id": "allow-read-ahu", "effect": "allow", "match": {"actions": ["read:ahu"]}}
        ],
    )
    evaluator = build_operation_aware_evaluator(bundle)
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator)

    resp = _post_oa(client, action="read:ahu")

    assert resp.status_code == 200
    body = resp.json()
    assert body["evaluation_status"] == "completed"
    assert body["outcome"] == "allow"
    assert "failure_reason" not in body
    assert body["disposition"] == "allow"
    assert body["bundle_id"] == "canonical-allow-basic"


# ---------------------------------------------------------------------------
# deny-precedence
# ---------------------------------------------------------------------------


def test_deny_precedence(monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier) -> None:
    """A request matching both an allow and a deny rule for the same action
    — deny takes precedence."""
    bundle = PolicyBundle(
        bundle_id="canonical-deny-precedence",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[
            {"rule_id": "allow-write-ahu", "effect": "allow", "match": {"actions": ["write:ahu"]}},
            {"rule_id": "deny-write-ahu", "effect": "deny", "match": {"actions": ["write:ahu"]}},
        ],
    )
    evaluator = build_operation_aware_evaluator(bundle)
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator)

    resp = _post_oa(client, action="write:ahu")

    assert resp.status_code == 403
    body = resp.json()
    assert body["evaluation_status"] == "completed"
    assert body["outcome"] == "deny"
    assert body["disposition"] == "deny"


# ---------------------------------------------------------------------------
# default-deny
# ---------------------------------------------------------------------------


def test_default_deny(monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier) -> None:
    """No rule matches the requested action; the bundle has no scope
    restriction, so the result is a completed default deny, not
    NOT_APPLICABLE."""
    bundle = PolicyBundle(
        bundle_id="canonical-default-deny",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[
            {"rule_id": "allow-read-ahu", "effect": "allow", "match": {"actions": ["read:ahu"]}}
        ],
    )
    evaluator = build_operation_aware_evaluator(bundle)
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator)

    resp = _post_oa(client, action="write:ahu")

    assert resp.status_code == 403
    body = resp.json()
    assert body["evaluation_status"] == "completed"
    assert body["outcome"] == "deny"
    assert body["disposition"] == "deny"


# ---------------------------------------------------------------------------
# not-applicable
# ---------------------------------------------------------------------------


def test_not_applicable(monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier) -> None:
    """The bundle's scope excludes the requested action entirely."""
    bundle = PolicyBundle(
        bundle_id="canonical-not-applicable",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        scope={"actions": ["read:other_domain"]},
        rules=[
            {"rule_id": "allow-read-ahu", "effect": "allow", "match": {"actions": ["read:ahu"]}}
        ],
    )
    evaluator = build_operation_aware_evaluator(bundle)
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator)

    resp = _post_oa(client, action="read:ahu")

    assert resp.status_code == 403
    body = resp.json()
    assert body["evaluation_status"] == "completed"
    assert body["outcome"] == "not_applicable"
    # The central §9 invariant: NOT_APPLICABLE is blocked (403) but never
    # rewritten to "deny" in the response body.
    assert body["outcome"] != "deny"
    assert body["disposition"] == "deny"


# ---------------------------------------------------------------------------
# invalid-policy-bundle (failure_reason=policy_validation_failure per the
# corrected basis-schemas v0.2.1 classification for this canonical vector —
# NOT the obsolete invalid_policy_bundle expectation)
# ---------------------------------------------------------------------------


def test_invalid_policy_bundle_canonical_scenario(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    """This represents the post-preflight dependency-integrity anomaly path,
    not a production startup configuration that should normally become
    ready: a real, structurally-valid-but-semantically-invalid bundle
    (duplicate rule_id) is loaded directly through the real public
    ``OperationAwareEnforcementPoint.for_bundle()`` factory, bypassing only
    ``build_operation_aware_evaluator``'s own startup preflight (which would
    itself correctly reject this bundle at startup — see
    ``test_operation_aware_startup.py::test_enabled_duplicate_rule_ids_fail_startup``
    for proof that production startup preflight is NOT weakened by this
    test). The evaluator is injected through the same
    app.state test seam every other fixture in this module uses.
    """
    dup_bundle = PolicyBundle(
        bundle_id="canonical-invalid-policy-bundle",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[
            {"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}},
            {"rule_id": "r1", "effect": "deny", "match": {"actions": ["write:ahu"]}},
        ],
    )
    enforcement_point = OperationAwareEnforcementPoint.for_bundle(dup_bundle)
    evaluator = OperationAwareGatewayEvaluator(
        _enforcement_point=enforcement_point,
        _trace_id_factory=lambda: "canonical-invalid-bundle-trace",
        _evidence_id_factory=lambda: "canonical-invalid-bundle-evidence",
        _clock=lambda: _FIXED_TIME,
    )
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator)

    resp = _post_oa(client, action="read:ahu")

    assert resp.status_code == 503
    body = resp.json()
    assert body["evaluation_status"] == "failed"
    assert body["failure_reason"] == "policy_validation_failure"
    assert body.get("outcome") is None or "outcome" not in body
    assert body["disposition"] == "deny"


def test_invalid_policy_bundle_scenario_never_returns_403(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    """A dependency-integrity anomaly must never be reported as an ordinary
    policy denial."""
    dup_bundle = PolicyBundle(
        bundle_id="canonical-invalid-policy-bundle-2",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[
            {"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}},
            {"rule_id": "r1", "effect": "deny", "match": {"actions": ["write:ahu"]}},
        ],
    )
    enforcement_point = OperationAwareEnforcementPoint.for_bundle(dup_bundle)
    evaluator = OperationAwareGatewayEvaluator(
        _enforcement_point=enforcement_point,
        _trace_id_factory=lambda: "trace-x",
        _evidence_id_factory=lambda: "evidence-x",
        _clock=lambda: _FIXED_TIME,
    )
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator)

    resp = _post_oa(client, action="read:ahu")

    assert resp.status_code != 403


# ---------------------------------------------------------------------------
# condition_evaluation_error (the one other governed failure reachable
# through the real kernel — see module docstring)
# ---------------------------------------------------------------------------


def test_condition_evaluation_error(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    bundle = PolicyBundle(
        bundle_id="canonical-condition-error",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[
            {
                "rule_id": "cond-error-rule",
                "effect": "allow",
                "match": {"actions": ["read:ahu"]},
                "conditions": [
                    {
                        "condition_id": "c1",
                        "field_path": "subject_id",
                        "operator": "not_a_real_operator",
                        "expected_value": "irrelevant",
                    }
                ],
            }
        ],
    )
    # Preflight would itself hit this same condition-evaluation error against
    # the synthetic preflight request (a different action), so this bundle
    # must be constructed directly via for_bundle(), exactly as for the
    # invalid-policy-bundle scenario above — evaluate() never raises either
    # way, so this remains a real-kernel-produced result, not a mock.
    enforcement_point = OperationAwareEnforcementPoint.for_bundle(bundle)
    evaluator = OperationAwareGatewayEvaluator(
        _enforcement_point=enforcement_point,
        _trace_id_factory=lambda: "trace-cond",
        _evidence_id_factory=lambda: "evidence-cond",
        _clock=lambda: _FIXED_TIME,
    )
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator)

    resp = _post_oa(client, action="read:ahu")

    assert resp.status_code == 500
    body = resp.json()
    assert body["evaluation_status"] == "failed"
    assert body["failure_reason"] == "condition_evaluation_error"
    assert body["disposition"] == "deny"


# ---------------------------------------------------------------------------
# Cross-scenario invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("bundle_kwargs", "action", "expected_status"),
    [
        (
            {"rules": [{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}]},
            "read:ahu",
            200,
        ),
        (
            {"rules": [{"rule_id": "r1", "effect": "deny", "match": {"actions": ["write:ahu"]}}]},
            "write:ahu",
            403,
        ),
    ],
)
def test_trace_id_and_bundle_identity_preserved_across_scenarios(
    monkeypatch: pytest.MonkeyPatch,
    mock_verifier: MockVerifier,
    bundle_kwargs: dict[str, Any],
    action: str,
    expected_status: int,
) -> None:
    bundle = PolicyBundle(
        bundle_id="trace-identity-bundle",
        bundle_version="9.9.9",
        schema_version="1.0.0",
        policy_owner="test-owner",
        **bundle_kwargs,
    )
    evaluator = build_operation_aware_evaluator(bundle, trace_id_factory=lambda: "fixed-trace-abc")
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator)

    resp = _post_oa(client, action=action)

    assert resp.status_code == expected_status
    body = resp.json()
    assert body["trace_id"] == "fixed-trace-abc"
    assert body["bundle_id"] == "trace-identity-bundle"
    assert body["bundle_version"] == "9.9.9"


def test_disposition_is_kernel_computed_not_gateway_recomputed(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    bundle = PolicyBundle(
        bundle_id="disposition-check-bundle",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
    )
    evaluator = build_operation_aware_evaluator(bundle)
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator)

    resp = _post_oa(client, action="read:ahu")
    body = resp.json()
    assert body["disposition"] == EnforcementDisposition.ALLOW.value
