"""Integration tests for the gateway action-composition boundary on /v1/evaluate.

Covers the two supported request styles, ambiguity rejection, reserved-namespace
collision handling, and composition evidence preservation.
"""

from __future__ import annotations

from typing import Any

import pytest
from basis_core.audit import NullAuditWriter
from basis_core.decisions import DecisionOutcome, DecisionResponse
from basis_core.domain import action as actions
from basis_core.enforcement import EnforcementPoint
from basis_core.policy import PolicyEngine, RolePolicyRule

from basis_gateway.core.actions import (
    EVIDENCE_ACTION_COMPOSED,
    EVIDENCE_COMPOSED_ACTION,
    EVIDENCE_ORIGINAL_ACTION,
    EVIDENCE_RESOURCE_TYPE,
)
from basis_gateway.core.evaluator import GatewayEvaluator

_AUTH = {"Authorization": "Bearer fake"}


def _post(client, body: dict[str, Any]):
    return client.post("/v1/evaluate", json=body, headers=_AUTH)


# ---------------------------------------------------------------------------
# Recording evaluator — captures exactly what the gateway hands to the kernel
# ---------------------------------------------------------------------------


class _RecordingEvaluator:
    """Stand-in evaluator that records the action/resource_id/context it receives.

    Always returns ALLOW so HTTP outcome does not depend on policy content; the
    point of these tests is *what the gateway composed*, not the decision.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.policy_version: str | None = "test"

    def evaluate(
        self,
        *,
        normalized_subject: Any,
        raw_token: str,
        claims: dict[str, Any],
        action: str,
        resource_id: str | None,
        request_id: str,
        correlation_id: str | None,
        context: dict[str, str],
    ) -> DecisionResponse:
        self.calls.append({"action": action, "resource_id": resource_id, "context": dict(context)})
        return DecisionResponse(
            request_id=request_id,
            outcome=DecisionOutcome.ALLOW,
            reason="recorded",
            evaluated_by="recording-stub",
            policy_version="test",
        )

    @property
    def last(self) -> dict[str, Any]:
        return self.calls[-1]


@pytest.fixture()
def recording(evaluate_client):
    """Replace the evaluator with a recording stub; return (client, recorder)."""
    rec = _RecordingEvaluator()
    evaluate_client.app.state.evaluator = rec
    return evaluate_client, rec


# ---------------------------------------------------------------------------
# Style 1 — direct kernel-compatible (composite) requests pass through unchanged
# ---------------------------------------------------------------------------


def test_composite_request_passes_action_through(recording):
    client, rec = recording
    resp = _post(client, {"action": "read:ahu", "resource_id": "ahu-1"})
    assert resp.status_code == 200
    assert rec.last["action"] == "read:ahu"
    assert rec.last["resource_id"] == "ahu-1"


def test_composite_request_adds_no_composition_evidence(recording):
    client, rec = recording
    _post(client, {"action": "read:ahu", "resource_id": "ahu-1"})
    ctx = rec.last["context"]
    for key in (
        EVIDENCE_ACTION_COMPOSED,
        EVIDENCE_ORIGINAL_ACTION,
        EVIDENCE_RESOURCE_TYPE,
        EVIDENCE_COMPOSED_ACTION,
    ):
        assert key not in ctx


def test_existing_composite_request_still_allows_end_to_end(evaluate_client):
    """Regression: a normal composite request still evaluates against real policy."""
    resp = _post(evaluate_client, {"action": actions.READ_SENSOR_TELEMETRY})
    assert resp.status_code == 200
    assert resp.json()["outcome"] == "allow"


# ---------------------------------------------------------------------------
# Style 2 — adapter-normalized (bare verb + resource_type) requests compose
# ---------------------------------------------------------------------------


def test_bare_request_composes_action(recording):
    client, rec = recording
    resp = _post(client, {"action": "read", "resource_type": "ahu", "resource_id": "ahu-1"})
    assert resp.status_code == 200
    assert rec.last["action"] == "read:ahu"
    assert rec.last["resource_id"] == "ahu-1"


def test_bare_request_composes_and_evaluates_end_to_end(evaluate_client):
    """Composed action is what the kernel evaluates: a policy on read:ahu grants ALLOW."""
    engine = PolicyEngine(
        policies=[RolePolicyRule(role_table={"read:ahu": {"admin", "viewer"}}, rule_name="rbac")]
    )
    ep = EnforcementPoint(engine=engine, audit_writer=NullAuditWriter(), policy_version="test")
    evaluate_client.app.state.evaluator = GatewayEvaluator(_enforcement_point=ep)

    # resource_id must satisfy the kernel's own {type}:{qualifier} format
    # independently of action composition (the gateway does not rewrite it).
    resp = _post(
        evaluate_client,
        {"action": "read", "resource_type": "ahu", "resource_id": "ahu:rooftop-1"},
    )
    assert resp.status_code == 200
    assert resp.json()["outcome"] == "allow"


def test_bare_verb_not_matched_when_policy_keys_composite(evaluate_client, mock_verifier):
    """A policy keyed only on the composite would NOT match a bare 'read'.

    Proves the kernel sees the composed action: the same policy that grants
    'read:ahu' is used, and the composed request is ALLOWed.
    """
    engine = PolicyEngine(
        policies=[RolePolicyRule(role_table={"read:ahu": {"admin", "viewer"}}, rule_name="rbac")]
    )
    ep = EnforcementPoint(engine=engine, audit_writer=NullAuditWriter(), policy_version="test")
    evaluate_client.app.state.evaluator = GatewayEvaluator(_enforcement_point=ep)
    resp = _post(evaluate_client, {"action": "read", "resource_type": "ahu"})
    assert resp.status_code == 200
    assert resp.json()["outcome"] == "allow"


# ---------------------------------------------------------------------------
# Ambiguity / missing-field rejection (400 validation_failed)
# ---------------------------------------------------------------------------


def test_bare_action_without_resource_type_returns_400(evaluate_client):
    resp = _post(evaluate_client, {"action": "read", "resource_id": "ahu-1"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "validation_failed"


def test_composite_action_with_resource_type_returns_400(evaluate_client):
    resp = _post(
        evaluate_client,
        {"action": "read:ahu", "resource_type": "ahu", "resource_id": "ahu-1"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "validation_failed"


def test_invalid_resource_type_returns_400(evaluate_client):
    resp = _post(evaluate_client, {"action": "read", "resource_type": "AHU!"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "validation_failed"


# ---------------------------------------------------------------------------
# Reserved-namespace context collisions
# ---------------------------------------------------------------------------


def test_reserved_context_key_rejected_on_bare_request(evaluate_client):
    resp = _post(
        evaluate_client,
        {
            "action": "read",
            "resource_type": "ahu",
            "context": {EVIDENCE_ORIGINAL_ACTION: "spoofed"},
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "validation_failed"


def test_reserved_context_key_rejected_on_composite_request(evaluate_client):
    """A caller cannot forge composition evidence even on a pass-through request."""
    resp = _post(
        evaluate_client,
        {"action": "read:ahu", "context": {EVIDENCE_ACTION_COMPOSED: "true"}},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "validation_failed"


def test_ordinary_context_is_preserved(recording):
    client, rec = recording
    _post(
        client,
        {"action": "read", "resource_type": "ahu", "context": {"site": "bldg-a"}},
    )
    assert rec.last["context"]["site"] == "bldg-a"


# ---------------------------------------------------------------------------
# Composition evidence
# ---------------------------------------------------------------------------


def test_composed_request_records_all_evidence(recording):
    client, rec = recording
    _post(client, {"action": "read", "resource_type": "ahu", "resource_id": "ahu-1"})
    ctx = rec.last["context"]
    assert ctx[EVIDENCE_ACTION_COMPOSED] == "true"
    assert ctx[EVIDENCE_ORIGINAL_ACTION] == "read"
    assert ctx[EVIDENCE_RESOURCE_TYPE] == "ahu"
    assert ctx[EVIDENCE_COMPOSED_ACTION] == "read:ahu"


def test_evidence_coexists_with_caller_context(recording):
    client, rec = recording
    _post(
        client,
        {
            "action": "read",
            "resource_type": "ahu",
            "context": {"site": "bldg-a"},
        },
    )
    ctx = rec.last["context"]
    assert ctx["site"] == "bldg-a"
    assert ctx[EVIDENCE_COMPOSED_ACTION] == "read:ahu"


# ---------------------------------------------------------------------------
# Regression — unchanged behaviour
# ---------------------------------------------------------------------------


def test_deny_still_returns_403(evaluate_client, mock_verifier):
    mock_verifier._claims["realm_access"] = {"roles": ["viewer"]}
    resp = _post(evaluate_client, {"action": actions.WRITE_HVAC_SETPOINT})
    assert resp.status_code == 403
    assert resp.json()["outcome"] == "deny"


def test_composed_request_has_correlation_header(recording):
    client, _ = recording
    resp = _post(client, {"action": "read", "resource_type": "ahu"})
    assert "x-correlation-id" in resp.headers


def test_missing_auth_still_401_even_with_valid_composition(evaluate_client):
    # Composition succeeds, but absent Authorization header still fails closed.
    resp = evaluate_client.post("/v1/evaluate", json={"action": "read", "resource_type": "ahu"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Audit path — the COMPOSED action reaches the emitted decision audit event
# ---------------------------------------------------------------------------
#
# The kernel records the action it actually evaluated. For an adapter-normalized
# request the gateway composes the action before invoking basis-core, so the
# emitted AuthorizationDecision AuditEvent.action must be the composed string
# ("read:ahu"), never the bare verb ("read"). This is the audit guarantee for the
# affected path. (The basis_gateway.* evidence keys travel in DecisionRequest.context
# only; basis-core's AuditEvent has no context field, so those keys are not part of
# the audit payload — see the task analysis.)


def test_composed_action_is_recorded_in_decision_audit_event(evaluate_client):
    events: list = []

    class _CapturingWriter:
        def write(self, event) -> None:
            events.append(event)

    engine = PolicyEngine(
        policies=[RolePolicyRule(role_table={"read:ahu": {"admin", "viewer"}}, rule_name="rbac")]
    )
    ep = EnforcementPoint(engine=engine, audit_writer=_CapturingWriter(), policy_version="test")
    evaluate_client.app.state.evaluator = GatewayEvaluator(_enforcement_point=ep)

    resp = _post(evaluate_client, {"action": "read", "resource_type": "ahu"})
    assert resp.status_code == 200

    decision_events = [getattr(e, "action", None) for e in events]
    assert "read:ahu" in decision_events  # composed action is what was audited
    assert "read" not in decision_events  # the bare verb is never audited
