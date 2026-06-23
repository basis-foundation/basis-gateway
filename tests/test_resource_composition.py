"""Integration tests for the gateway resource-identifier-composition boundary
on /v1/evaluate.

Covers the two supported request styles (typed pass-through and local-id
composition), ambiguity/missing-field rejection, reserved-namespace collisions,
composition evidence, and the resource-independent (no resource_id) path.
"""

from __future__ import annotations

from typing import Any

import pytest
from basis_core.audit import NullAuditWriter
from basis_core.decisions import DecisionOutcome, DecisionResponse
from basis_core.enforcement import EnforcementPoint
from basis_core.policy import PolicyEngine, RolePolicyRule

from basis_gateway.core.evaluator import GatewayEvaluator
from basis_gateway.core.resources import (
    EVIDENCE_COMPOSED_RESOURCE_ID,
    EVIDENCE_ORIGINAL_RESOURCE_ID,
    EVIDENCE_RESOURCE_COMPOSED,
)

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
# Style 1 — typed resource_id passes through unchanged
# ---------------------------------------------------------------------------


def test_typed_resource_id_passes_through(recording):
    client, rec = recording
    resp = _post(client, {"action": "read:ahu", "resource_id": "ahu:rooftop-1"})
    assert resp.status_code == 200
    assert rec.last["resource_id"] == "ahu:rooftop-1"


def test_typed_resource_id_adds_no_resource_evidence(recording):
    client, rec = recording
    _post(client, {"action": "read:ahu", "resource_id": "ahu:rooftop-1"})
    ctx = rec.last["context"]
    for key in (
        EVIDENCE_RESOURCE_COMPOSED,
        EVIDENCE_ORIGINAL_RESOURCE_ID,
        EVIDENCE_COMPOSED_RESOURCE_ID,
    ):
        assert key not in ctx


# ---------------------------------------------------------------------------
# Style 2 — local resource_id + resource_type composes
# ---------------------------------------------------------------------------


def test_local_resource_id_composes(recording):
    client, rec = recording
    resp = _post(client, {"action": "read", "resource_type": "ahu", "resource_id": "rooftop-1"})
    assert resp.status_code == 200
    assert rec.last["action"] == "read:ahu"
    assert rec.last["resource_id"] == "ahu:rooftop-1"


def test_local_resource_id_composes_and_evaluates_end_to_end(evaluate_client):
    """Composed resource_id is what the kernel evaluates against real policy."""
    engine = PolicyEngine(
        policies=[RolePolicyRule(role_table={"read:ahu": {"admin", "viewer"}}, rule_name="rbac")]
    )
    ep = EnforcementPoint(engine=engine, audit_writer=NullAuditWriter(), policy_version="test")
    evaluate_client.app.state.evaluator = GatewayEvaluator(_enforcement_point=ep)

    resp = _post(
        evaluate_client,
        {"action": "read", "resource_type": "ahu", "resource_id": "rooftop-1"},
    )
    assert resp.status_code == 200
    assert resp.json()["outcome"] == "allow"


# ---------------------------------------------------------------------------
# Resource-independent — resource_type without resource_id stays valid
# ---------------------------------------------------------------------------


def test_resource_type_without_resource_id_is_valid(recording):
    """A resource_type with no resource_id is a domain-level request: it composes
    the action but no resource_id, and is NOT rejected."""
    client, rec = recording
    resp = _post(client, {"action": "read", "resource_type": "ahu"})
    assert resp.status_code == 200
    assert rec.last["action"] == "read:ahu"
    assert rec.last["resource_id"] is None
    assert EVIDENCE_RESOURCE_COMPOSED not in rec.last["context"]


def test_fully_resource_independent_request_is_valid(recording):
    client, rec = recording
    resp = _post(client, {"action": "read:audit:log"})
    assert resp.status_code == 200
    assert rec.last["action"] == "read:audit:log"
    assert rec.last["resource_id"] is None


# ---------------------------------------------------------------------------
# Rejection (400 validation_failed)
# ---------------------------------------------------------------------------


def test_typed_resource_id_with_resource_type_returns_400(evaluate_client):
    """Already-typed resource_id plus resource_type — dual sources of truth."""
    resp = _post(
        evaluate_client,
        {"action": "read", "resource_type": "ahu", "resource_id": "ahu:rooftop-1"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "validation_failed"


def test_conflicting_resource_type_and_prefix_returns_400(evaluate_client):
    """resource_type conflicts with an existing typed resource_id prefix."""
    resp = _post(
        evaluate_client,
        {"action": "read", "resource_type": "sensor", "resource_id": "ahu:rooftop-1"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "validation_failed"


def test_local_resource_id_without_resource_type_returns_400(evaluate_client):
    """A composite action with a local resource_id but no resource_type cannot
    be composed into a canonical identifier."""
    resp = _post(evaluate_client, {"action": "read:ahu", "resource_id": "rooftop-1"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "validation_failed"


# ---------------------------------------------------------------------------
# Reserved-namespace context collisions
# ---------------------------------------------------------------------------


def test_reserved_resource_context_key_rejected(evaluate_client):
    resp = _post(
        evaluate_client,
        {
            "action": "read",
            "resource_type": "ahu",
            "resource_id": "rooftop-1",
            "context": {EVIDENCE_COMPOSED_RESOURCE_ID: "spoofed:1"},
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "validation_failed"


def test_caller_cannot_forge_resource_composed_flag(evaluate_client):
    """A caller cannot pre-set resource_composed even on a pass-through request."""
    resp = _post(
        evaluate_client,
        {"action": "read:ahu", "context": {EVIDENCE_RESOURCE_COMPOSED: "true"}},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "validation_failed"


# ---------------------------------------------------------------------------
# Composition evidence
# ---------------------------------------------------------------------------


def test_composed_resource_records_all_evidence(recording):
    client, rec = recording
    _post(client, {"action": "read", "resource_type": "ahu", "resource_id": "rooftop-1"})
    ctx = rec.last["context"]
    assert ctx[EVIDENCE_RESOURCE_COMPOSED] == "true"
    assert ctx[EVIDENCE_ORIGINAL_RESOURCE_ID] == "rooftop-1"
    assert ctx[EVIDENCE_COMPOSED_RESOURCE_ID] == "ahu:rooftop-1"


def test_resource_evidence_coexists_with_caller_context(recording):
    client, rec = recording
    _post(
        client,
        {
            "action": "read",
            "resource_type": "ahu",
            "resource_id": "rooftop-1",
            "context": {"site": "bldg-a"},
        },
    )
    ctx = rec.last["context"]
    assert ctx["site"] == "bldg-a"
    assert ctx[EVIDENCE_COMPOSED_RESOURCE_ID] == "ahu:rooftop-1"


# ---------------------------------------------------------------------------
# Audit — the COMPOSED resource_id reaches the emitted decision audit event
# ---------------------------------------------------------------------------


def test_composed_resource_id_is_recorded_in_decision_audit_event(evaluate_client):
    events: list = []

    class _CapturingWriter:
        def write(self, event) -> None:
            events.append(event)

    engine = PolicyEngine(
        policies=[RolePolicyRule(role_table={"read:ahu": {"admin", "viewer"}}, rule_name="rbac")]
    )
    ep = EnforcementPoint(engine=engine, audit_writer=_CapturingWriter(), policy_version="test")
    evaluate_client.app.state.evaluator = GatewayEvaluator(_enforcement_point=ep)

    resp = _post(
        evaluate_client,
        {"action": "read", "resource_type": "ahu", "resource_id": "rooftop-1"},
    )
    assert resp.status_code == 200

    resource_ids = [getattr(e, "resource_id", None) for e in events]
    assert "ahu:rooftop-1" in resource_ids  # composed id is what was audited
    assert "rooftop-1" not in resource_ids  # the local id is never audited
