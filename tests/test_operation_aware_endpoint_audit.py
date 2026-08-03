"""Gateway audit-record tests for POST /v1/evaluate/operation-aware (PR 7).

Covers:
  - Shared ``GatewayAuditWriter`` lifecycle (operation-aware-only,
    v0.1-only, both, neither).
  - The five canonical scenarios run through the real, authenticated HTTP
    endpoint with a capturing writer, asserting the full durable-record
    cross-agreement matrix required by the PR 7 work item.
  - Pre-kernel rejection paths write no kernel evidence.
  - The missing-``AuditEvidence`` regression case.
  - ``AUDIT_FAIL_CLOSED`` extended to the operation-aware endpoint, reusing
    the exact existing strict-mode semantics.
  - A write failure never alters the already-computed response.

Real, public ``basis-core`` types and the real FastAPI route are used
throughout — never a mocked kernel result for the canonical scenarios.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from basis_core.enforcement import OperationAwareEnforcementResult
from basis_core.policy import PolicyBundle
from fastapi.testclient import TestClient
from helpers import MockVerifier

from basis_gateway.audit.operation_aware_gateway_events import (
    AUTHORIZATION_COMPLETED,
    EVIDENCE_MISSING,
)
from basis_gateway.audit.writer import GatewayAuditWriter
from basis_gateway.core.operation_aware_evaluator import (
    OperationAwareGatewayEvaluator,
    build_operation_aware_evaluator,
)
from basis_gateway.main import create_app
from basis_gateway.readiness import get_readiness_state, reset_readiness_state

_NONEXISTENT_BUNDLE_PATH = "/tmp/basis-gateway-test-oa-audit-bundle-does-not-exist.json"


class _CapturingWriter:
    """AuditWriter that appends every event to a list — mirrors
    ``tests/helpers.py``'s ``CapturingWriter`` (kept local so this module
    stays self-contained)."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    def write(self, event: Any) -> None:
        self.events.append(event)


def _post_oa(client: TestClient, headers: dict[str, str] | None = None, **body: Any):
    return client.post(
        "/v1/evaluate/operation-aware",
        json=body,
        headers=headers if headers is not None else {"Authorization": "Bearer fake"},
    )


def _client_with_evaluator(
    monkeypatch: pytest.MonkeyPatch,
    mock_verifier: MockVerifier,
    evaluator: OperationAwareGatewayEvaluator,
    *,
    audit_writer: Any = None,
) -> TestClient:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    reset_readiness_state()
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    client.__enter__()
    app.state.verifier = mock_verifier
    app.state.operation_aware_evaluator = evaluator
    if audit_writer is not None:
        app.state.audit_writer = audit_writer
    return client


def _completed_events(writer: _CapturingWriter) -> list[Any]:
    return [e for e in writer.events if e.action == AUTHORIZATION_COMPLETED]


# ---------------------------------------------------------------------------
# Writer lifecycle
# ---------------------------------------------------------------------------


def test_operation_aware_only_config_initializes_audit_writer(monkeypatch, tmp_path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(
        json.dumps(
            {
                "bundle_id": "b1",
                "bundle_version": "1.0.0",
                "schema_version": "1.0.0",
                "policy_owner": "test-owner",
                "rules": [{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(bundle_path))
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert isinstance(app.state.audit_writer, GatewayAuditWriter)
        assert get_readiness_state().components.get("audit_writer") is True


def test_v01_only_config_unaffected(tmp_path, monkeypatch) -> None:
    p = tmp_path / "policy.json"
    p.write_text(
        json.dumps(
            {"rules": [{"rule_name": "r", "role_table": {"read:sensor:telemetry": ["viewer"]}}]}
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("POLICY_PATH", str(p))
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert isinstance(app.state.audit_writer, GatewayAuditWriter)
        assert app.state.evaluator is not None
        assert app.state.operation_aware_evaluator is None


def test_neither_enabled_no_writer() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert app.state.audit_writer is None
        assert "audit_writer" not in get_readiness_state().components


def test_disabled_operation_aware_adds_no_new_readiness_component() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert "operation_aware_evaluator" not in get_readiness_state().components
        assert app.state.audit_writer is None


def test_both_enabled_share_exactly_one_writer_instance(monkeypatch, tmp_path) -> None:
    import json as _json

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        rsa_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    v01_policy_path = tmp_path / "v01-policy.json"
    v01_policy_path.write_text(
        _json.dumps(
            {"rules": [{"rule_name": "r", "role_table": {"read:sensor:telemetry": ["viewer"]}}]}
        ),
        encoding="utf-8",
    )
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(
        _json.dumps(
            {
                "bundle_id": "b1",
                "bundle_version": "1.0.0",
                "schema_version": "1.0.0",
                "policy_owner": "test-owner",
                "rules": [{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.setenv("AUTH_MODE", "basis_local_token")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_ISSUER", "https://identity.basis.example.com")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_AUDIENCE", "basis-gateway")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON", _json.dumps({"key-1": public_pem}))
    monkeypatch.setenv("POLICY_PATH", str(v01_policy_path))
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(bundle_path))

    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert app.state.audit_writer is not None
        assert app.state.evaluator is not None
        assert app.state.operation_aware_evaluator is not None
        # Exactly one writer instance is shared by both evaluators.
        assert app.state.evaluator._enforcement_point._audit_writer is app.state.audit_writer  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Canonical scenarios through the real endpoint, with a capturing writer
# ---------------------------------------------------------------------------


def test_canonical_allow_basic(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = _CapturingWriter()
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
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = _post_oa(client, action="read:ahu")
    assert resp.status_code == 200
    body = resp.json()

    completed = _completed_events(writer)
    assert len(completed) == 1
    event = completed[0]
    gw_event = event.detail["gateway_audit_event"]
    evidence = event.detail["audit_evidence"]

    assert gw_event["audit_evidence_id"] == evidence["evidence_id"]
    assert body["request_id"] == gw_event["request_id"] == evidence["request_id"]
    assert (
        body["evaluation_status"]
        == gw_event["evaluation_status"]
        == evidence["evaluation_status"]
        == "completed"
    )
    assert body["outcome"] == gw_event["outcome"] == evidence["outcome"] == "allow"
    assert gw_event["failure_reason"] is None
    assert evidence["failure_reason"] is None
    assert gw_event["enforcement_action"] == "allow" == body["disposition"]
    assert event.detail["http_status"] == 200


def test_canonical_deny_precedence(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = _CapturingWriter()
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
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = _post_oa(client, action="write:ahu")
    assert resp.status_code == 403
    body = resp.json()

    completed = _completed_events(writer)
    assert len(completed) == 1
    gw_event = completed[0].detail["gateway_audit_event"]
    evidence = completed[0].detail["audit_evidence"]

    assert body["outcome"] == gw_event["outcome"] == evidence["outcome"] == "deny"
    assert gw_event["enforcement_action"] == "deny" == body["disposition"]
    assert "deny-write-ahu" in evidence["matched_rule_ids"]


def test_canonical_default_deny(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = _CapturingWriter()
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
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = _post_oa(client, action="write:ahu")
    assert resp.status_code == 403
    body = resp.json()

    completed = _completed_events(writer)
    assert len(completed) == 1
    gw_event = completed[0].detail["gateway_audit_event"]
    assert body["outcome"] == gw_event["outcome"] == "deny"
    assert gw_event["enforcement_action"] == "deny"


def test_canonical_not_applicable(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = _CapturingWriter()
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
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = _post_oa(client, action="read:ahu")
    assert resp.status_code == 403
    body = resp.json()

    completed = _completed_events(writer)
    assert len(completed) == 1
    gw_event = completed[0].detail["gateway_audit_event"]
    evidence = completed[0].detail["audit_evidence"]

    # The central invariant: NOT_APPLICABLE is preserved verbatim in both the
    # response and the durable record, even though enforcement is "deny".
    assert body["outcome"] == gw_event["outcome"] == evidence["outcome"] == "not_applicable"
    assert gw_event["outcome"] != "deny"
    assert gw_event["enforcement_action"] == "deny"


def test_canonical_invalid_policy_bundle(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    from basis_core.enforcement import OperationAwareEnforcementPoint

    writer = _CapturingWriter()
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
        _clock=lambda: __import__("datetime").datetime(
            2026, 8, 1, 12, tzinfo=__import__("datetime").timezone.utc
        ),
    )
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = _post_oa(client, action="read:ahu")
    assert resp.status_code == 503
    body = resp.json()

    completed = _completed_events(writer)
    assert len(completed) == 1
    gw_event = completed[0].detail["gateway_audit_event"]
    evidence = completed[0].detail["audit_evidence"]

    assert (
        body["evaluation_status"]
        == gw_event["evaluation_status"]
        == evidence["evaluation_status"]
        == "failed"
    )
    assert body.get("outcome") is None
    assert gw_event["outcome"] is None
    assert evidence["outcome"] is None
    assert (
        body["failure_reason"]
        == gw_event["failure_reason"]
        == evidence["failure_reason"]
        == "policy_validation_failure"
    )
    assert gw_event["enforcement_action"] == "deny" == body["disposition"]
    assert completed[0].detail["http_status"] == 503


def test_canonical_scenarios_write_exactly_one_completed_record(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = _CapturingWriter()
    bundle = PolicyBundle(
        bundle_id="single-record-bundle",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
    )
    evaluator = build_operation_aware_evaluator(bundle)
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    _post_oa(client, action="read:ahu")
    assert len(writer.events) == 1
    assert writer.events[0].action == AUTHORIZATION_COMPLETED


# ---------------------------------------------------------------------------
# Pre-kernel rejections write no kernel evidence
# ---------------------------------------------------------------------------


def test_validation_failure_writes_no_kernel_evidence(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = _CapturingWriter()
    bundle = PolicyBundle(
        bundle_id="b1",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
    )
    evaluator = build_operation_aware_evaluator(bundle)
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = client.post(
        "/v1/evaluate/operation-aware",
        content=b"{not valid json",
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 400
    assert len(writer.events) == 1
    event = writer.events[0]
    assert "gateway_audit_event" not in event.detail
    assert "audit_evidence" not in event.detail
    assert event.action != AUTHORIZATION_COMPLETED


def test_authentication_failure_writes_no_kernel_evidence(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = _CapturingWriter()
    bundle = PolicyBundle(
        bundle_id="b1",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
    )
    evaluator = build_operation_aware_evaluator(bundle)
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = _post_oa(client, headers={}, action="read:ahu")
    assert resp.status_code == 401
    assert len(writer.events) == 1
    event = writer.events[0]
    assert "gateway_audit_event" not in event.detail
    assert "audit_evidence" not in event.detail


def test_producer_context_rejection_writes_no_kernel_evidence(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = _CapturingWriter()
    bundle = PolicyBundle(
        bundle_id="b1",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
    )
    evaluator = build_operation_aware_evaluator(bundle)
    client = _client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = _post_oa(client, action="read:ahu", operation_intent="read_only")
    assert resp.status_code == 400
    assert len(writer.events) == 1
    event = writer.events[0]
    assert "gateway_audit_event" not in event.detail
    assert "audit_evidence" not in event.detail
    assert event.reason == "producer_context_rejected"


def test_evaluator_unavailable_writes_no_kernel_evidence(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = _CapturingWriter()
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        app.state.verifier = mock_verifier
        app.state.audit_writer = writer
        assert app.state.operation_aware_evaluator is None

        resp = _post_oa(client, action="read:ahu")
        assert resp.status_code == 503
        assert len(writer.events) == 1
        event = writer.events[0]
        assert "gateway_audit_event" not in event.detail
        assert "audit_evidence" not in event.detail


# ---------------------------------------------------------------------------
# Missing kernel AuditEvidence regression
# ---------------------------------------------------------------------------


class _MissingEvidenceEvaluator:
    """Duck-typed stand-in for OperationAwareGatewayEvaluator whose
    ``.evaluate()`` returns a real, previously-obtained response/disposition
    pair but with ``audit_evidence=None`` — simulating the enforcement
    point's own internal-error fallback without importing any internal
    ``basis_core.evaluation.*`` symbol."""

    def __init__(self, result: OperationAwareEnforcementResult) -> None:
        self._result = result

    def evaluate(self, composed: object) -> OperationAwareEnforcementResult:
        return self._result


def test_missing_audit_evidence_writes_no_completed_gateway_audit_event(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = _CapturingWriter()
    bundle = PolicyBundle(
        bundle_id="b1",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
    )
    real_evaluator = build_operation_aware_evaluator(bundle)
    from basis_gateway.api.operation_aware_schemas import OperationAwareEvaluateRequest
    from basis_gateway.auth.operation_producer import classify_operation_producer
    from basis_gateway.auth.subject_mapper import IdentityContext, NormalizedSubject
    from basis_gateway.core.operation_aware_composition import compose_operation_aware_input

    subject = NormalizedSubject(subject_id="user1", name="user1", roles=(), attributes={})
    identity_ctx = IdentityContext(
        issuer="https://issuer.example", subject_id="user1", claims={"sub": "user1"}
    )
    producer_trust = classify_operation_producer(subject, frozenset())
    composed = compose_operation_aware_input(
        OperationAwareEvaluateRequest(action="read:ahu"),
        subject=subject,
        identity_context=identity_ctx,
        producer_trust=producer_trust,
        correlation_id="corr-fixed",
    )
    real_result = real_evaluator.evaluate(composed)
    missing_evidence_result = OperationAwareEnforcementResult(
        response=real_result.response,
        audit_evidence=None,
        disposition=real_result.disposition,
    )
    stub_evaluator = _MissingEvidenceEvaluator(missing_evidence_result)
    client = _client_with_evaluator(monkeypatch, mock_verifier, stub_evaluator, audit_writer=writer)  # type: ignore[arg-type]

    resp = _post_oa(client, action="read:ahu")
    # HTTP classification still follows the real (allow) response.
    assert resp.status_code == 200

    assert len(writer.events) == 1
    event = writer.events[0]
    assert event.action == EVIDENCE_MISSING
    assert "gateway_audit_event" not in event.detail
    assert "audit_evidence" not in event.detail
    assert _completed_events(writer) == []


# ---------------------------------------------------------------------------
# AUDIT_FAIL_CLOSED extension
# ---------------------------------------------------------------------------


class _AlwaysFailingWriter:
    def write(self, event: object) -> None:
        raise OSError("audit sink down")


class _AlwaysSucceedingWriter:
    def write(self, event: object) -> None:
        pass


def _degrade(writer: GatewayAuditWriter) -> None:
    writer._inner = _AlwaysFailingWriter()
    for _ in range(writer.failure_threshold):
        writer.write(object())
    assert writer.degraded


def _fresh_bundle_client(monkeypatch, mock_verifier, *, fail_closed: bool) -> TestClient:
    bundle_path = Path("/tmp/basis-gateway-fail-closed-oa-bundle-nonexistent.json")
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(bundle_path))
    monkeypatch.setenv("AUDIT_FAIL_CLOSED", "true" if fail_closed else "false")
    reset_readiness_state()
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    client.__enter__()
    app.state.verifier = mock_verifier
    bundle = PolicyBundle(
        bundle_id="fail-closed-bundle",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
    )
    app.state.operation_aware_evaluator = build_operation_aware_evaluator(bundle)
    return client


def test_audit_fail_closed_false_degraded_writer_does_not_block(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    client = _fresh_bundle_client(monkeypatch, mock_verifier, fail_closed=False)
    writer: GatewayAuditWriter = client.app.state.audit_writer
    _degrade(writer)

    resp = _post_oa(client, action="read:ahu")
    assert resp.status_code != 503 or "audit" not in resp.json().get("message", "").lower()


def test_audit_fail_closed_true_degraded_writer_returns_503(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    client = _fresh_bundle_client(monkeypatch, mock_verifier, fail_closed=True)
    writer: GatewayAuditWriter = client.app.state.audit_writer
    _degrade(writer)

    resp = _post_oa(client, action="read:ahu")
    assert resp.status_code == 503
    assert "audit" in resp.json().get("message", "").lower()


def test_audit_fail_closed_true_recovers_via_probe(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    client = _fresh_bundle_client(monkeypatch, mock_verifier, fail_closed=True)
    writer: GatewayAuditWriter = client.app.state.audit_writer
    _degrade(writer)
    assert _post_oa(client, action="read:ahu").status_code == 503

    writer._inner = _AlwaysSucceedingWriter()
    assert writer.degraded  # no write yet — still degraded

    resp = _post_oa(client, action="read:ahu")
    assert resp.status_code == 200
    assert not writer.degraded


def test_audit_fail_closed_probe_event_recorded_with_oa_action(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    from basis_gateway.audit.operation_aware_gateway_events import OA_AUDIT_RECOVERY_PROBE

    client = _fresh_bundle_client(monkeypatch, mock_verifier, fail_closed=True)
    writer: GatewayAuditWriter = client.app.state.audit_writer
    _degrade(writer)

    capturing_inner = _CapturingWriter()
    writer._inner = capturing_inner

    resp = _post_oa(client, action="read:ahu")
    assert resp.status_code == 200
    assert not writer.degraded

    probe_events = [e for e in capturing_inner.events if e.action == OA_AUDIT_RECOVERY_PROBE]
    assert len(probe_events) == 1


def test_audit_fail_closed_probe_uses_operation_aware_specific_action() -> None:
    """The recovery probe's own recorded action is distinguishable from
    /v1/evaluate's ``AUDIT_RECOVERY_PROBE`` — the shared fail-closed control
    flow is reused, but each endpoint's own audit trail stays distinguishable
    (see ``test_emit_system_event_includes_http_status`` and friends in
    ``test_operation_aware_audit_events.py`` for the emission-level proof
    that the probe event is actually written with this action name)."""
    from basis_gateway.audit.gateway_events import AUDIT_RECOVERY_PROBE
    from basis_gateway.audit.operation_aware_gateway_events import OA_AUDIT_RECOVERY_PROBE

    assert OA_AUDIT_RECOVERY_PROBE != AUDIT_RECOVERY_PROBE


# ---------------------------------------------------------------------------
# Write failure does not alter the already-computed response
# ---------------------------------------------------------------------------


def test_writer_failure_after_evaluation_does_not_change_response(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    bundle = PolicyBundle(
        bundle_id="b1",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
    )
    evaluator = build_operation_aware_evaluator(bundle)

    working_writer = _CapturingWriter()
    working_client = _client_with_evaluator(
        monkeypatch, mock_verifier, evaluator, audit_writer=working_writer
    )
    good_resp = _post_oa(working_client, action="read:ahu")

    failing_writer = _AlwaysFailingWriter()
    failing_client = _client_with_evaluator(
        monkeypatch,
        mock_verifier,
        build_operation_aware_evaluator(bundle),
        audit_writer=failing_writer,
    )
    # Must not raise despite the writer always failing.
    bad_resp = _post_oa(failing_client, action="read:ahu")

    assert good_resp.status_code == bad_resp.status_code == 200
    assert good_resp.json()["outcome"] == bad_resp.json()["outcome"] == "allow"
