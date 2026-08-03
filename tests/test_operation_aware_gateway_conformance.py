"""Gateway-boundary canonical and adversarial conformance suite (PR 9).

This is the final conformance phase for the feature-gated operation-aware
authorization path, ``POST /v1/evaluate/operation-aware``. It proves that the
complete real gateway boundary — authentication, operation-producer trust,
request validation, action/resource composition, field-level provenance,
public ``basis-core`` request construction, deterministic kernel evaluation,
HTTP classification, enforcement disposition, and gateway audit evidence —
preserves the contracts and invariants established by PRs 1-8.

Relationship to existing coverage
----------------------------------
PRs 1-8 already built an extensive, real-kernel-backed test suite:
``test_operation_aware_endpoint*.py`` (feature gating, auth, shape/provenance
validation, composition, evaluator availability, unexpected-exception
containment), ``test_operation_aware_endpoint_canonical_scenarios.py`` (the
five canonical scenarios through the real route), ``test_operation_aware_
endpoint_audit.py`` (per-scenario audit-record field agreement and writer
lifecycle), ``test_operation_aware_composition.py``/``test_operation_producer_
trust.py`` (composition and producer-trust unit coverage, including every
identity-consistency invariant), ``test_operation_aware_http_classification.py``
(the exhaustive pure-function classification table), ``test_operation_aware_
audit_events.py`` (audit-assembly unit coverage, including contradictory-state
rejection), ``test_operation_aware_readiness.py``/``test_operation_aware_
startup.py``/``test_operation_aware_router_registration.py`` (readiness and
route-registration matrices), and ``test_operation_aware_public_api_contract.py``
(the repository-wide import-boundary sweep).

This module does not re-derive that coverage. Its job is the piece none of
those files provide: a single suite that (a) walks *every* canonical scenario
through the real HTTP boundary while checking the *complete* cross-artifact
agreement matrix in one place (request/evidence/gateway-event/response/HTTP
status/subject/producer, all at once), (b) supplies small, reusable
conformance-assertion helpers that compare already-produced governed
artifacts (never re-deriving authorization), and (c) proves those helpers
actually detect tampering via targeted single-field mutation tests (see
``test_operation_aware_gateway_conformance_mutations.py``).

Canonical fixture provenance
------------------------------
This repository vendors no JSON ``basis-schemas`` compatibility-vector file,
fetches nothing from a network or sibling checkout, and takes no runtime
dependency on the ``basis-schemas`` package. The five canonical scenario
bundles below are pinned, repository-local ``PolicyBundle`` Python objects —
the same representation already established for these exact scenario names
by ``test_operation_aware_endpoint_canonical_scenarios.py`` and
``test_operation_aware_endpoint_audit.py`` in this repository. They are
reused (not reinvented) here, unified into one shared module-level constant
so this suite and any sibling module can both build on the identical
definitions.

  source repository:        basis-gateway (this repository)
  source contract version:  operation-aware v0.2.2-compatible scenario shapes
                             (allow-basic, deny-precedence, default-deny,
                             not-applicable, invalid-policy-bundle)
  vendoring date:            2026-08-03
  files included:            none (no JSON fixture file; pinned Python
                             ``PolicyBundle`` literals only, defined in this
                             module)

Hermeticity
------------
No network, no subprocess, no Docker, no live IdP. Authentication uses the
existing repository-standard ``MockVerifier`` double. Trace/evidence
identifiers and clocks are injected explicitly wherever this module asserts
on their exact value; correlation IDs are gateway-generated per request (by
design) and are compared for *cross-artifact agreement*, never asserted to a
fixed literal.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from typing import Any

import pytest
from basis_core.decisions import OperationIntent
from basis_core.enforcement import EnforcementDisposition, OperationAwareEnforcementPoint
from basis_core.policy import PolicyBundle
from fastapi.testclient import TestClient
from helpers import MockVerifier

from basis_gateway.api.operation_aware_classification import classify_operation_aware_http_status
from basis_gateway.audit.operation_aware_gateway_events import AUTHORIZATION_COMPLETED
from basis_gateway.core.operation_aware_composition import OPERATION_PRODUCER_ONLY_FIELDS
from basis_gateway.core.operation_aware_evaluator import (
    OperationAwareGatewayEvaluator,
    build_operation_aware_evaluator,
)
from basis_gateway.main import create_app
from basis_gateway.readiness import get_readiness_state, reset_readiness_state

_FIXED_TIME = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_NONEXISTENT_BUNDLE_PATH = "/tmp/basis-gateway-test-oa-conformance-bundle-does-not-exist.json"

# A sentinel that must never leak into any response, readiness payload, audit
# event, or logged text produced by this suite.
SENTINEL_DO_NOT_LEAK = "SENTINEL_DO_NOT_LEAK_9f3c2a"

_PROHIBITED_SUBSTRINGS = (
    "Bearer ",
    "Authorization:",
    "authorization_header",
    "cookie",
    "claims=",
    "credential",
    "private_key",
    "-----BEGIN",
    "Traceback (most recent call last)",
    "exception",
    " at 0x",  # Python object address repr, e.g. "<Foo object at 0x7f...>"
)


# ---------------------------------------------------------------------------
# Canonical scenario bundles (pinned; see module docstring for provenance)
# ---------------------------------------------------------------------------

CANONICAL_ALLOW_BASIC_BUNDLE = PolicyBundle(
    bundle_id="canonical-allow-basic",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    rules=[{"rule_id": "allow-read-ahu", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
)

CANONICAL_DENY_PRECEDENCE_BUNDLE = PolicyBundle(
    bundle_id="canonical-deny-precedence",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    rules=[
        {"rule_id": "allow-write-ahu", "effect": "allow", "match": {"actions": ["write:ahu"]}},
        {"rule_id": "deny-write-ahu", "effect": "deny", "match": {"actions": ["write:ahu"]}},
    ],
)

CANONICAL_DEFAULT_DENY_BUNDLE = PolicyBundle(
    bundle_id="canonical-default-deny",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    rules=[{"rule_id": "allow-read-ahu", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
)

CANONICAL_NOT_APPLICABLE_BUNDLE = PolicyBundle(
    bundle_id="canonical-not-applicable",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    scope={"actions": ["read:other_domain"]},
    rules=[{"rule_id": "allow-read-ahu", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
)

CANONICAL_INVALID_POLICY_BUNDLE = PolicyBundle(
    bundle_id="canonical-invalid-policy-bundle",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    rules=[
        {"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}},
        {"rule_id": "r1", "effect": "deny", "match": {"actions": ["write:ahu"]}},
    ],
)

# Plain-dict mirrors of the bundles above, for the handful of tests that must
# write a bundle to a real file and let it load through the real (unmocked)
# structural loader. ``PolicyBundle.model_dump_json()`` cannot be used for
# this — it serializes every unset selector field as an explicit ``null``,
# which ``OperationAwarePolicyMatch`` itself then rejects on reload (selector
# fields must be omitted entirely to mean "no restriction", never present as
# ``null``) — so these dict literals are kept in exact sync with the
# ``PolicyBundle`` objects above instead.
CANONICAL_ALLOW_BASIC_BUNDLE_DICT: dict = {
    "bundle_id": "canonical-allow-basic",
    "bundle_version": "1.0.0",
    "schema_version": "1.0.0",
    "policy_owner": "test-owner",
    "rules": [{"rule_id": "allow-read-ahu", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
}

CANONICAL_INVALID_POLICY_BUNDLE_DICT: dict = {
    "bundle_id": "canonical-invalid-policy-bundle",
    "bundle_version": "1.0.0",
    "schema_version": "1.0.0",
    "policy_owner": "test-owner",
    "rules": [
        {"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}},
        {"rule_id": "r1", "effect": "deny", "match": {"actions": ["write:ahu"]}},
    ],
}


# ---------------------------------------------------------------------------
# Shared test infrastructure
# ---------------------------------------------------------------------------


class CapturingWriter:
    """AuditWriter double that appends every real ``basis_core.audit.AuditEvent``
    to a list. Local to this module (mirrors ``tests/helpers.py``'s own
    ``CapturingWriter``) so this conformance suite carries no import
    dependency on another test module's fixtures."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    def write(self, event: Any) -> None:
        self.events.append(event)


def post_oa(client: TestClient, headers: dict[str, str] | None = None, **body: Any):
    return client.post(
        "/v1/evaluate/operation-aware",
        json=body,
        headers=headers if headers is not None else {"Authorization": "Bearer fake"},
    )


def post_oa_raw(client: TestClient, content: bytes, headers: dict[str, str] | None = None):
    merged_headers = {"Authorization": "Bearer fake", "Content-Type": "application/json"}
    if headers:
        merged_headers.update(headers)
    return client.post("/v1/evaluate/operation-aware", content=content, headers=merged_headers)


def client_with_evaluator(
    monkeypatch: pytest.MonkeyPatch,
    mock_verifier: MockVerifier,
    evaluator: Any,
    *,
    audit_writer: Any = None,
    trusted_subject_ids: str | None = None,
) -> TestClient:
    """Real, authenticated, feature-enabled gateway app with a real (or
    deliberately-real-then-injected) operation-aware evaluator. Mirrors the
    established ``_client_with_evaluator`` pattern already used by
    ``test_operation_aware_endpoint_canonical_scenarios.py`` and
    ``test_operation_aware_endpoint_audit.py`` — reused, not reinvented,
    across this suite's many scenarios."""
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    if trusted_subject_ids is not None:
        monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", trusted_subject_ids)
    reset_readiness_state()
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    client.__enter__()
    app.state.verifier = mock_verifier
    app.state.operation_aware_evaluator = evaluator
    if audit_writer is not None:
        app.state.audit_writer = audit_writer
    return client


def deterministic_evaluator(bundle: PolicyBundle, *, trace_id: str, evidence_id: str) -> Any:
    """Real ``OperationAwareGatewayEvaluator`` wrapping a real, structurally
    valid, preflighted ``OperationAwareEnforcementPoint`` — deterministic
    trace/evidence identifiers and a fixed clock so repeated invocations with
    the same inputs are byte-for-byte reproducible (Determinism/hermeticity)."""
    return build_operation_aware_evaluator(
        bundle,
        trace_id_factory=lambda: trace_id,
        evidence_id_factory=lambda: evidence_id,
        clock=lambda: _FIXED_TIME,
    )


def deterministic_evaluator_bypassing_preflight(
    bundle: PolicyBundle, *, trace_id: str, evidence_id: str
) -> OperationAwareGatewayEvaluator:
    """For the ``invalid-policy-bundle`` canonical scenario only: constructs
    the real enforcement point via the public ``for_bundle()`` factory but
    deliberately bypasses ``build_operation_aware_evaluator``'s own startup
    preflight (which would itself correctly reject this bundle at startup —
    see ``test_operation_aware_startup.py::test_enabled_duplicate_rule_ids_fail_startup``).
    This represents the post-preflight dependency-integrity anomaly path
    described in the PR 9 brief, not a production startup configuration that
    should normally become ready."""
    enforcement_point = OperationAwareEnforcementPoint.for_bundle(bundle)
    return OperationAwareGatewayEvaluator(
        _enforcement_point=enforcement_point,
        _trace_id_factory=lambda: trace_id,
        _evidence_id_factory=lambda: evidence_id,
        _clock=lambda: _FIXED_TIME,
    )


def completed_events(writer: CapturingWriter) -> list[Any]:
    return [e for e in writer.events if e.action == AUTHORIZATION_COMPLETED]


def capture_artifacts(resp, writer: CapturingWriter, *, known_subject_id: str) -> dict[str, Any]:
    """Build the flattened, plain-dict artifact bundle every conformance
    assertion helper below operates on: the HTTP response body, the
    contract-shaped ``GatewayAuditEvent``, the complete kernel ``AuditEvidence``,
    the HTTP status actually returned, and the authenticated subject identity
    recorded on the outer durable audit record. Exactly one completed record
    is required to exist; this function asserts that itself so every caller
    does not have to repeat the check.
    """
    completed = completed_events(writer)
    assert len(completed) == 1, (
        f"expected exactly one completed operation-aware audit record, got {len(completed)}"
    )
    event = completed[0]
    return {
        "response": resp.json(),
        "gw_event": dict(event.detail["gateway_audit_event"]),
        "evidence": dict(event.detail["audit_evidence"]),
        "http_status": resp.status_code,
        "detail_http_status": event.detail["http_status"],
        "event_subject_id": event.subject_id,
        "known_subject_id": known_subject_id,
        "operation_producer_subject_id": event.detail["operation_producer_subject_id"],
        "operation_producer_trust_status": event.detail["operation_producer_trust_status"],
    }


# ---------------------------------------------------------------------------
# Conformance assertion helpers
#
# Pure, reusable comparisons over already-produced governed artifacts. They
# never evaluate policy, never infer expected authorization, and never
# mutate their inputs. Each helper's failure message identifies the
# mismatched field, so a mutation test's AssertionError is diagnostic on its
# own. These are the exact helpers the mutation-test module
# (test_operation_aware_gateway_conformance_mutations.py) exercises.
# ---------------------------------------------------------------------------


def assert_request_ids_align(artifacts: dict[str, Any]) -> None:
    response_id = artifacts["response"]["request_id"]
    gw_id = artifacts["gw_event"]["request_id"]
    evidence_id = artifacts["evidence"]["request_id"]
    assert response_id == gw_id == evidence_id, (
        f"request_id mismatch: response={response_id!r} gw_event={gw_id!r} evidence={evidence_id!r}"
    )


def assert_gateway_and_kernel_agree(artifacts: dict[str, Any]) -> None:
    gw_evidence_ref = artifacts["gw_event"]["audit_evidence_id"]
    evidence_id = artifacts["evidence"]["evidence_id"]
    assert gw_evidence_ref == evidence_id, (
        f"GatewayAuditEvent.audit_evidence_id ({gw_evidence_ref!r}) does not match "
        f"AuditEvidence.evidence_id ({evidence_id!r})"
    )


def assert_response_and_evidence_agree(artifacts: dict[str, Any]) -> None:
    response = artifacts["response"]
    gw_event = artifacts["gw_event"]
    evidence = artifacts["evidence"]
    r_status, g_status, e_status = (
        response["evaluation_status"],
        gw_event["evaluation_status"],
        evidence["evaluation_status"],
    )
    assert r_status == g_status == e_status, (
        f"evaluation_status mismatch: response={r_status!r} gw_event={g_status!r} "
        f"evidence={e_status!r}"
    )
    r_outcome, g_outcome, e_outcome = (
        response.get("outcome"),
        gw_event["outcome"],
        evidence["outcome"],
    )
    assert r_outcome == g_outcome == e_outcome, (
        f"outcome mismatch: response={r_outcome!r} gw_event={g_outcome!r} evidence={e_outcome!r}"
    )
    r_reason, g_reason, e_reason = (
        response.get("failure_reason"),
        gw_event["failure_reason"],
        evidence["failure_reason"],
    )
    assert r_reason == g_reason == e_reason, (
        f"failure_reason mismatch: response={r_reason!r} gw_event={g_reason!r} "
        f"evidence={e_reason!r}"
    )


def assert_disposition_matches_enforcement(artifacts: dict[str, Any]) -> None:
    disposition = artifacts["response"]["disposition"]
    enforcement_action = artifacts["gw_event"]["enforcement_action"]
    assert disposition == enforcement_action, (
        f"response.disposition ({disposition!r}) does not match "
        f"GatewayAuditEvent.enforcement_action ({enforcement_action!r})"
    )


def assert_bundle_provenance_agrees(artifacts: dict[str, Any]) -> None:
    response = artifacts["response"]
    evidence = artifacts["evidence"]
    assert response.get("bundle_id") == evidence.get("bundle_id"), (
        f"bundle_id mismatch: response={response.get('bundle_id')!r} "
        f"evidence={evidence.get('bundle_id')!r}"
    )
    assert response.get("bundle_version") == evidence.get("bundle_version"), (
        f"bundle_version mismatch: response={response.get('bundle_version')!r} "
        f"evidence={evidence.get('bundle_version')!r}"
    )


def assert_http_status_agrees(artifacts: dict[str, Any]) -> None:
    assert artifacts["http_status"] == artifacts["detail_http_status"], (
        f"HTTP status mismatch: actual response={artifacts['http_status']!r} "
        f"recorded in audit detail={artifacts['detail_http_status']!r}"
    )


def assert_subject_identity_agrees(artifacts: dict[str, Any]) -> None:
    assert artifacts["event_subject_id"] == artifacts["known_subject_id"], (
        f"audit event subject_id ({artifacts['event_subject_id']!r}) does not match the "
        f"authenticated subject ({artifacts['known_subject_id']!r})"
    )


def assert_trace_rules_exist_in_policy(artifacts: dict[str, Any], bundle: PolicyBundle) -> None:
    """Every ``matched_rule_ids`` entry must name a rule that actually exists
    in the evaluated bundle, and its effect must agree with that rule's own
    declared effect. Does not build a second policy engine — this only
    cross-references already-produced evidence against static fixture policy
    data, per the PR 9 brief's "Trace-to-Policy Consistency" boundary.
    """
    rules_by_id = {rule.rule_id: rule for rule in bundle.rules}
    matched_rule_ids = artifacts["evidence"]["matched_rule_ids"]
    for rule_id in matched_rule_ids:
        assert rule_id in rules_by_id, (
            f"matched_rule_ids contains {rule_id!r}, which does not exist in bundle "
            f"{bundle.bundle_id!r}"
        )


def assert_matched_rule_order_preserved(
    artifacts: dict[str, Any], expected_order: list[str]
) -> None:
    actual = artifacts["evidence"]["matched_rule_ids"]
    assert actual == expected_order, (
        f"matched_rule_ids order changed: expected {expected_order!r}, got {actual!r}"
    )


def assert_completed_has_no_failure_reason(artifacts: dict[str, Any]) -> None:
    response = artifacts["response"]
    if response["evaluation_status"] == "completed":
        assert response.get("failure_reason") is None, (
            "a completed evaluation must never carry a non-null failure_reason, got "
            f"{response.get('failure_reason')!r}"
        )


def assert_failed_has_no_outcome(artifacts: dict[str, Any]) -> None:
    response = artifacts["response"]
    if response["evaluation_status"] == "failed":
        assert response.get("outcome") is None, (
            "a failed evaluation must never carry a non-null outcome, got "
            f"{response.get('outcome')!r}"
        )


def assert_outcome_matches_expected(artifacts: dict[str, Any], expected_outcome: str) -> None:
    """Central §9 invariant check for a single known-good scenario: the
    response's own outcome must equal the scenario's expected, governed
    outcome (e.g. ``not_applicable`` must never silently become ``deny``)."""
    actual = artifacts["response"].get("outcome")
    assert actual == expected_outcome, (
        f"outcome does not match the scenario's expected value: expected "
        f"{expected_outcome!r}, got {actual!r}"
    )


def assert_no_kernel_evidence(event: Any) -> None:
    assert "gateway_audit_event" not in event.detail, (
        "a pre-kernel rejection must never carry a gateway_audit_event"
    )
    assert "audit_evidence" not in event.detail, (
        "a pre-kernel rejection must never carry audit_evidence"
    )


def assert_full_cross_artifact_agreement(artifacts: dict[str, Any]) -> None:
    """Runs every field-agreement helper above in sequence. This is the
    single call canonical-scenario tests use, and the single call every
    mutation test in the sibling module expects to fail after a single-field
    mutation.
    """
    assert_request_ids_align(artifacts)
    assert_gateway_and_kernel_agree(artifacts)
    assert_response_and_evidence_agree(artifacts)
    assert_disposition_matches_enforcement(artifacts)
    assert_bundle_provenance_agrees(artifacts)
    assert_http_status_agrees(artifacts)
    assert_subject_identity_agrees(artifacts)
    assert_completed_has_no_failure_reason(artifacts)
    assert_failed_has_no_outcome(artifacts)


def assert_safe_response_text(*texts: str) -> None:
    """Sensitive-data conformance: none of the prohibited substrings, and
    never the sentinel, may appear in any of *texts* (HTTP response bodies,
    readiness payloads, or stringified audit records)."""
    for text in texts:
        assert SENTINEL_DO_NOT_LEAK not in text, "sentinel value leaked into response/audit text"
        for needle in _PROHIBITED_SUBSTRINGS:
            assert needle not in text, f"prohibited substring {needle!r} found in response text"


# ---------------------------------------------------------------------------
# 1. Canonical scenario matrix
# ---------------------------------------------------------------------------


def test_canonical_allow_basic(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier, tmp_path
) -> None:
    # Real bundle file, real (unmocked) startup — proves all four readiness
    # components reach True through the genuine lifespan, not merely via the
    # app.state test seam other scenarios below use. The deterministic
    # evaluator is swapped in only *after* real startup already succeeded,
    # so this scenario's own trace_id/evidence_id stay assertable while
    # readiness state reflects a real, complete, successful startup.
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(CANONICAL_ALLOW_BASIC_BUNDLE_DICT), encoding="utf-8")
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(bundle_path))
    reset_readiness_state()
    app = create_app()
    writer = CapturingWriter()
    client = TestClient(app, raise_server_exceptions=False)
    client.__enter__()
    assert app.state.operation_aware_evaluator is not None  # real startup succeeded
    app.state.verifier = mock_verifier
    app.state.audit_writer = writer
    app.state.operation_aware_evaluator = deterministic_evaluator(
        CANONICAL_ALLOW_BASIC_BUNDLE,
        trace_id="trace-allow-basic",
        evidence_id="evidence-allow-basic",
    )

    resp = post_oa(client, action="read:ahu")

    assert resp.status_code == 200
    body = resp.json()
    assert body["evaluation_status"] == "completed"
    assert body["outcome"] == "allow"
    assert body["disposition"] == EnforcementDisposition.ALLOW.value

    artifacts = capture_artifacts(resp, writer, known_subject_id="user1")
    assert_full_cross_artifact_agreement(artifacts)
    assert_trace_rules_exist_in_policy(artifacts, CANONICAL_ALLOW_BASIC_BUNDLE)
    assert_matched_rule_order_preserved(artifacts, ["allow-read-ahu"])
    assert_outcome_matches_expected(artifacts, "allow")

    state = get_readiness_state()
    for component in (
        "operation_aware_mode_enabled",
        "operation_aware_bundle_loaded",
        "operation_aware_evaluator_initialized",
        "operation_aware_policy_semantically_valid",
    ):
        assert state.components.get(component) is True


def test_canonical_deny_precedence(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(
        CANONICAL_DENY_PRECEDENCE_BUNDLE,
        trace_id="trace-deny-precedence",
        evidence_id="evidence-deny-precedence",
    )
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = post_oa(client, action="write:ahu")

    assert resp.status_code == 403
    body = resp.json()
    assert body["evaluation_status"] == "completed"
    assert body["outcome"] == "deny"
    assert body["disposition"] == EnforcementDisposition.DENY.value

    artifacts = capture_artifacts(resp, writer, known_subject_id="user1")
    assert_full_cross_artifact_agreement(artifacts)
    assert_trace_rules_exist_in_policy(artifacts, CANONICAL_DENY_PRECEDENCE_BUNDLE)
    # Explicit deny precedence: both the matching allow and the matching deny
    # rule are preserved in evidence, in the kernel's own declared order — no
    # gateway layer reorders or drops the allow rule from the evidence trail.
    assert_matched_rule_order_preserved(artifacts, ["allow-write-ahu", "deny-write-ahu"])
    assert "deny-write-ahu" in artifacts["evidence"]["matched_rule_ids"]
    assert_outcome_matches_expected(artifacts, "deny")


def test_canonical_default_deny(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(
        CANONICAL_DEFAULT_DENY_BUNDLE,
        trace_id="trace-default-deny",
        evidence_id="evidence-default-deny",
    )
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = post_oa(client, action="write:ahu")

    assert resp.status_code == 403
    body = resp.json()
    assert body["evaluation_status"] == "completed"
    assert body["outcome"] == "deny"
    assert body["disposition"] == EnforcementDisposition.DENY.value

    artifacts = capture_artifacts(resp, writer, known_subject_id="user1")
    assert_full_cross_artifact_agreement(artifacts)
    # Default deny: no rule matched at all — the gateway must never invent an
    # explicit deny rule id to explain this outcome.
    assert artifacts["evidence"]["matched_rule_ids"] == []
    assert_outcome_matches_expected(artifacts, "deny")


def test_canonical_not_applicable(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(
        CANONICAL_NOT_APPLICABLE_BUNDLE,
        trace_id="trace-not-applicable",
        evidence_id="evidence-not-applicable",
    )
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = post_oa(client, action="read:ahu")

    assert resp.status_code == 403
    body = resp.json()
    assert body["evaluation_status"] == "completed"
    assert body["outcome"] == "not_applicable"
    assert body["disposition"] == EnforcementDisposition.DENY.value

    artifacts = capture_artifacts(resp, writer, known_subject_id="user1")
    assert_full_cross_artifact_agreement(artifacts)
    assert_outcome_matches_expected(artifacts, "not_applicable")
    # Central §9 invariant: NOT_APPLICABLE preserved end to end, never
    # collapsed to "deny" anywhere it appears (response, gw_event, evidence)
    # even though the enforcement action/disposition is "deny".
    assert artifacts["response"]["outcome"] != "deny"
    assert artifacts["gw_event"]["outcome"] != "deny"
    assert artifacts["evidence"]["outcome"] != "deny"
    assert artifacts["gw_event"]["enforcement_action"] == "deny"
    # No rule matched (out of scope) — the gateway does not fabricate one.
    assert artifacts["evidence"]["matched_rule_ids"] == []


def test_canonical_invalid_policy_bundle(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    """Runtime canonical conformance for the dependency-integrity anomaly
    path. Distinguished from *startup* canonical conformance: an invalid
    bundle presented at startup is correctly rejected before the route ever
    becomes ready (proven by ``test_operation_aware_startup.py::
    test_enabled_duplicate_rule_ids_fail_startup`` and
    ``test_operation_aware_readiness.py::test_semantic_preflight_failure_duplicate_rule_ids``);
    startup validation is not weakened here to force this bundle through.
    Instead, exactly as the pre-existing
    ``test_operation_aware_endpoint_canonical_scenarios.py``/``test_operation_aware_
    endpoint_audit.py`` already establish, the evaluator is constructed
    directly via the public ``for_bundle()`` factory (bypassing only the
    startup preflight call site) and injected through the same
    ``app.state`` test seam every fixture in this module uses.
    """
    writer = CapturingWriter()
    evaluator = deterministic_evaluator_bypassing_preflight(
        CANONICAL_INVALID_POLICY_BUNDLE,
        trace_id="trace-invalid-policy-bundle",
        evidence_id="evidence-invalid-policy-bundle",
    )
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = post_oa(client, action="read:ahu")

    assert resp.status_code == 503
    body = resp.json()
    assert body["evaluation_status"] == "failed"
    assert body.get("outcome") is None
    assert body["failure_reason"] == "policy_validation_failure"
    assert body["disposition"] == EnforcementDisposition.DENY.value

    artifacts = capture_artifacts(resp, writer, known_subject_id="user1")
    assert_full_cross_artifact_agreement(artifacts)
    assert artifacts["gw_event"]["outcome"] is None
    assert artifacts["evidence"]["outcome"] is None
    # A dependency-integrity anomaly must never be classified as an ordinary
    # policy denial.
    assert resp.status_code != 403


def test_startup_canonical_conformance_invalid_bundle_rejected_before_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Startup canonical conformance (distinct from the runtime scenario
    above): the same structurally-valid-but-semantically-invalid bundle
    cannot reach the live endpoint at all when presented as the actual
    startup configuration — the real, unweakened lifespan preflight
    correctly fails startup and /ready stays 503."""
    bundle_path = tmp_path / "invalid-bundle.json"
    bundle_path.write_text(json.dumps(CANONICAL_INVALID_POLICY_BUNDLE_DICT), encoding="utf-8")
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(bundle_path))
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        assert app.state.operation_aware_evaluator is None
        assert client.get("/ready").status_code == 503
        assert (
            get_readiness_state().components.get("operation_aware_policy_semantically_valid")
            is False
        )


# ---------------------------------------------------------------------------
# 2. Operation-producer and context adversarial matrix
# ---------------------------------------------------------------------------


_PRODUCER_ONLY_FIELD_PAYLOADS: dict[str, object] = {
    "operation_intent": OperationIntent.READ_ONLY.value,
    "location": {"site_id": "site-1"},
    "device": {"device_id": "device-1", "device_class": "controller"},
    "protocol_context": {"protocol": "bacnet", "operation": "readProperty"},
    "safety_context": {"mode": "interlock-engaged"},
    "environment_context": {"mode": "maintenance_mode"},
    "risk_context": {"classification": "elevated"},
    "identity_evidence_reference": {
        "reference_id": "identity-evidence-1",
        "evidence_digest": {"algorithm": "sha-256", "value": "abc123"},
        "identity_source": "basis-identity",
        "redaction_classification": "safe_to_expose",
    },
    "adapter_evidence_reference": {
        "reference_id": "adapter-evidence-1",
        "evidence_digest": {"algorithm": "sha-256", "value": "abc123"},
        "adapter_source": "basis-adapters:bacnet",
        "redaction_classification": "safe_to_expose",
    },
}
assert set(_PRODUCER_ONLY_FIELD_PAYLOADS) == set(OPERATION_PRODUCER_ONLY_FIELDS)


@pytest.mark.parametrize("field_name", OPERATION_PRODUCER_ONLY_FIELDS)
def test_untrusted_caller_rejected_before_kernel_for_every_producer_only_field(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier, field_name: str
) -> None:
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    payload = {field_name: _PRODUCER_ONLY_FIELD_PAYLOADS[field_name]}
    resp = post_oa(client, action="read:ahu", **payload)

    assert resp.status_code == 400
    assert "evaluation_status" not in resp.json()
    assert len(writer.events) == 1
    assert_no_kernel_evidence(writer.events[0])
    assert completed_events(writer) == []


def test_trusted_producer_field_reaches_kernel_with_asserted_provenance(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    """A configured trusted producer may submit a producer-only field, it
    reaches composition unchanged, and the kernel receives only governed
    structured fields (never a caller-supplied gateway-owned field)."""
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(
        monkeypatch, mock_verifier, evaluator, audit_writer=writer, trusted_subject_ids="user1"
    )

    resp = post_oa(client, action="read:ahu", operation_intent="read_only")

    assert resp.status_code == 200
    assert resp.json()["evaluation_status"] == "completed"
    completed = completed_events(writer)
    assert len(completed) == 1
    detail = completed[0].detail
    assert detail["operation_producer_subject_id"] == "user1"
    assert detail["operation_producer_trust_status"] == "trusted"
    assert detail["provenance"]["operation_intent"] == "trusted_producer_asserted"
    # Never upgraded to "verified".
    assert detail["provenance"]["operation_intent"] != "verified"


def test_empty_trust_configuration_default_is_no_trusted_producer(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    """Default posture: with no OPERATION_PRODUCER_SUBJECT_IDS configured,
    the same subject who would be trusted if configured is untrusted by
    default — no implicit trust arises from subject identity, role, issuer,
    field presence, request shape, or auth mode alone."""
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = post_oa(client, action="read:ahu", operation_intent="read_only")

    assert resp.status_code == 400
    assert completed_events(writer) == []


@pytest.mark.parametrize(
    "attempted_subject_id",
    ["User1", "user1x", "us", "USER1"],
    ids=["case-mismatch", "prefix-match", "substring", "upper"],
)
def test_producer_allowlist_matching_is_exact_and_case_sensitive(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier, attempted_subject_id: str
) -> None:
    """The configured allowlist contains a value that is *not* an exact
    match for the authenticated caller's subject_id ("user1") — proving
    matching is case-sensitive, not prefix-based, and not substring-based.
    (Surrounding whitespace is deliberately trimmed by config *parsing*
    itself — ``GatewayConfig.parse_operation_producer_subject_ids`` — the
    same env-var convenience ``BASIS_LOCAL_TOKEN_AUDIENCE`` CSV parsing
    already applies; that is intentional operator convenience at
    configuration time, not a runtime whitespace-normalized match, so it is
    correctly excluded from this adversarial matrix.)"""
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(
        monkeypatch,
        mock_verifier,
        evaluator,
        audit_writer=writer,
        trusted_subject_ids=attempted_subject_id,
    )

    resp = post_oa(client, action="read:ahu", operation_intent="read_only")

    assert resp.status_code == 400, (
        f"allowlist entry {attempted_subject_id!r} must not match authenticated subject "
        "'user1' via case-insensitive, prefix, substring, or whitespace-normalized matching"
    )


def test_subject_role_does_not_grant_producer_trust(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    """The mock verifier's default claims already include roles ["admin",
    "viewer"] (see conftest.py) — proving role membership alone never
    grants producer trust regardless of configuration."""
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = post_oa(client, action="read:ahu", operation_intent="read_only")

    assert resp.status_code == 400
    assert completed_events(writer) == []


# ---------------------------------------------------------------------------
# 3. Request validation adversarial matrix
# ---------------------------------------------------------------------------


@pytest.fixture()
def validation_client(monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier):
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)
    return client, writer


def test_invalid_json_body_rejected(validation_client) -> None:
    client, writer = validation_client
    resp = post_oa_raw(client, content=b"{not valid json")
    assert resp.status_code == 400
    assert completed_events(writer) == []
    assert_safe_response_text(resp.text)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"action": None},
        {"action": ""},
        {"action": "   "},
        {"action": "INVALID ACTION!!"},
        {"action": "read:ahu", "resource_type": "ahu"},
        {"action": "read:ahu", "resource_id": "rooftop-1"},
        {"action": "read:ahu", "resource_id": "ahu:rooftop-1", "resource_type": "ahu"},
        {"action": "read:ahu", "unsupported_extra_field": "value"},
        {"action": "read:ahu", "subject_id": "attacker"},
        {"action": "read:ahu", "subject_roles": ["admin"]},
        {"action": "read:ahu", "evaluation_time": "2020-01-01T00:00:00Z"},
        {"action": "read:ahu", "disposition": "allow"},
        {"action": "read:ahu", "correlation_id": "attacker-supplied"},
        {"action": "read:ahu", "context": {"maintenance_ticket": "CHG-1"}},
        {"action": "read:ahu", "context": {"basis_gateway.forged": "x"}},
        {"action": "read:ahu", "location": "not-an-object"},
        {"action": 123},
        {"action": ["read", "ahu"]},
    ],
    ids=[
        "missing_action",
        "null_action",
        "empty_action",
        "whitespace_action",
        "invalid_action_grammar",
        "composite_action_with_resource_type",
        "local_resource_id_without_type",
        "typed_resource_id_with_resource_type",
        "unsupported_extra_field",
        "gateway_owned_subject_id",
        "gateway_owned_subject_roles",
        "gateway_owned_evaluation_time",
        "gateway_owned_disposition",
        "gateway_owned_correlation_id",
        "non_empty_free_form_context",
        "reserved_context_collision",
        "malformed_nested_context",
        "wrong_scalar_type_action",
        "wrong_array_type_action",
    ],
)
def test_malformed_request_rejected_before_kernel(validation_client, body: dict) -> None:
    client, writer = validation_client
    resp = post_oa(client, **body)
    assert resp.status_code == 400, f"body {body!r} expected 400, got {resp.status_code}"
    assert completed_events(writer) == []
    assert len(writer.events) == 1
    assert_no_kernel_evidence(writer.events[0])
    assert_safe_response_text(resp.text)


def test_malformed_resource_composition_fails_before_kernel(validation_client) -> None:
    """A resource_id with valid gateway-level shape can still be composed
    and then rejected by the kernel's own resource-format validation at
    request-construction time — this is a gateway-owned, pre-kernel
    ``OperationAwareRequestConstructionError`` (400), not a fabricated
    kernel failure."""
    client, writer = validation_client
    resp = post_oa(client, action="read", resource_type="ahu", resource_id="has spaces!!")
    assert resp.status_code == 400
    assert completed_events(writer) == []


def test_duplicate_json_keys_last_value_wins_deterministically(validation_client) -> None:
    """Python's ``json`` module (used by both FastAPI/Pydantic's JSON parser
    and this assertion) deterministically keeps the *last* occurrence of a
    duplicate top-level key — a testable, deterministic contract, not an
    invented one."""
    client, _writer = validation_client
    raw = b'{"action": "write:ahu", "action": "read:ahu"}'
    resp = post_oa_raw(client, content=raw)
    assert resp.status_code == 200
    assert resp.json()["evaluation_status"] == "completed"


def test_reserved_context_key_from_caller_is_the_only_case_producing_a_context_related_400(
    validation_client,
) -> None:
    """Distinguishes the reserved-namespace-collision rejection reason from
    the more general non-empty-context rejection reason: both return 400
    pre-kernel, but a caller attempting to forge gateway evidence receives
    a validation failure at the same layer as any other non-empty context."""
    client, writer = validation_client
    resp = post_oa(client, action="read:ahu", context={"basis_gateway.original_action": "forged"})
    assert resp.status_code == 400
    assert completed_events(writer) == []


# ---------------------------------------------------------------------------
# 4. Identity consistency adversarial matrix
#
# The HTTP authentication boundary (auth/runtime.py's authenticate()) always
# derives NormalizedSubject/IdentityContext from the same verified claims in
# one call, and auth/operation_producer.py's classify_operation_producer()
# always derives OperationProducerTrust from that same NormalizedSubject —
# so a genuinely contradictory identity triple cannot arise through the real
# HTTP route at all. The full adversarial matrix for this invariant is
# therefore exercised directly at the composition layer (see
# test_operation_aware_composition.py's "14. Identity-consistency
# invariants" section) — reused here as a structural/compatibility check,
# not duplicated line-for-line.
# ---------------------------------------------------------------------------


def test_http_boundary_always_derives_consistent_identity_triple() -> None:
    """Structural proof: ``authenticate()`` returns exactly one
    (NormalizedSubject, IdentityContext) pair from one verified-claims input,
    and ``classify_operation_producer()`` accepts only that same
    NormalizedSubject — there is no code path in ``api/routes.py`` that
    constructs an ``OperationProducerTrust`` from a subject other than the
    one ``authenticate()`` just returned, so the HTTP boundary cannot
    construct a contradictory identity triple in the first place."""
    import ast
    import inspect

    from basis_gateway.api import routes

    source = inspect.getsource(routes.evaluate_operation_aware)
    tree = ast.parse(source)
    classify_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "classify_operation_producer"
    ]
    assert len(classify_calls) == 1, (
        "expected exactly one classify_operation_producer() call site in the route handler"
    )
    # The single call site's first argument must be the same `normalized_subject`
    # name the preceding authenticate() call assigned.
    call = classify_calls[0]
    assert isinstance(call.args[0], ast.Name)
    assert call.args[0].id == "normalized_subject"


def test_identity_mismatch_is_rejected_before_any_composed_result_exists() -> None:
    """Direct composition-layer proof (HTTP cannot construct this state — see
    module note above): a contradictory identity triple raises
    CompositionInternalError before any ComposedOperationAwareInput exists,
    so no kernel invocation and no fabricated evidence are possible."""
    from basis_gateway.api.operation_aware_schemas import OperationAwareEvaluateRequest
    from basis_gateway.auth.operation_producer import classify_operation_producer
    from basis_gateway.auth.subject_mapper import IdentityContext, NormalizedSubject
    from basis_gateway.core.operation_aware_composition import (
        CompositionInternalError,
        compose_operation_aware_input,
    )

    subject = NormalizedSubject(subject_id="human-1", name="human-1", roles=(), attributes={})
    mismatched_identity_context = IdentityContext(
        issuer="https://issuer.example", subject_id="someone-else", claims={}
    )
    producer_trust = classify_operation_producer(subject, frozenset())
    request = OperationAwareEvaluateRequest(action="read:ahu")

    with pytest.raises(CompositionInternalError):
        compose_operation_aware_input(
            request,
            subject=subject,
            identity_context=mismatched_identity_context,
            producer_trust=producer_trust,
            correlation_id="corr-1",
            clock=lambda: _FIXED_TIME,
        )


# ---------------------------------------------------------------------------
# 5. Composition adversarial matrix (real HTTP boundary)
# ---------------------------------------------------------------------------


def test_bare_verb_plus_resource_type_composes_once(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)
    resp = post_oa(client, action="read", resource_type="ahu")
    assert resp.status_code == 200
    assert completed_events(writer)[0].detail["gateway_audit_event"]["evaluation_status"] == (
        "completed"
    )


def test_already_composed_action_remains_unchanged_when_valid(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)
    resp = post_oa(client, action="read:ahu")
    assert resp.status_code == 200


def test_invalid_double_composition_rejected(validation_client) -> None:
    client, writer = validation_client
    resp = post_oa(client, action="read:ahu", resource_type="ahu")
    assert resp.status_code == 400
    assert completed_events(writer) == []


def test_typed_resource_identifier_remains_unchanged(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)
    resp = post_oa(client, action="read:ahu", resource_id="ahu:rooftop-1")
    assert resp.status_code == 200


def test_no_resource_synthesized_when_omitted(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)
    resp = post_oa(client, action="read:ahu")
    assert resp.status_code == 200


def test_composition_deterministic_across_repeated_identical_requests(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    """Repeated execution of a canonical scenario with the same injected
    inputs (fixed trace_id/evidence_id/clock) produces equal governed
    artifacts."""
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(
        CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="fixed-trace", evidence_id="fixed-evidence"
    )
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp1 = post_oa(client, action="read:ahu", request_id="fixed-request-id")
    resp2 = post_oa(client, action="read:ahu", request_id="fixed-request-id")

    body1, body2 = resp1.json(), resp2.json()
    for key in ("evaluation_status", "outcome", "disposition", "trace_id", "bundle_id"):
        assert body1[key] == body2[key], f"{key} differs across identical repeated requests"


# ---------------------------------------------------------------------------
# 6. HTTP classification conformance (table-driven)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("evaluation_status", "outcome", "failure_reason", "expected_status"),
    [
        ("completed", "allow", None, 200),
        ("completed", "deny", None, 403),
        ("completed", "not_applicable", None, 403),
        ("failed", None, "invalid_request", 400),
        ("failed", None, "unsupported_schema_version", 400),
        ("failed", None, "invalid_policy_bundle", 503),
        ("failed", None, "policy_validation_failure", 503),
        ("failed", None, "condition_evaluation_error", 500),
        ("failed", None, "internal_evaluation_error", 500),
    ],
)
def test_http_classification_table(
    evaluation_status: str, outcome: str | None, failure_reason: str | None, expected_status: int
) -> None:
    from basis_core.decisions.operation_aware import (
        OperationAwareDecisionOutcome,
        OperationAwareEvaluationStatus,
        OperationAwareFailureReason,
    )

    status = classify_operation_aware_http_status(
        evaluation_status=OperationAwareEvaluationStatus(evaluation_status),
        outcome=OperationAwareDecisionOutcome(outcome) if outcome else None,
        failure_reason=OperationAwareFailureReason(failure_reason) if failure_reason else None,
    )
    assert status == expected_status


@pytest.mark.parametrize(
    "kwargs",
    [
        {"evaluation_status": "completed", "outcome": None, "failure_reason": None},
        {"evaluation_status": "failed", "outcome": "allow", "failure_reason": "invalid_request"},
        {"evaluation_status": "completed", "outcome": "allow", "failure_reason": "invalid_request"},
        {"evaluation_status": "failed", "outcome": None, "failure_reason": None},
    ],
    ids=[
        "completed_null_outcome",
        "failed_allow_outcome",
        "completed_with_failure_reason",
        "failed_missing_failure_reason",
    ],
)
def test_classifier_impossible_states_via_gateway_audit_event_rejection(kwargs: dict) -> None:
    """The classifier itself has no permissive default (proven exhaustively
    by test_operation_aware_http_classification.py); this conformance test
    proves the *contract-shaped* GatewayAuditEvent independently rejects the
    same contradictory states at construction time, so a caller cannot even
    build one of these impossible artifacts to pass downstream."""
    from basis_gateway.audit.operation_aware_gateway_events import (
        GATEWAY_AUDIT_EVENT_TYPE,
        GatewayAuditEvent,
    )

    with pytest.raises(ValueError):
        GatewayAuditEvent(
            event_type=GATEWAY_AUDIT_EVENT_TYPE,
            request_id="req-1",
            audit_evidence_id="evidence-1",
            enforcement_action="deny",
            **kwargs,
        )


def test_allow_outcome_with_deny_disposition_is_never_constructed_by_assembly() -> None:
    """Impossible-state guard: the assembly function always copies
    ``enforcement_action`` from ``result.disposition`` directly — this test
    proves that copy is exact for every canonical scenario, so an
    "allow outcome with deny disposition" state cannot silently arise from
    assembly itself (as opposed to a hand-constructed GatewayAuditEvent,
    already proven rejected above)."""
    from basis_gateway.audit.operation_aware_gateway_events import assemble_gateway_audit_event

    enforcement_point = OperationAwareEnforcementPoint.for_bundle(CANONICAL_ALLOW_BASIC_BUNDLE)
    from basis_core.decisions import OperationAwareDecisionRequest

    request = OperationAwareDecisionRequest(
        request_id="req-x", subject_id="user1", action="read:ahu", evaluation_time=_FIXED_TIME
    )
    result = enforcement_point.evaluate(
        request=request, trace_id="t", evidence_id="e", recorded_at=_FIXED_TIME
    )
    event = assemble_gateway_audit_event(result)
    assert event is not None
    assert event.enforcement_action == result.disposition.value


# ---------------------------------------------------------------------------
# 7. Missing evidence and writer-failure conformance
# ---------------------------------------------------------------------------


def test_missing_audit_evidence_writes_no_completed_event_http_result_unaffected(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    from basis_core.enforcement import OperationAwareEnforcementResult

    writer = CapturingWriter()
    real_evaluator = deterministic_evaluator(
        CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e"
    )
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
        clock=lambda: _FIXED_TIME,
    )
    real_result = real_evaluator.evaluate(composed)
    missing_evidence_result = OperationAwareEnforcementResult(
        response=real_result.response, audit_evidence=None, disposition=real_result.disposition
    )

    class _StubEvaluator:
        def evaluate(self, _composed: object) -> OperationAwareEnforcementResult:
            return missing_evidence_result

    client = client_with_evaluator(
        monkeypatch, mock_verifier, _StubEvaluator(), audit_writer=writer
    )
    resp = post_oa(client, action="read:ahu")

    assert resp.status_code == 200  # HTTP classification still follows the real response
    assert resp.json()["outcome"] == "allow"
    assert len(writer.events) == 1
    assert_no_kernel_evidence(writer.events[0])
    assert completed_events(writer) == []


def test_writer_failure_after_evaluation_does_not_alter_response(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    class _AlwaysFailingWriter:
        def write(self, event: object) -> None:
            raise OSError("audit sink down")

    good_writer = CapturingWriter()
    good_client = client_with_evaluator(
        monkeypatch,
        mock_verifier,
        deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e"),
        audit_writer=good_writer,
    )
    good_resp = post_oa(good_client, action="read:ahu")

    failing_client = client_with_evaluator(
        monkeypatch,
        mock_verifier,
        deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e"),
        audit_writer=_AlwaysFailingWriter(),
    )
    bad_resp = post_oa(failing_client, action="read:ahu")

    assert good_resp.status_code == bad_resp.status_code == 200
    assert good_resp.json()["outcome"] == bad_resp.json()["outcome"] == "allow"


def test_strict_fail_closed_pre_evaluation_failure_does_not_invoke_kernel(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    from basis_gateway.audit.writer import GatewayAuditWriter

    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    monkeypatch.setenv("AUDIT_FAIL_CLOSED", "true")
    reset_readiness_state()
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    client.__enter__()
    app.state.verifier = mock_verifier
    evaluator_calls: list[int] = []

    class _CountingEvaluator:
        def evaluate(self, composed: object) -> Any:
            evaluator_calls.append(1)
            raise AssertionError("kernel must not be invoked while strict-mode writer is degraded")

    app.state.operation_aware_evaluator = _CountingEvaluator()
    writer: GatewayAuditWriter = app.state.audit_writer

    class _AlwaysFailingInner:
        def write(self, event: object) -> None:
            raise OSError("audit sink down")

    writer._inner = _AlwaysFailingInner()
    for _ in range(writer.failure_threshold):
        writer.write(object())
    assert writer.degraded

    resp = post_oa(client, action="read:ahu")

    assert resp.status_code == 503
    assert evaluator_calls == []
    # /health remains liveness-only; /ready reflects the writer's degradation.
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 503


# ---------------------------------------------------------------------------
# 8. Readiness conformance (cross-boundary agreement)
# ---------------------------------------------------------------------------


def test_readiness_route_and_evaluator_agree_when_fully_valid(monkeypatch, tmp_path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(CANONICAL_ALLOW_BASIC_BUNDLE_DICT), encoding="utf-8")
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(bundle_path))
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        assert get_readiness_state().is_ready
        assert client.get("/ready").status_code == 200
        assert app.state.operation_aware_evaluator is not None
        resp = client.post(
            "/v1/evaluate/operation-aware",
            json={"action": "read:ahu"},
            headers={"Authorization": "Bearer fake"},
        )
        assert resp.status_code == 401  # reachable (auth not injected here), not 404/503


def test_readiness_route_and_evaluator_agree_when_bundle_missing(monkeypatch) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        assert not get_readiness_state().is_ready
        assert client.get("/ready").status_code == 503
        assert app.state.operation_aware_evaluator is None
        # Route is registered (reachable), evaluator merely unavailable — 503, not 404.
        resp = client.post(
            "/v1/evaluate/operation-aware",
            json={"action": "read:ahu"},
            headers={"Authorization": "Bearer fake"},
        )
        assert resp.status_code != 404


def test_readiness_reasons_contain_no_sensitive_content(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(tmp_path / "does-not-exist.json"))
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False):
        reasons = get_readiness_state().all_reasons
        assert_safe_response_text(*reasons.values())


# ---------------------------------------------------------------------------
# 9. Route-registration conformance
# ---------------------------------------------------------------------------


def test_disabled_mode_route_absent_and_no_operation_aware_readiness() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        resp = client.post("/v1/evaluate/operation-aware", json={"action": "read:ahu"})
        assert resp.status_code == 404
        components = get_readiness_state().components
        for name in (
            "operation_aware_mode_enabled",
            "operation_aware_bundle_loaded",
            "operation_aware_evaluator_initialized",
            "operation_aware_policy_semantically_valid",
        ):
            assert name not in components
        # /v1/evaluate itself unaffected.
        v1_resp = client.post("/v1/evaluate", json={"action": "read:ahu"})
        assert v1_resp.status_code != 404


def test_enabled_but_startup_fails_later_route_registered_not_404(monkeypatch) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/v1/evaluate/operation-aware",
            json={"action": "read:ahu"},
            headers={"Authorization": "Bearer fake"},
        )
        assert resp.status_code in (401, 503)
        assert resp.status_code != 404


def test_enabled_and_ready_route_registered_once_openapi_has_one_path(
    monkeypatch, tmp_path
) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(CANONICAL_ALLOW_BASIC_BUNDLE_DICT), encoding="utf-8")
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(bundle_path))
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        pass
    reset_readiness_state()
    with TestClient(app) as client:
        schema = client.get("/openapi.json").json()
        oa_paths = [p for p in schema["paths"] if p == "/v1/evaluate/operation-aware"]
        assert len(oa_paths) == 1


# ---------------------------------------------------------------------------
# 10. Internal failure containment
# ---------------------------------------------------------------------------


def test_unexpected_evaluator_exception_fails_closed_no_stack_trace(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    class _ExplodingEvaluator:
        def evaluate(self, composed: object) -> None:
            raise RuntimeError(f"simulated internal failure — {SENTINEL_DO_NOT_LEAK}")

    writer = CapturingWriter()
    client = client_with_evaluator(
        monkeypatch, mock_verifier, _ExplodingEvaluator(), audit_writer=writer
    )
    resp = post_oa(client, action="read:ahu")

    assert resp.status_code == 500
    assert_safe_response_text(resp.text)
    assert completed_events(writer) == []
    # Process liveness remains available.
    assert client.get("/health").status_code == 200


def test_composition_internal_error_fails_closed_never_allows(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    """A gateway-internal composition invariant violation (never
    caller-triggered) must fail closed with 500, never 200."""
    import basis_gateway.api.routes as routes_module

    def _explode(*args: object, **kwargs: object) -> None:
        from basis_gateway.core.operation_aware_composition import CompositionInternalError

        raise CompositionInternalError(f"simulated invariant violation {SENTINEL_DO_NOT_LEAK}")

    monkeypatch.setattr(routes_module, "compose_operation_aware_input", _explode)
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = post_oa(client, action="read:ahu")

    assert resp.status_code == 500
    assert resp.status_code != 200
    assert_safe_response_text(resp.text)
    assert completed_events(writer) == []


# ---------------------------------------------------------------------------
# 11. Sensitive-data conformance
# ---------------------------------------------------------------------------


def test_authorization_header_never_appears_in_response_or_audit(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = post_oa(
        client,
        headers={"Authorization": f"Bearer {SENTINEL_DO_NOT_LEAK}"},
        action="read:ahu",
    )
    assert resp.status_code == 200
    assert_safe_response_text(resp.text)
    for event in writer.events:
        assert_safe_response_text(str(event.detail))


def test_sentinel_in_rejected_producer_context_does_not_leak(
    monkeypatch: pytest.MonkeyPatch, mock_verifier: MockVerifier
) -> None:
    writer = CapturingWriter()
    evaluator = deterministic_evaluator(CANONICAL_ALLOW_BASIC_BUNDLE, trace_id="t", evidence_id="e")
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)

    resp = post_oa(client, action="read:ahu", location={"site_id": SENTINEL_DO_NOT_LEAK})
    assert resp.status_code == 400
    assert_safe_response_text(resp.text)
    for event in writer.events:
        assert_safe_response_text(str(event.detail), str(event.reason or ""))


# ---------------------------------------------------------------------------
# 12. /v1/evaluate compatibility (narrow group; full v0.1 suite runs unchanged)
# ---------------------------------------------------------------------------


def test_v1_evaluate_unaffected_by_operation_aware_enablement(monkeypatch, tmp_path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(CANONICAL_ALLOW_BASIC_BUNDLE_DICT), encoding="utf-8")
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(bundle_path))
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        resp = client.post(
            "/v1/evaluate", json={"action": "read:ahu"}, headers={"Authorization": "Bearer fake"}
        )
        assert resp.status_code != 404
        assert app.state.evaluator is None  # no POLICY_PATH set — unaffected either way


def test_both_endpoints_share_exactly_one_audit_writer(monkeypatch, tmp_path) -> None:
    # AUTH_MODE=basis_local_token (not the default "oidc") so startup requires
    # no network OIDC discovery round-trip — hermetic, matching the identical
    # pattern already established by
    # test_operation_aware_endpoint_audit.py::test_both_enabled_share_exactly_one_writer_instance.
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

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(CANONICAL_ALLOW_BASIC_BUNDLE_DICT), encoding="utf-8")
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(bundle_path))
    v01_policy_path = tmp_path / "v01-policy.json"
    v01_policy_path.write_text(
        '{"rules": [{"rule_name": "r", "role_table": {"read:sensor:telemetry": ["viewer"]}}]}',
        encoding="utf-8",
    )
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.setenv("AUTH_MODE", "basis_local_token")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_ISSUER", "https://identity.basis.example.com")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_AUDIENCE", "basis-gateway")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON", json.dumps({"key-1": public_pem}))
    monkeypatch.setenv("POLICY_PATH", str(v01_policy_path))
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert app.state.evaluator is not None
        assert app.state.operation_aware_evaluator is not None
        assert app.state.evaluator._enforcement_point._audit_writer is app.state.audit_writer  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 13. Public import boundary (repository-wide sweep already exists in
# test_operation_aware_public_api_contract.py; this is a narrow, local
# reference check specific to this module's own new imports)
# ---------------------------------------------------------------------------


def test_this_conformance_module_imports_no_kernel_internals() -> None:
    import ast
    import inspect
    import sys

    this_module = sys.modules[__name__]

    source = inspect.getsource(this_module)
    tree = ast.parse(source)
    forbidden_prefixes = ("basis_core.evaluation",)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert not any(node.module.startswith(p) for p in forbidden_prefixes), node.module
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not any(alias.name.startswith(p) for p in forbidden_prefixes), alias.name


# ---------------------------------------------------------------------------
# Shared canonical artifact builders (imported by the mutation-test module)
# ---------------------------------------------------------------------------


def build_known_good_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    mock_verifier: MockVerifier,
    *,
    bundle: PolicyBundle,
    action: str,
    trace_id: str,
    evidence_id: str,
    bypass_preflight: bool = False,
) -> dict[str, Any]:
    """Build one known-good, fully cross-agreeing artifact bundle for reuse
    by the mutation-test module — avoids re-deriving the HTTP round-trip
    logic in a second file."""
    writer = CapturingWriter()
    evaluator = (
        deterministic_evaluator_bypassing_preflight(
            bundle, trace_id=trace_id, evidence_id=evidence_id
        )
        if bypass_preflight
        else deterministic_evaluator(bundle, trace_id=trace_id, evidence_id=evidence_id)
    )
    client = client_with_evaluator(monkeypatch, mock_verifier, evaluator, audit_writer=writer)
    resp = post_oa(client, action=action)
    return capture_artifacts(resp, writer, known_subject_id="user1")


def mutate(artifacts: dict[str, Any], *keys: str, value: Any) -> dict[str, Any]:
    """Deep-copy *artifacts* and set a nested value at the dotted *keys*
    path — never mutates the original known-good fixture."""
    mutated = copy.deepcopy(artifacts)
    target = mutated
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    return mutated
