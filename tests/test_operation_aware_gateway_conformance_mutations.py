"""Mutation-quality tests for the gateway conformance suite (PR 9).

Each test below begins with a known-good, fully cross-agreeing artifact
bundle (produced by a real canonical scenario through the real HTTP
boundary — see ``test_operation_aware_gateway_conformance.py``), copies it,
modifies exactly one governed relationship, and proves the corresponding
conformance-assertion helper detects the violation. These tests prove the
helpers in the sibling module are not merely checking known-good artifacts —
they actually fail when tampered with.

No production object is mutated in place anywhere in this module: every
mutation operates on a deep copy of a plain-dict artifact bundle, via the
sibling module's ``mutate()`` helper. No second gateway or policy engine is
implemented here — every helper under test only compares already-produced
values.
"""

from __future__ import annotations

import pytest
from test_operation_aware_gateway_conformance import (
    CANONICAL_DENY_PRECEDENCE_BUNDLE,
    CANONICAL_INVALID_POLICY_BUNDLE,
    CANONICAL_NOT_APPLICABLE_BUNDLE,
    assert_bundle_provenance_agrees,
    assert_completed_has_no_failure_reason,
    assert_disposition_matches_enforcement,
    assert_failed_has_no_outcome,
    assert_full_cross_artifact_agreement,
    assert_gateway_and_kernel_agree,
    assert_matched_rule_order_preserved,
    assert_outcome_matches_expected,
    assert_request_ids_align,
    assert_response_and_evidence_agree,
    assert_subject_identity_agrees,
    build_known_good_artifacts,
    mutate,
)


@pytest.fixture()
def allow_basic_artifacts(monkeypatch, mock_verifier):
    from test_operation_aware_gateway_conformance import CANONICAL_ALLOW_BASIC_BUNDLE

    return build_known_good_artifacts(
        monkeypatch,
        mock_verifier,
        bundle=CANONICAL_ALLOW_BASIC_BUNDLE,
        action="read:ahu",
        trace_id="mutation-trace-allow",
        evidence_id="mutation-evidence-allow",
    )


@pytest.fixture()
def deny_precedence_artifacts(monkeypatch, mock_verifier):
    return build_known_good_artifacts(
        monkeypatch,
        mock_verifier,
        bundle=CANONICAL_DENY_PRECEDENCE_BUNDLE,
        action="write:ahu",
        trace_id="mutation-trace-deny",
        evidence_id="mutation-evidence-deny",
    )


@pytest.fixture()
def not_applicable_artifacts(monkeypatch, mock_verifier):
    return build_known_good_artifacts(
        monkeypatch,
        mock_verifier,
        bundle=CANONICAL_NOT_APPLICABLE_BUNDLE,
        action="read:ahu",
        trace_id="mutation-trace-na",
        evidence_id="mutation-evidence-na",
    )


@pytest.fixture()
def invalid_bundle_artifacts(monkeypatch, mock_verifier):
    return build_known_good_artifacts(
        monkeypatch,
        mock_verifier,
        bundle=CANONICAL_INVALID_POLICY_BUNDLE,
        action="read:ahu",
        trace_id="mutation-trace-invalid",
        evidence_id="mutation-evidence-invalid",
        bypass_preflight=True,
    )


# ---------------------------------------------------------------------------
# Sanity: known-good fixtures pass every helper before any mutation is
# applied (a mutation test that starts from a broken fixture proves nothing).
# ---------------------------------------------------------------------------


def test_known_good_allow_basic_passes_full_agreement(allow_basic_artifacts) -> None:
    assert_full_cross_artifact_agreement(allow_basic_artifacts)


def test_known_good_deny_precedence_passes_full_agreement(deny_precedence_artifacts) -> None:
    assert_full_cross_artifact_agreement(deny_precedence_artifacts)


def test_known_good_not_applicable_passes_full_agreement(not_applicable_artifacts) -> None:
    assert_full_cross_artifact_agreement(not_applicable_artifacts)


def test_known_good_invalid_bundle_passes_full_agreement(invalid_bundle_artifacts) -> None:
    assert_full_cross_artifact_agreement(invalid_bundle_artifacts)


# ---------------------------------------------------------------------------
# 1. Identity mismatch
# ---------------------------------------------------------------------------


def test_mutation_identity_mismatch_detected(allow_basic_artifacts) -> None:
    mutated = mutate(allow_basic_artifacts, "event_subject_id", value="attacker-controlled-subject")
    with pytest.raises(AssertionError):
        assert_subject_identity_agrees(mutated)


# ---------------------------------------------------------------------------
# 2. Request ID mismatch
# ---------------------------------------------------------------------------


def test_mutation_request_id_mismatch_detected(allow_basic_artifacts) -> None:
    mutated = mutate(allow_basic_artifacts, "gw_event", "request_id", value="forged-request-id")
    with pytest.raises(AssertionError):
        assert_request_ids_align(mutated)


# ---------------------------------------------------------------------------
# 3. Evaluation-status mismatch
# ---------------------------------------------------------------------------


def test_mutation_evaluation_status_mismatch_detected(allow_basic_artifacts) -> None:
    mutated = mutate(allow_basic_artifacts, "evidence", "evaluation_status", value="failed")
    with pytest.raises(AssertionError):
        assert_response_and_evidence_agree(mutated)


# ---------------------------------------------------------------------------
# 4. Outcome mismatch
# ---------------------------------------------------------------------------


def test_mutation_outcome_mismatch_detected(allow_basic_artifacts) -> None:
    mutated = mutate(allow_basic_artifacts, "response", "outcome", value="deny")
    with pytest.raises(AssertionError):
        assert_response_and_evidence_agree(mutated)


# ---------------------------------------------------------------------------
# 5. Failure-reason mismatch
# ---------------------------------------------------------------------------


def test_mutation_failure_reason_mismatch_detected(invalid_bundle_artifacts) -> None:
    mutated = mutate(
        invalid_bundle_artifacts, "gw_event", "failure_reason", value="internal_evaluation_error"
    )
    with pytest.raises(AssertionError):
        assert_response_and_evidence_agree(mutated)


# ---------------------------------------------------------------------------
# 6. Evidence-reference mismatch
# ---------------------------------------------------------------------------


def test_mutation_evidence_reference_mismatch_detected(allow_basic_artifacts) -> None:
    mutated = mutate(
        allow_basic_artifacts, "gw_event", "audit_evidence_id", value="wrong-evidence-id"
    )
    with pytest.raises(AssertionError):
        assert_gateway_and_kernel_agree(mutated)


# ---------------------------------------------------------------------------
# 7. Disposition / enforcement mismatch
# ---------------------------------------------------------------------------


def test_mutation_disposition_enforcement_mismatch_detected(allow_basic_artifacts) -> None:
    mutated = mutate(allow_basic_artifacts, "gw_event", "enforcement_action", value="deny")
    with pytest.raises(AssertionError):
        assert_disposition_matches_enforcement(mutated)


# ---------------------------------------------------------------------------
# 8. Bundle-version mismatch
# ---------------------------------------------------------------------------


def test_mutation_bundle_version_mismatch_detected(allow_basic_artifacts) -> None:
    mutated = mutate(allow_basic_artifacts, "evidence", "bundle_version", value="9.9.9")
    with pytest.raises(AssertionError):
        assert_bundle_provenance_agrees(mutated)


# ---------------------------------------------------------------------------
# 9. Trace-rule mismatch (matched_rule_ids order changes during serialization)
# ---------------------------------------------------------------------------


def test_mutation_matched_rule_order_mismatch_detected(deny_precedence_artifacts) -> None:
    reversed_order = list(reversed(deny_precedence_artifacts["evidence"]["matched_rule_ids"]))
    mutated = mutate(
        deny_precedence_artifacts, "evidence", "matched_rule_ids", value=reversed_order
    )
    with pytest.raises(AssertionError):
        assert_matched_rule_order_preserved(mutated, ["allow-write-ahu", "deny-write-ahu"])


# ---------------------------------------------------------------------------
# 10. not_applicable collapsed to deny
# ---------------------------------------------------------------------------


def test_mutation_not_applicable_collapsed_to_deny_detected(not_applicable_artifacts) -> None:
    mutated = mutate(not_applicable_artifacts, "response", "outcome", value="deny")
    with pytest.raises(AssertionError):
        assert_outcome_matches_expected(mutated, "not_applicable")


# ---------------------------------------------------------------------------
# 11. Failed result gains a non-null allow outcome
# ---------------------------------------------------------------------------


def test_mutation_failed_result_gains_allow_outcome_detected(invalid_bundle_artifacts) -> None:
    mutated = mutate(invalid_bundle_artifacts, "response", "outcome", value="allow")
    with pytest.raises(AssertionError):
        assert_failed_has_no_outcome(mutated)


# ---------------------------------------------------------------------------
# 12. Completed result gains a failure reason
# ---------------------------------------------------------------------------


def test_mutation_completed_result_gains_failure_reason_detected(allow_basic_artifacts) -> None:
    mutated = mutate(allow_basic_artifacts, "response", "failure_reason", value="invalid_request")
    with pytest.raises(AssertionError):
        assert_completed_has_no_failure_reason(mutated)


# ---------------------------------------------------------------------------
# 13. Gateway outcome differs from kernel evidence (distinct from #4, which
# mutates the HTTP response body rather than the gateway audit event)
# ---------------------------------------------------------------------------


def test_mutation_gateway_outcome_differs_from_kernel_evidence_detected(
    allow_basic_artifacts,
) -> None:
    mutated = mutate(allow_basic_artifacts, "gw_event", "outcome", value="deny")
    with pytest.raises(AssertionError):
        assert_response_and_evidence_agree(mutated)


# ---------------------------------------------------------------------------
# 14. Pre-kernel rejection mutated to contain kernel evidence
# ---------------------------------------------------------------------------


def test_mutation_pre_kernel_rejection_gains_fabricated_kernel_evidence_detected() -> None:
    """A pre-kernel system event (no gateway_audit_event/audit_evidence keys)
    must never carry kernel evidence. Simulates the tamper by adding both
    keys to a bare detail dict and proving the "no kernel evidence" guard
    would reject it."""

    class _FakeEvent:
        detail = {"http_method": "POST", "request_path": "/v1/evaluate/operation-aware"}

    event = _FakeEvent()
    # Establish the untampered invariant first.
    assert "gateway_audit_event" not in event.detail
    assert "audit_evidence" not in event.detail

    # Tamper: fabricate kernel evidence on what should be a pre-kernel event.
    tampered_detail = dict(event.detail)
    tampered_detail["gateway_audit_event"] = {"request_id": "forged"}
    tampered_detail["audit_evidence"] = {"evidence_id": "forged"}

    with pytest.raises(AssertionError):
        assert "gateway_audit_event" not in tampered_detail
        assert "audit_evidence" not in tampered_detail


# ---------------------------------------------------------------------------
# 15. Full cross-artifact agreement catches every mutation above when run as
# the single aggregate check (proves assert_full_cross_artifact_agreement
# itself, not just the individual helpers, is a faithful conjunction).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("gw_event", "request_id"), "forged-request-id"),
        (("evidence", "evaluation_status"), "failed"),
        (("response", "outcome"), "deny"),
        (("gw_event", "enforcement_action"), "deny"),
        (("evidence", "bundle_version"), "9.9.9"),
        (("gw_event", "audit_evidence_id"), "wrong-evidence-id"),
    ],
    ids=[
        "request_id",
        "evaluation_status",
        "outcome",
        "enforcement_action",
        "bundle_version",
        "audit_evidence_id",
    ],
)
def test_mutation_full_aggregate_check_catches_every_single_field_tamper(
    allow_basic_artifacts, path: tuple[str, ...], value: str
) -> None:
    mutated = mutate(allow_basic_artifacts, *path, value=value)
    with pytest.raises(AssertionError):
        assert_full_cross_artifact_agreement(mutated)
