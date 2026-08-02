"""Tests for basis_gateway.api.operation_aware_classification (PR 6, §9).

Exhaustive, table-driven coverage of the result-to-HTTP classification
function in isolation from the route/kernel — every row of the integration
plan's §9 table, plus the fail-closed default for a structurally impossible
evaluation_status/outcome/failure_reason combination.
"""

from __future__ import annotations

import pytest
from basis_core.decisions.operation_aware import (
    OperationAwareDecisionOutcome,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)

from basis_gateway.api.operation_aware_classification import classify_operation_aware_http_status

COMPLETED = OperationAwareEvaluationStatus.COMPLETED
FAILED = OperationAwareEvaluationStatus.FAILED
ALLOW = OperationAwareDecisionOutcome.ALLOW
DENY = OperationAwareDecisionOutcome.DENY
NOT_APPLICABLE = OperationAwareDecisionOutcome.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# §9 classification table — every row
# ---------------------------------------------------------------------------


def test_completed_allow_is_200() -> None:
    assert (
        classify_operation_aware_http_status(
            evaluation_status=COMPLETED, outcome=ALLOW, failure_reason=None
        )
        == 200
    )


def test_completed_explicit_deny_is_403() -> None:
    assert (
        classify_operation_aware_http_status(
            evaluation_status=COMPLETED, outcome=DENY, failure_reason=None
        )
        == 403
    )


def test_completed_default_deny_is_403() -> None:
    """Default deny is reported as outcome=DENY by the kernel (no distinct
    outcome value) — same classification as explicit deny."""
    assert (
        classify_operation_aware_http_status(
            evaluation_status=COMPLETED, outcome=DENY, failure_reason=None
        )
        == 403
    )


def test_completed_not_applicable_is_403() -> None:
    assert (
        classify_operation_aware_http_status(
            evaluation_status=COMPLETED, outcome=NOT_APPLICABLE, failure_reason=None
        )
        == 403
    )


def test_not_applicable_is_403_not_200() -> None:
    """NOT_APPLICABLE must never be classified as an allow, even though the
    gateway's execution behavior (block) is the same as an explicit deny."""
    status = classify_operation_aware_http_status(
        evaluation_status=COMPLETED, outcome=NOT_APPLICABLE, failure_reason=None
    )
    assert status != 200


@pytest.mark.parametrize(
    ("failure_reason", "expected_status"),
    [
        (OperationAwareFailureReason.INVALID_REQUEST, 400),
        (OperationAwareFailureReason.UNSUPPORTED_SCHEMA_VERSION, 400),
        (OperationAwareFailureReason.INVALID_POLICY_BUNDLE, 503),
        (OperationAwareFailureReason.POLICY_VALIDATION_FAILURE, 503),
        (OperationAwareFailureReason.CONDITION_EVALUATION_ERROR, 500),
        (OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR, 500),
    ],
)
def test_failed_evaluation_status_by_failure_reason(
    failure_reason: OperationAwareFailureReason, expected_status: int
) -> None:
    assert (
        classify_operation_aware_http_status(
            evaluation_status=FAILED, outcome=None, failure_reason=failure_reason
        )
        == expected_status
    )


def test_every_failure_reason_member_is_classified() -> None:
    """Closed-vocabulary guard: every member of OperationAwareFailureReason
    must appear in the module's mapping, so a future basis-core release
    adding a seventh reason fails a test here rather than silently falling
    through to the fail-closed 500 default."""
    from basis_gateway.api.operation_aware_classification import (
        _FAILURE_REASON_HTTP_STATUS,
    )

    assert set(_FAILURE_REASON_HTTP_STATUS) == set(OperationAwareFailureReason)


# ---------------------------------------------------------------------------
# Distinctness — governed failures are not collapsed into 403
# ---------------------------------------------------------------------------


def test_governed_failures_never_return_403() -> None:
    for failure_reason in OperationAwareFailureReason:
        status = classify_operation_aware_http_status(
            evaluation_status=FAILED, outcome=None, failure_reason=failure_reason
        )
        assert status != 403, f"{failure_reason} must not be classified as an ordinary 403 deny"


def test_dependency_integrity_failures_are_503_not_500() -> None:
    for failure_reason in (
        OperationAwareFailureReason.INVALID_POLICY_BUNDLE,
        OperationAwareFailureReason.POLICY_VALIDATION_FAILURE,
    ):
        assert (
            classify_operation_aware_http_status(
                evaluation_status=FAILED, outcome=None, failure_reason=failure_reason
            )
            == 503
        )


def test_per_request_kernel_failures_are_500_not_503() -> None:
    for failure_reason in (
        OperationAwareFailureReason.CONDITION_EVALUATION_ERROR,
        OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR,
    ):
        assert (
            classify_operation_aware_http_status(
                evaluation_status=FAILED, outcome=None, failure_reason=failure_reason
            )
            == 500
        )


def test_shape_failures_are_400_not_500_or_503() -> None:
    for failure_reason in (
        OperationAwareFailureReason.INVALID_REQUEST,
        OperationAwareFailureReason.UNSUPPORTED_SCHEMA_VERSION,
    ):
        assert (
            classify_operation_aware_http_status(
                evaluation_status=FAILED, outcome=None, failure_reason=failure_reason
            )
            == 400
        )


# ---------------------------------------------------------------------------
# Fail-closed defaults for structurally impossible states
# ---------------------------------------------------------------------------


def test_completed_with_no_outcome_fails_closed_to_500() -> None:
    """Structurally impossible per the kernel's own contract (a completed
    result always carries an outcome) — must never default to 200/403."""
    status = classify_operation_aware_http_status(
        evaluation_status=COMPLETED, outcome=None, failure_reason=None
    )
    assert status == 500


def test_failed_with_no_failure_reason_fails_closed_to_500() -> None:
    """Structurally impossible per the kernel's own contract (a failed
    result always carries a governed failure_reason)."""
    status = classify_operation_aware_http_status(
        evaluation_status=FAILED, outcome=None, failure_reason=None
    )
    assert status == 500


def test_no_combination_ever_returns_a_permissive_default() -> None:
    """Every reachable (evaluation_status, outcome, failure_reason) triple —
    including nonsensical ones a real kernel would never produce — must
    resolve to one of the closed set of documented statuses, never silently
    falling through to 200."""
    allowed_statuses = {200, 400, 403, 500, 503}
    outcomes: list[OperationAwareDecisionOutcome | None] = [None, ALLOW, DENY, NOT_APPLICABLE]
    reasons: list[OperationAwareFailureReason | None] = [None, *list(OperationAwareFailureReason)]
    for status in (COMPLETED, FAILED):
        for outcome in outcomes:
            for reason in reasons:
                result = classify_operation_aware_http_status(
                    evaluation_status=status, outcome=outcome, failure_reason=reason
                )
                assert result in allowed_statuses
                if result == 200:
                    assert status is COMPLETED and outcome is ALLOW
