"""Exact result-to-HTTP classification for the operation-aware endpoint.

Implements §9 ("Kernel Outcome Versus Gateway Disposition") of
``docs/implementation/operation-aware-gateway-integration-plan.md`` as a
single, small, explicit, exhaustively-tested function — deliberately not
scattered across conditionals in the route handler (§16 PR 6).

|                Result                | Evaluation status | HTTP |
|---------------------------------------|--------------------|-----:|
| Completed ALLOW                       | completed          |  200 |
| Completed explicit DENY               | completed          |  403 |
| Completed default deny                | completed          |  403 |
| Completed NOT_APPLICABLE              | completed          |  403 |
| invalid_request                       | failed             |  400 |
| unsupported_schema_version            | failed             |  400 |
| invalid_policy_bundle                 | failed             |  503 |
| policy_validation_failure             | failed             |  503 |
| condition_evaluation_error            | failed             |  500 |
| internal_evaluation_error             | failed             |  500 |

This function is called only after the kernel has already produced a
trustworthy ``OperationAwareDecisionResponse`` (i.e. the route's own call to
``OperationAwareGatewayEvaluator.evaluate()`` did not raise). It never
determines whether the kernel ran at all — "evaluator unavailable"
(``503``) and "unexpected exception crossing the evaluator boundary"
(``500``) are pre/peri-kernel gateway conditions handled directly by the
route, not by this function.

No permissive default exists here: an evaluation_status/outcome/
failure_reason combination this table does not recognize (which should be
structurally impossible given the kernel's own closed vocabularies) fails
closed with ``500`` rather than guessing ``200``/``403``.
"""

from __future__ import annotations

from basis_core.decisions.operation_aware import (
    OperationAwareDecisionOutcome,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)

__all__ = ["classify_operation_aware_http_status"]

# Closed, exhaustive mapping — every OperationAwareFailureReason member is
# listed explicitly (§9). A failure reason that is somehow not in this
# mapping (structurally impossible given the kernel's closed enum, but never
# assumed) falls through to the 500 fail-closed default below.
_FAILURE_REASON_HTTP_STATUS: dict[OperationAwareFailureReason, int] = {
    OperationAwareFailureReason.INVALID_REQUEST: 400,
    OperationAwareFailureReason.UNSUPPORTED_SCHEMA_VERSION: 400,
    OperationAwareFailureReason.INVALID_POLICY_BUNDLE: 503,
    OperationAwareFailureReason.POLICY_VALIDATION_FAILURE: 503,
    OperationAwareFailureReason.CONDITION_EVALUATION_ERROR: 500,
    OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR: 500,
}

# Fail-closed default for any evaluation_status/outcome/failure_reason
# combination this table does not explicitly recognize. Never a permissive
# 200/403 guess.
_UNRECOGNIZED_STATE_HTTP_STATUS = 500


def classify_operation_aware_http_status(
    *,
    evaluation_status: OperationAwareEvaluationStatus,
    outcome: OperationAwareDecisionOutcome | None,
    failure_reason: OperationAwareFailureReason | None,
) -> int:
    """Return the exact HTTP status for a completed kernel evaluation (§9).

    Args:
        evaluation_status: ``result.response.evaluation_status``, preserved
            verbatim from the kernel.
        outcome: ``result.response.outcome``, preserved verbatim from the
            kernel. ``None`` when ``evaluation_status`` is ``FAILED``.
        failure_reason: ``result.response.failure_reason``, preserved
            verbatim from the kernel. ``None`` when ``evaluation_status`` is
            ``COMPLETED``.

    Returns:
        The exact HTTP status code per this module's classification table.
        Never derives a status from ``disposition`` alone, and never
        collapses distinct governed failure categories into the same status
        as an ordinary policy denial.
    """
    if evaluation_status is OperationAwareEvaluationStatus.COMPLETED:
        if outcome is OperationAwareDecisionOutcome.ALLOW:
            return 200
        if outcome in (
            OperationAwareDecisionOutcome.DENY,
            OperationAwareDecisionOutcome.NOT_APPLICABLE,
        ):
            return 403
        # A completed result with no recognized outcome is structurally
        # impossible per the kernel's own contract (COMPLETED always
        # carries an outcome) — fail closed rather than assume ALLOW.
        return _UNRECOGNIZED_STATE_HTTP_STATUS

    if evaluation_status is OperationAwareEvaluationStatus.FAILED:
        if failure_reason is not None and failure_reason in _FAILURE_REASON_HTTP_STATUS:
            return _FAILURE_REASON_HTTP_STATUS[failure_reason]
        # A failed result with no recognized failure_reason is structurally
        # impossible per the kernel's own contract (FAILED always carries a
        # governed failure_reason) — fail closed.
        return _UNRECOGNIZED_STATE_HTTP_STATUS

    # evaluation_status itself is neither COMPLETED nor FAILED — impossible
    # given the closed two-member enum, but never assumed.
    return _UNRECOGNIZED_STATE_HTTP_STATUS
