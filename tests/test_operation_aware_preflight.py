"""Tests for the startup semantic preflight (§8a, §16 PR 5).

Covers ``basis_gateway.core.operation_aware_evaluator.preflight_operation_aware_evaluator``
and ``build_operation_aware_evaluator``'s use of it. Uses real public
``basis-core`` evaluation throughout — no monkeypatching of the kernel to
manufacture semantic results when a real bundle can produce them.
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timezone

import pytest
from basis_core.decisions.operation_aware import (
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)
from basis_core.enforcement import OperationAwareEnforcementPoint
from basis_core.policy import PolicyBundle

from basis_gateway.core.operation_aware_evaluator import (
    OperationAwareGatewayEvaluator,
    OperationAwarePreflightError,
    build_operation_aware_evaluator,
    preflight_operation_aware_evaluator,
)

# ---------------------------------------------------------------------------
# Bundle fixtures
# ---------------------------------------------------------------------------

ALLOW_ALL_BUNDLE = PolicyBundle(
    bundle_id="allow-all",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    rules=[
        {
            "rule_id": "allow-everything-preflight-matches",
            "effect": "allow",
            "match": {"actions": ["read:basis_gateway_preflight"]},
        }
    ],
)

DENY_ALL_BUNDLE = PolicyBundle(
    bundle_id="deny-all",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    rules=[
        {
            "rule_id": "deny-everything-preflight-matches",
            "effect": "deny",
            "match": {"actions": ["read:basis_gateway_preflight"]},
        }
    ],
)

DEFAULT_DENY_BUNDLE = PolicyBundle(
    bundle_id="default-deny",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    rules=[
        # Nothing matches the preflight's own action -> completed default deny.
        {"rule_id": "unrelated", "effect": "allow", "match": {"actions": ["write:unrelated"]}}
    ],
)

NOT_APPLICABLE_BUNDLE = PolicyBundle(
    bundle_id="not-applicable",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    scope={"actions": ["write:unrelated"]},
    rules=[{"rule_id": "r1", "effect": "allow", "match": {"actions": ["write:unrelated"]}}],
)

DUPLICATE_RULE_ID_BUNDLE = PolicyBundle(
    bundle_id="dup-rule-id",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    rules=[
        {"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}},
        {"rule_id": "r1", "effect": "deny", "match": {"actions": ["write:ahu"]}},
    ],
)


def _evaluator_for(bundle: PolicyBundle) -> OperationAwareGatewayEvaluator:
    """Construct an OperationAwareGatewayEvaluator WITHOUT running preflight
    (bypasses build_operation_aware_evaluator's own preflight call, so the
    preflight function itself can be exercised and tested directly, even
    against bundles that would fail it). Uses the released public
    ``OperationAwareEnforcementPoint.for_bundle()`` factory — never the
    internal ``OperationAwareEvaluationEngine``."""
    enforcement_point = OperationAwareEnforcementPoint.for_bundle(bundle)
    return OperationAwareGatewayEvaluator(
        _enforcement_point=enforcement_point,
        _trace_id_factory=lambda: "unused-trace-id",
        _evidence_id_factory=lambda: "unused-evidence-id",
        _clock=lambda: datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# 1-5. Success cases
# ---------------------------------------------------------------------------


def test_structurally_and_semantically_valid_bundle_succeeds() -> None:
    result = preflight_operation_aware_evaluator(_evaluator_for(ALLOW_ALL_BUNDLE))
    assert result.response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED


def test_completed_allow_result_succeeds() -> None:
    result = preflight_operation_aware_evaluator(_evaluator_for(ALLOW_ALL_BUNDLE))
    assert result.response.outcome.value == "allow"


def test_completed_explicit_deny_result_succeeds() -> None:
    result = preflight_operation_aware_evaluator(_evaluator_for(DENY_ALL_BUNDLE))
    assert result.response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
    assert result.response.outcome.value == "deny"


def test_completed_default_deny_result_succeeds() -> None:
    result = preflight_operation_aware_evaluator(_evaluator_for(DEFAULT_DENY_BUNDLE))
    assert result.response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
    assert result.response.outcome.value == "deny"


def test_completed_not_applicable_result_succeeds() -> None:
    result = preflight_operation_aware_evaluator(_evaluator_for(NOT_APPLICABLE_BUNDLE))
    assert result.response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
    assert result.response.outcome.value == "not_applicable"


def test_build_operation_aware_evaluator_succeeds_for_valid_bundle() -> None:
    evaluator = build_operation_aware_evaluator(ALLOW_ALL_BUNDLE)
    assert isinstance(evaluator, OperationAwareGatewayEvaluator)


# ---------------------------------------------------------------------------
# 6-9. Failure cases
# ---------------------------------------------------------------------------


def test_duplicate_rule_ids_fail_preflight() -> None:
    with pytest.raises(OperationAwarePreflightError) as exc_info:
        preflight_operation_aware_evaluator(_evaluator_for(DUPLICATE_RULE_ID_BUNDLE))
    assert exc_info.value.evaluation_status is OperationAwareEvaluationStatus.FAILED
    assert exc_info.value.failure_reason is OperationAwareFailureReason.POLICY_VALIDATION_FAILURE


def test_invalid_scope_fails_preflight() -> None:
    """A PolicyBundleScope with a genuinely empty selector set is rejected
    by PolicyBundleScope's own structural validator before this bundle can
    even be constructed here — proving the invalid-scope category is caught
    upstream of preflight. Exercised as a construction-time ValueError, not
    a preflight-time failure, since scope structural validity is enforced
    by the public PolicyBundle model itself (not by this repository)."""
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError, structural
        PolicyBundle(
            bundle_id="invalid-scope",
            bundle_version="1.0.0",
            schema_version="1.0.0",
            policy_owner="test-owner",
            scope={},
            rules=[{"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
        )


def test_unsupported_condition_operator_fails_preflight() -> None:
    """PolicyCondition's operator field is open (no whitelist) — an
    invented, structurally well-formed but semantically unimplemented
    operator is accepted by PolicyCondition/PolicyBundle construction, and
    fails only at real condition-evaluation time (condition_evaluation_error),
    which the preflight also treats conservatively as a startup failure
    (§8a step 5)."""
    bundle = PolicyBundle(
        bundle_id="unsupported-operator",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="test-owner",
        rules=[
            {
                "rule_id": "r1",
                "effect": "allow",
                "match": {"actions": ["read:basis_gateway_preflight"]},
                "conditions": [
                    {
                        "condition_id": "c1",
                        "field_path": "risk_context.classification",
                        "operator": "not_a_real_operator",
                        "expected_value": "low",
                    }
                ],
            }
        ],
    )
    with pytest.raises(OperationAwarePreflightError) as exc_info:
        preflight_operation_aware_evaluator(_evaluator_for(bundle))
    assert exc_info.value.evaluation_status is OperationAwareEvaluationStatus.FAILED
    assert exc_info.value.failure_reason is OperationAwareFailureReason.CONDITION_EVALUATION_ERROR


def test_build_operation_aware_evaluator_raises_for_invalid_bundle() -> None:
    with pytest.raises(OperationAwarePreflightError):
        build_operation_aware_evaluator(DUPLICATE_RULE_ID_BUNDLE)


# ---------------------------------------------------------------------------
# 10-11. Safe failure exposure
# ---------------------------------------------------------------------------


def test_preflight_failure_exposes_safe_status_and_reason() -> None:
    with pytest.raises(OperationAwarePreflightError) as exc_info:
        preflight_operation_aware_evaluator(_evaluator_for(DUPLICATE_RULE_ID_BUNDLE))
    assert exc_info.value.evaluation_status is OperationAwareEvaluationStatus.FAILED
    assert isinstance(exc_info.value.failure_reason, OperationAwareFailureReason)
    assert "policy_validation_failure" in str(exc_info.value)


def test_preflight_failure_does_not_expose_policy_document() -> None:
    secret_bundle = PolicyBundle(
        bundle_id="dup-rule-id",
        bundle_version="1.0.0",
        schema_version="1.0.0",
        policy_owner="top-secret-owner-value",
        rules=[
            {"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}},
            {"rule_id": "r1", "effect": "deny", "match": {"actions": ["write:ahu"]}},
        ],
    )
    with pytest.raises(OperationAwarePreflightError) as exc_info:
        preflight_operation_aware_evaluator(_evaluator_for(secret_bundle))
    assert "top-secret-owner-value" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 12-13. Synthetic request contains no live identity or fabricated context
# ---------------------------------------------------------------------------


def test_preflight_uses_no_live_caller_identity() -> None:
    import basis_gateway.core.operation_aware_evaluator as module

    assert module._PREFLIGHT_SUBJECT_ID.startswith("basis-gateway:")
    assert module._PREFLIGHT_REQUEST_ID.startswith("basis-gateway:")


def test_preflight_fabricates_no_optional_operational_context() -> None:
    import basis_gateway.core.operation_aware_evaluator as module

    request = module._build_preflight_request(evaluation_time=datetime.now(timezone.utc))
    assert request.location is None
    assert request.device is None
    assert request.protocol_context is None
    assert request.safety_context is None
    assert request.environment_context is None
    assert request.risk_context is None
    assert request.identity_evidence_reference is None
    assert request.adapter_evidence_reference is None
    assert request.operation_intent is None


# ---------------------------------------------------------------------------
# 14. Preflight evidence never enters the operational audit stream
# ---------------------------------------------------------------------------


def test_preflight_does_not_write_to_operational_audit_stream() -> None:
    """preflight_operation_aware_evaluator takes no AuditWriter/
    GatewayAuditWriter dependency at all — structurally, there is no audit
    writer for it to write to. Checked via the function's own body (AST),
    not its docstring, so prose explaining the invariant does not produce a
    false positive."""
    sig = inspect.signature(preflight_operation_aware_evaluator)
    assert list(sig.parameters) == ["evaluator"]

    source = inspect.getsource(preflight_operation_aware_evaluator)
    tree = ast.parse(source)
    func_node = tree.body[0]
    assert isinstance(func_node, ast.FunctionDef)
    # Body only — index 0 may be a docstring Expr, harmless either way since
    # we inspect calls/names, not raw text.
    call_func_names = {
        node.func.id
        for node in ast.walk(func_node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    attribute_calls = {
        node.func.attr
        for node in ast.walk(func_node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "AuditWriter" not in call_func_names
    assert "write" not in attribute_calls


def test_build_operation_aware_evaluator_does_not_accept_audit_writer() -> None:
    sig = inspect.signature(build_operation_aware_evaluator)
    assert "audit_writer" not in sig.parameters


# ---------------------------------------------------------------------------
# 15. No evaluator returned when preflight fails
# ---------------------------------------------------------------------------


def test_no_evaluator_returned_on_preflight_failure() -> None:
    with pytest.raises(OperationAwarePreflightError):
        build_operation_aware_evaluator(DUPLICATE_RULE_ID_BUNDLE)
    # No partial/half-initialized evaluator escapes — the exception is the
    # only observable outcome; nothing further to assert on since
    # build_operation_aware_evaluator raises rather than returning.


# ---------------------------------------------------------------------------
# 16-17. Public path used, no internal validation import
# ---------------------------------------------------------------------------


def test_preflight_uses_real_enforcement_point_type() -> None:
    evaluator = _evaluator_for(ALLOW_ALL_BUNDLE)
    assert isinstance(evaluator._enforcement_point, OperationAwareEnforcementPoint)


def test_no_internal_validation_function_imported_or_called() -> None:
    """Structural boundary check: the evaluator module must not import
    validate_policy_bundle or any basis_core.evaluation.* internal symbol."""
    import basis_gateway.core.operation_aware_evaluator as module

    source = inspect.getsource(module)
    tree = ast.parse(source)
    imported_names: set[str] = set()
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.add(node.module)
            imported_names.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported_names.update(alias.asname or alias.name for alias in node.names)

    assert "validate_policy_bundle" not in imported_names
    for mod in imported_modules:
        assert not mod.startswith("basis_core.policy.operation_aware.validation")
