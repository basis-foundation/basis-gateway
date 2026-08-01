"""Public-contract test for the adopted basis-core operation-aware surface.

The module-level imports prove that every operation-aware symbol approved by
the gateway integration plan is available from its documented public package
path. This test does not exercise kernel behavior or import internal modules.
"""

from __future__ import annotations

from basis_core.audit import AuditEvidence
from basis_core.decisions import (
    OperationAwareDecisionOutcome,
    OperationAwareDecisionRequest,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
    OperationIntent,
)
from basis_core.domain import (
    AdapterEvidenceReference,
    IdentityEvidenceReference,
    OperationAwareDevice,
    OperationAwareEnvironmentContext,
    OperationAwareLocation,
    OperationAwareProtocolContext,
    OperationAwareRiskContext,
    OperationAwareSafetyContext,
)
from basis_core.enforcement import (
    EnforcementDisposition,
    OperationAwareEnforcementPoint,
    OperationAwareEnforcementResult,
)
from basis_core.policy import PolicyBundle

PUBLIC_OPERATION_AWARE_SYMBOLS_BY_PACKAGE: dict[str, tuple[object, ...]] = {
    "basis_core.decisions": (
        OperationAwareDecisionOutcome,
        OperationAwareDecisionRequest,
        OperationAwareEvaluationStatus,
        OperationAwareFailureReason,
        OperationIntent,
    ),
    "basis_core.domain": (
        AdapterEvidenceReference,
        IdentityEvidenceReference,
        OperationAwareDevice,
        OperationAwareEnvironmentContext,
        OperationAwareLocation,
        OperationAwareProtocolContext,
        OperationAwareRiskContext,
        OperationAwareSafetyContext,
    ),
    "basis_core.policy": (PolicyBundle,),
    "basis_core.enforcement": (
        EnforcementDisposition,
        OperationAwareEnforcementPoint,
        OperationAwareEnforcementResult,
    ),
    "basis_core.audit": (AuditEvidence,),
}


def test_operation_aware_public_symbols_are_importable() -> None:
    """Every approved symbol resolves through its public package path."""
    for package, symbols in PUBLIC_OPERATION_AWARE_SYMBOLS_BY_PACKAGE.items():
        assert symbols, f"no public symbols registered for {package}"
        assert all(symbol is not None for symbol in symbols)
