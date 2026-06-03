"""Tests for the checked-in example policy file (policies/default.json).

Verifies:
  - the file exists at the expected path
  - it loads successfully with the Phase 4 policy loader
  - the loaded engine can initialize a GatewayEvaluator
"""

from __future__ import annotations

from pathlib import Path

from basis_core.audit import NullAuditWriter

from basis_gateway.core.evaluator import GatewayEvaluator, build_evaluator
from basis_gateway.policy.loader import load_policy_engine

# Path is relative to the repo root; resolve from this file's location.
_REPO_ROOT = Path(__file__).parent.parent
_EXAMPLE_POLICY_PATH = _REPO_ROOT / "policies" / "default.json"


def test_example_policy_file_exists():
    assert _EXAMPLE_POLICY_PATH.exists(), (
        f"policies/default.json not found at {_EXAMPLE_POLICY_PATH}. "
        "This file must be checked in alongside the gateway source."
    )


def test_example_policy_loads_successfully():
    engine = load_policy_engine(str(_EXAMPLE_POLICY_PATH))
    assert engine is not None


def test_example_policy_initializes_evaluator():
    engine = load_policy_engine(str(_EXAMPLE_POLICY_PATH))
    evaluator = build_evaluator(
        engine=engine,
        audit_writer=NullAuditWriter(),
        policy_version="example-v1",
    )
    assert isinstance(evaluator, GatewayEvaluator)
    assert evaluator.policy_version == "example-v1"
