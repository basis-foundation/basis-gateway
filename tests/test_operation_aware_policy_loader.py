"""Tests for basis_gateway.policy.operation_aware_loader (PR 5).

Covers §8/§16 PR 5 of
``docs/implementation/operation-aware-gateway-integration-plan.md``: structural
loading of a JSON operation-aware policy bundle into the public
``basis_core.policy.PolicyBundle`` model. Uses real public models throughout
— no mocking of ``PolicyBundle``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from basis_core.policy import PolicyBundle

from basis_gateway.policy.loader import load_policy_engine
from basis_gateway.policy.operation_aware_loader import (
    OperationAwarePolicyLoadError,
    OperationAwarePolicyLoadFailureStage,
    load_operation_aware_policy_bundle,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

VALID_BUNDLE: dict = {
    "bundle_id": "test-bundle",
    "bundle_version": "1.0.0",
    "schema_version": "1.0.0",
    "policy_owner": "test-owner",
    "rules": [
        {
            "rule_id": "rule-1",
            "effect": "allow",
            "match": {"actions": ["read:ahu"]},
        }
    ],
}


def write_bundle(tmp_path: Path, data: object, filename: str = "bundle.json") -> str:
    p = tmp_path / filename
    if isinstance(data, str):
        p.write_text(data, encoding="utf-8")
    else:
        p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# 1. Happy path
# ---------------------------------------------------------------------------


def test_valid_bundle_loads_into_real_policy_bundle(tmp_path):
    path = write_bundle(tmp_path, VALID_BUNDLE)
    bundle = load_operation_aware_policy_bundle(path)
    assert type(bundle) is PolicyBundle
    assert bundle.bundle_id == "test-bundle"
    assert bundle.bundle_version == "1.0.0"
    assert len(bundle.rules) == 1


def test_loader_accepts_path_object(tmp_path):
    path = Path(write_bundle(tmp_path, VALID_BUNDLE))
    bundle = load_operation_aware_policy_bundle(path)
    assert bundle.bundle_id == "test-bundle"


# ---------------------------------------------------------------------------
# 2. Missing / unreadable file
# ---------------------------------------------------------------------------


def test_missing_file_raises_file_unreadable(tmp_path):
    missing = str(tmp_path / "does-not-exist.json")
    with pytest.raises(OperationAwarePolicyLoadError) as exc_info:
        load_operation_aware_policy_bundle(missing)
    assert exc_info.value.stage is OperationAwarePolicyLoadFailureStage.FILE_UNREADABLE


def test_directory_instead_of_file_raises_file_unreadable(tmp_path):
    with pytest.raises(OperationAwarePolicyLoadError) as exc_info:
        load_operation_aware_policy_bundle(str(tmp_path))
    assert exc_info.value.stage is OperationAwarePolicyLoadFailureStage.FILE_UNREADABLE


# ---------------------------------------------------------------------------
# 3. Malformed JSON
# ---------------------------------------------------------------------------


def test_malformed_json_raises_invalid_json(tmp_path):
    path = write_bundle(tmp_path, "{not valid json")
    with pytest.raises(OperationAwarePolicyLoadError) as exc_info:
        load_operation_aware_policy_bundle(path)
    assert exc_info.value.stage is OperationAwarePolicyLoadFailureStage.INVALID_JSON


# ---------------------------------------------------------------------------
# 4. Wrong top-level shape
# ---------------------------------------------------------------------------


def test_top_level_array_raises_invalid_structure(tmp_path):
    path = write_bundle(tmp_path, [1, 2, 3])
    with pytest.raises(OperationAwarePolicyLoadError) as exc_info:
        load_operation_aware_policy_bundle(path)
    assert exc_info.value.stage is OperationAwarePolicyLoadFailureStage.INVALID_STRUCTURE


def test_top_level_string_raises_invalid_structure(tmp_path):
    path = write_bundle(tmp_path, json.dumps("just a string"))
    with pytest.raises(OperationAwarePolicyLoadError) as exc_info:
        load_operation_aware_policy_bundle(path)
    assert exc_info.value.stage is OperationAwarePolicyLoadFailureStage.INVALID_STRUCTURE


# ---------------------------------------------------------------------------
# 5. Structurally invalid bundle (delegated to PolicyBundle itself)
# ---------------------------------------------------------------------------


def test_missing_required_field_raises_invalid_structure(tmp_path):
    invalid = dict(VALID_BUNDLE)
    del invalid["policy_owner"]
    path = write_bundle(tmp_path, invalid)
    with pytest.raises(OperationAwarePolicyLoadError) as exc_info:
        load_operation_aware_policy_bundle(path)
    assert exc_info.value.stage is OperationAwarePolicyLoadFailureStage.INVALID_STRUCTURE


def test_empty_rules_array_raises_invalid_structure(tmp_path):
    invalid = dict(VALID_BUNDLE)
    invalid["rules"] = []
    path = write_bundle(tmp_path, invalid)
    with pytest.raises(OperationAwarePolicyLoadError) as exc_info:
        load_operation_aware_policy_bundle(path)
    assert exc_info.value.stage is OperationAwarePolicyLoadFailureStage.INVALID_STRUCTURE


def test_malformed_bundle_version_raises_invalid_structure(tmp_path):
    invalid = dict(VALID_BUNDLE)
    invalid["bundle_version"] = "not-a-semver"
    path = write_bundle(tmp_path, invalid)
    with pytest.raises(OperationAwarePolicyLoadError) as exc_info:
        load_operation_aware_policy_bundle(path)
    assert exc_info.value.stage is OperationAwarePolicyLoadFailureStage.INVALID_STRUCTURE


def test_unconditional_rule_raises_invalid_structure(tmp_path):
    """A rule with neither match nor conditions is structurally rejected by
    OperationAwarePolicyRule itself — proving the loader delegates to the
    public model rather than reimplementing shape validation."""
    invalid = dict(VALID_BUNDLE)
    invalid["rules"] = [{"rule_id": "rule-1", "effect": "allow"}]
    path = write_bundle(tmp_path, invalid)
    with pytest.raises(OperationAwarePolicyLoadError) as exc_info:
        load_operation_aware_policy_bundle(path)
    assert exc_info.value.stage is OperationAwarePolicyLoadFailureStage.INVALID_STRUCTURE


# ---------------------------------------------------------------------------
# 6. Unknown field behavior — governed by PolicyBundle's own extra="forbid"
# ---------------------------------------------------------------------------


def test_unknown_top_level_field_rejected(tmp_path):
    invalid = dict(VALID_BUNDLE)
    invalid["validation_status"] = "approved"
    path = write_bundle(tmp_path, invalid)
    with pytest.raises(OperationAwarePolicyLoadError) as exc_info:
        load_operation_aware_policy_bundle(path)
    assert exc_info.value.stage is OperationAwarePolicyLoadFailureStage.INVALID_STRUCTURE


# ---------------------------------------------------------------------------
# 7. Duplicate rule IDs — structurally accepted (PR 15's job, not this
#    loader's or PolicyBundle's own)
# ---------------------------------------------------------------------------


def test_duplicate_rule_ids_load_structurally(tmp_path):
    """PolicyBundle does not reject duplicate rule_id values structurally —
    see basis_core.policy.operation_aware.bundle's own "Deferred to PR 15"
    docstring section. This loader does not duplicate or pre-empt that
    kernel-owned semantic check; it structurally succeeds here and is only
    caught later by the startup semantic preflight."""
    dup = dict(VALID_BUNDLE)
    dup["rules"] = [
        {"rule_id": "rule-1", "effect": "allow", "match": {"actions": ["read:ahu"]}},
        {"rule_id": "rule-1", "effect": "deny", "match": {"actions": ["write:ahu"]}},
    ]
    path = write_bundle(tmp_path, dup)
    bundle = load_operation_aware_policy_bundle(path)
    assert len(bundle.rules) == 2


# ---------------------------------------------------------------------------
# 8. Error message safety
# ---------------------------------------------------------------------------


def test_error_does_not_expose_full_policy_document(tmp_path):
    invalid = dict(VALID_BUNDLE)
    invalid["policy_owner"] = "top-secret-owner-value"
    del invalid["bundle_id"]
    path = write_bundle(tmp_path, invalid)
    with pytest.raises(OperationAwarePolicyLoadError) as exc_info:
        load_operation_aware_policy_bundle(path)
    assert "top-secret-owner-value" not in str(exc_info.value)


def test_malformed_json_error_does_not_expose_raw_content(tmp_path):
    path = write_bundle(tmp_path, '{"secret_marker_xyz": "should-not-leak"')
    with pytest.raises(OperationAwarePolicyLoadError) as exc_info:
        load_operation_aware_policy_bundle(path)
    assert "should-not-leak" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 9. Read-once
# ---------------------------------------------------------------------------


def test_file_read_exactly_once_per_load(tmp_path, monkeypatch):
    path = write_bundle(tmp_path, VALID_BUNDLE)
    calls: list[int] = []
    original_read_text = Path.read_text

    def counting_read_text(self: Path, *args: object, **kwargs: object) -> str:
        if str(self) == path:
            calls.append(1)
        return original_read_text(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", counting_read_text)
    load_operation_aware_policy_bundle(path)
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# 10. Public type, no semantic re-validation, existing loader unchanged
# ---------------------------------------------------------------------------


def test_returns_public_policy_bundle_not_gateway_copy(tmp_path):
    path = write_bundle(tmp_path, VALID_BUNDLE)
    bundle = load_operation_aware_policy_bundle(path)
    assert bundle.__class__.__module__.startswith("basis_core.policy")


def test_no_semantic_validation_reimplemented_in_loader():
    """Structural boundary check: the loader module must not import the
    kernel's semantic validation entry point at all."""
    import ast
    import inspect

    import basis_gateway.policy.operation_aware_loader as module

    source = inspect.getsource(module)
    tree = ast.parse(source)
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            imported_names.update(alias.asname or alias.name for alias in node.names)
    assert "validate_policy_bundle" not in imported_names


def test_existing_v01_policy_loader_unchanged_and_independent(tmp_path):
    """The v0.1 role-table loader remains a structurally unrelated function —
    loading an operation-aware bundle does not touch it, and it rejects the
    operation-aware bundle shape (proving the two formats are not
    interchangeable)."""
    op_path = write_bundle(tmp_path, VALID_BUNDLE, filename="op-bundle.json")
    load_operation_aware_policy_bundle(op_path)

    from basis_gateway.policy.loader import PolicyLoadError

    with pytest.raises(PolicyLoadError):
        load_policy_engine(op_path)
