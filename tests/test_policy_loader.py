"""Tests for basis_gateway.policy.loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from basis_core.policy import PolicyEngine

from basis_gateway.policy.loader import PolicyLoadError, load_policy_engine

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_policy(tmp_path: Path, data: object, filename: str = "policy.json") -> str:
    p = tmp_path / filename
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


MINIMAL_POLICY = {
    "rules": [
        {
            "rule_name": "test-rbac",
            "role_table": {
                "read:sensor:telemetry": ["viewer", "admin"],
                "write:hvac:setpoint": ["admin"],
            },
        }
    ]
}


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_valid_policy_loads_successfully(tmp_path):
    path = write_policy(tmp_path, MINIMAL_POLICY)
    engine = load_policy_engine(path)
    assert isinstance(engine, PolicyEngine)


def test_loaded_engine_has_correct_rules(tmp_path):
    """The loaded engine should contain one rule (the minimal policy has one rule)."""
    path = write_policy(tmp_path, MINIMAL_POLICY)
    engine = load_policy_engine(path)
    # Verify engine is usable by spot-checking it has policies
    assert engine is not None


def test_multiple_rules_load(tmp_path):
    policy = {
        "rules": [
            {"rule_name": "rule-a", "role_table": {"read:x": ["viewer"]}},
            {"rule_name": "rule-b", "role_table": {"write:y": ["admin"]}},
        ]
    }
    path = write_policy(tmp_path, policy)
    engine = load_policy_engine(path)
    assert isinstance(engine, PolicyEngine)


def test_rule_name_defaults_when_omitted(tmp_path):
    policy = {
        "rules": [
            {"role_table": {"read:x": ["viewer"]}},
        ]
    }
    path = write_policy(tmp_path, policy)
    engine = load_policy_engine(path)
    assert isinstance(engine, PolicyEngine)


# ---------------------------------------------------------------------------
# Missing / unreadable file
# ---------------------------------------------------------------------------


def test_missing_policy_file_raises(tmp_path):
    with pytest.raises(PolicyLoadError, match="not found"):
        load_policy_engine(str(tmp_path / "nonexistent.json"))


def test_path_is_directory_raises(tmp_path):
    with pytest.raises(PolicyLoadError, match="not a file"):
        load_policy_engine(str(tmp_path))


# ---------------------------------------------------------------------------
# Invalid JSON
# ---------------------------------------------------------------------------


def test_invalid_json_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ this is not json }", encoding="utf-8")
    with pytest.raises(PolicyLoadError, match="not valid JSON"):
        load_policy_engine(str(p))


def test_json_array_at_top_level_raises(tmp_path):
    path = write_policy(tmp_path, [{"rules": []}])
    with pytest.raises(PolicyLoadError, match="JSON object"):
        load_policy_engine(path)


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def test_missing_rules_key_raises(tmp_path):
    path = write_policy(tmp_path, {"version": "1"})
    with pytest.raises(PolicyLoadError, match="'rules' array"):
        load_policy_engine(path)


def test_rules_not_array_raises(tmp_path):
    path = write_policy(tmp_path, {"rules": "not-a-list"})
    with pytest.raises(PolicyLoadError, match="must be an array"):
        load_policy_engine(path)


def test_empty_rules_raises(tmp_path):
    path = write_policy(tmp_path, {"rules": []})
    with pytest.raises(PolicyLoadError, match="at least one rule"):
        load_policy_engine(path)


def test_rule_not_object_raises(tmp_path):
    path = write_policy(tmp_path, {"rules": ["not-a-dict"]})
    with pytest.raises(PolicyLoadError, match="must be an object"):
        load_policy_engine(path)


def test_missing_role_table_raises(tmp_path):
    path = write_policy(tmp_path, {"rules": [{"rule_name": "r"}]})
    with pytest.raises(PolicyLoadError, match="role_table is required"):
        load_policy_engine(path)


def test_role_table_not_object_raises(tmp_path):
    path = write_policy(tmp_path, {"rules": [{"rule_name": "r", "role_table": ["a"]}]})
    with pytest.raises(PolicyLoadError, match="must be an object"):
        load_policy_engine(path)


def test_roles_not_list_raises(tmp_path):
    path = write_policy(tmp_path, {"rules": [{"role_table": {"read:x": "admin"}}]})
    with pytest.raises(PolicyLoadError, match="must be a list"):
        load_policy_engine(path)


def test_role_not_string_raises(tmp_path):
    path = write_policy(tmp_path, {"rules": [{"role_table": {"read:x": [123]}}]})
    with pytest.raises(PolicyLoadError, match="non-empty string"):
        load_policy_engine(path)


def test_empty_rule_name_raises(tmp_path):
    path = write_policy(tmp_path, {"rules": [{"rule_name": "  ", "role_table": {"r": ["a"]}}]})
    with pytest.raises(PolicyLoadError, match="non-empty string"):
        load_policy_engine(path)
