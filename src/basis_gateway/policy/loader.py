"""Policy loader for basis-gateway.

Reads a JSON policy file at startup and constructs a basis-core PolicyEngine.
Loading happens once, synchronously, before the app serves requests.

Policy file format
------------------
{
  "rules": [
    {
      "rule_name": "my-rbac",
      "role_table": {
        "read:sensor:telemetry": ["viewer", "operator", "admin"],
        "write:hvac:setpoint":   ["operator", "admin"]
      }
    }
  ]
}

Constraints:
  - No network access.
  - No background reload.
  - Raises PolicyLoadError on any failure (missing file, parse error, schema error).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from basis_core.policy import PolicyEngine, PolicyRule, RolePolicyRule

log = logging.getLogger(__name__)


class PolicyLoadError(Exception):
    """Raised when the policy file cannot be loaded or is invalid.

    Callers should treat this as a fatal startup error when evaluation
    is enabled.
    """


def _parse_rule(raw: Any, index: int) -> RolePolicyRule:
    """Parse a single rule dict into a RolePolicyRule.

    Raises PolicyLoadError on missing or malformed fields.
    """
    if not isinstance(raw, dict):
        raise PolicyLoadError(f"rules[{index}] must be an object, got {type(raw).__name__}")

    rule_name: str = raw.get("rule_name", f"rule-{index}")
    if not isinstance(rule_name, str) or not rule_name.strip():
        raise PolicyLoadError(f"rules[{index}].rule_name must be a non-empty string")

    raw_table = raw.get("role_table")
    if raw_table is None:
        raise PolicyLoadError(f"rules[{index}].role_table is required")
    if not isinstance(raw_table, dict):
        raise PolicyLoadError(
            f"rules[{index}].role_table must be an object, got {type(raw_table).__name__}"
        )

    role_table: dict[str, set[str]] = {}
    for action, roles in raw_table.items():
        if not isinstance(action, str) or not action.strip():
            raise PolicyLoadError(
                f"rules[{index}].role_table: action keys must be non-empty strings"
            )
        if not isinstance(roles, list):
            raise PolicyLoadError(
                f"rules[{index}].role_table[{action!r}]: roles must be a list, "
                f"got {type(roles).__name__}"
            )
        for role in roles:
            if not isinstance(role, str) or not role.strip():
                raise PolicyLoadError(
                    f"rules[{index}].role_table[{action!r}]: each role must be a non-empty string"
                )
        role_table[action] = set(roles)

    return RolePolicyRule(role_table=role_table, rule_name=rule_name)


def load_policy_engine(policy_path: str) -> PolicyEngine:
    """Load a PolicyEngine from a JSON policy file.

    Args:
        policy_path: Filesystem path to the JSON policy file.

    Returns:
        An initialized PolicyEngine ready to be passed to EnforcementPoint.

    Raises:
        PolicyLoadError: If the file is missing, unreadable, not valid JSON,
                         or does not match the expected schema.
    """
    path = Path(policy_path)

    if not path.exists():
        raise PolicyLoadError(
            f"Policy file not found: {policy_path!r}. "
            "Set POLICY_PATH to the path of your JSON policy file."
        )

    if not path.is_file():
        raise PolicyLoadError(f"Policy path is not a file: {policy_path!r}")

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyLoadError(f"Could not read policy file {policy_path!r}: {exc}") from exc

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise PolicyLoadError(
            f"Policy file {policy_path!r} is not valid JSON: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise PolicyLoadError(
            f"Policy file {policy_path!r} must be a JSON object at the top level"
        )

    raw_rules = data.get("rules")
    if raw_rules is None:
        raise PolicyLoadError(
            f"Policy file {policy_path!r} must contain a 'rules' array"
        )
    if not isinstance(raw_rules, list):
        raise PolicyLoadError(
            f"Policy file {policy_path!r}: 'rules' must be an array, "
            f"got {type(raw_rules).__name__}"
        )
    if len(raw_rules) == 0:
        raise PolicyLoadError(
            f"Policy file {policy_path!r}: 'rules' must contain at least one rule"
        )

    rules: list[PolicyRule] = [_parse_rule(raw, i) for i, raw in enumerate(raw_rules)]

    log.info(
        "Policy loaded path=%r rules=%d",
        policy_path,
        len(rules),
    )

    return PolicyEngine(policies=rules)
