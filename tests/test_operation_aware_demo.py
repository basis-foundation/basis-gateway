"""Tests for the bounded, offline operation-aware gateway demonstration
(``demo/operation-aware/``).

This module exercises ``demo/operation-aware/run_demo.py`` directly, by
importable function, rather than shelling out to a subprocess — the
demonstration script never spawns an external process or requires network
access, and neither do these tests. The full demo runner is executed once
per test module (see ``demo_result`` below) and reused across assertions so
this module stays fast; a handful of tests re-run a single scenario where
that is the only way to exercise the behavior in question (determinism,
mutated-expectation failure).

``demo/operation-aware`` is not an installed Python package (it is
deliberately outside ``src/``, per the repository's production-code
boundary) — this module adds it to ``sys.path`` and imports ``run_demo``
as a plain module, mirroring how a person would run the script directly.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "demo" / "operation-aware"

if str(DEMO_DIR) not in sys.path:
    sys.path.insert(0, str(DEMO_DIR))

import run_demo  # noqa: E402  (path must be adjusted above first)

pytestmark = pytest.mark.filterwarnings(
    "ignore:Using `httpx` with `starlette.testclient` is deprecated:DeprecationWarning"
)


@pytest.fixture(scope="module")
def demo_result() -> tuple[int, dict[str, run_demo.ScenarioReport]]:
    """Run the full demonstration once per test module; reuse the result."""
    exit_code, reports = run_demo.run_demo(scenario=None, json_output=False)
    return exit_code, {report.name: report for report in reports}


# ---------------------------------------------------------------------------
# 1. Demo files exist.
# ---------------------------------------------------------------------------


def test_demo_files_exist() -> None:
    assert (DEMO_DIR / "run_demo.py").is_file()
    assert (DEMO_DIR / "README.md").is_file()
    assert run_demo.VALID_BUNDLE_PATH.is_file()
    assert run_demo.INVALID_BUNDLE_PATH.is_file()
    assert run_demo.EXPECTED_SUMMARY_PATH.is_file()


# ---------------------------------------------------------------------------
# 2. Demo policy bundle loads structurally.
# ---------------------------------------------------------------------------


def test_valid_bundle_loads_structurally() -> None:
    from basis_core.policy import PolicyBundle

    data = json.loads(run_demo.VALID_BUNDLE_PATH.read_text(encoding="utf-8"))
    bundle = PolicyBundle.model_validate(data)
    assert bundle.bundle_id == "operation-aware-demo"
    assert len(bundle.rules) == 3
    rule_ids = {rule.rule_id for rule in bundle.rules}
    assert rule_ids == {"allow-read-ahu", "allow-write-ahu", "deny-write-protected-ahu"}


def test_invalid_bundle_loads_structurally_but_is_semantically_invalid() -> None:
    """The invalid demo bundle must be structurally valid (PolicyBundle
    accepts it) — its defect (duplicate rule_id) is a semantic one only the
    startup preflight catches, which is exactly what the
    semantic-startup-failure scenario demonstrates."""
    from basis_core.policy import PolicyBundle

    data = json.loads(run_demo.INVALID_BUNDLE_PATH.read_text(encoding="utf-8"))
    bundle = PolicyBundle.model_validate(data)  # must not raise
    rule_ids = [rule.rule_id for rule in bundle.rules]
    assert len(rule_ids) != len(set(rule_ids)), "expected a duplicate rule_id in the invalid bundle"


# ---------------------------------------------------------------------------
# 3. Expected summary JSON parses.
# ---------------------------------------------------------------------------


def test_expected_summary_parses() -> None:
    data = json.loads(run_demo.EXPECTED_SUMMARY_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert data  # non-empty


# ---------------------------------------------------------------------------
# 4. All expected scenarios are declared.
# ---------------------------------------------------------------------------


def test_all_scenarios_declared_in_expected_summary() -> None:
    data = json.loads(run_demo.EXPECTED_SUMMARY_PATH.read_text(encoding="utf-8"))
    for name in run_demo.SCENARIO_ORDER:
        assert name in data, f"expected/scenario-summary.json is missing scenario {name!r}"


# ---------------------------------------------------------------------------
# 5. Full demo runner returns success.
# ---------------------------------------------------------------------------


def test_full_demo_runner_succeeds(demo_result: tuple[int, dict[str, Any]]) -> None:
    exit_code, reports = demo_result
    assert exit_code == 0
    assert len(reports) == len(run_demo.SCENARIO_ORDER)
    for name, report in reports.items():
        assert report.passed, f"scenario {name!r} failed: {report.mismatches}"


# ---------------------------------------------------------------------------
# 6. Allow scenario matches expected result.
# ---------------------------------------------------------------------------


def test_allow_scenario_matches_expected(demo_result: tuple[int, dict[str, Any]]) -> None:
    _, reports = demo_result
    report = reports["allow"]
    assert report.passed
    assert report.details["http_status"] == 200
    assert report.details["evaluation_status"] == "completed"
    assert report.details["outcome"] == "allow"
    assert report.details["disposition"] == "allow"
    assert report.details["matched_rule_ids"] == ["allow-read-ahu"]


# ---------------------------------------------------------------------------
# 7. Explicit deny matches expected result.
# ---------------------------------------------------------------------------


def test_explicit_deny_matches_expected(demo_result: tuple[int, dict[str, Any]]) -> None:
    _, reports = demo_result
    report = reports["explicit-deny"]
    assert report.passed
    assert report.details["http_status"] == 403
    assert report.details["outcome"] == "deny"
    assert report.details["disposition"] == "deny"
    # Distinguishable from default deny: matched-rule evidence names both
    # the allow rule that matched and the deny rule that took precedence.
    assert set(report.details["matched_rule_ids"]) == {
        "allow-write-ahu",
        "deny-write-protected-ahu",
    }


# ---------------------------------------------------------------------------
# 8. Default deny matches expected result.
# ---------------------------------------------------------------------------


def test_default_deny_matches_expected(demo_result: tuple[int, dict[str, Any]]) -> None:
    _, reports = demo_result
    report = reports["default-deny"]
    assert report.passed
    assert report.details["http_status"] == 403
    assert report.details["outcome"] == "deny"
    assert report.details["disposition"] == "deny"
    # No fabricated deny rule: matched-rule evidence is empty.
    assert report.details["matched_rule_ids"] == []


# ---------------------------------------------------------------------------
# 9. not_applicable remains distinct from deny.
# ---------------------------------------------------------------------------


def test_not_applicable_remains_distinct_from_deny(demo_result: tuple[int, dict[str, Any]]) -> None:
    _, reports = demo_result
    report = reports["not-applicable"]
    assert report.passed
    assert report.details["outcome"] == "not_applicable"
    assert report.details["outcome"] != "deny"
    # Only the gateway's separately-derived enforcement disposition collapses
    # not_applicable with deny -- the kernel outcome itself never does.
    assert report.details["disposition"] == "deny"
    assert report.details["http_status"] == 403


# ---------------------------------------------------------------------------
# 10. Untrusted producer is rejected before kernel evaluation.
# ---------------------------------------------------------------------------


def test_untrusted_producer_rejected_before_kernel(demo_result: tuple[int, dict[str, Any]]) -> None:
    _, reports = demo_result
    report = reports["untrusted-producer"]
    assert report.passed
    assert report.details["http_status"] == 400
    assert report.details["kernel_invoked"] is False
    assert report.details["gateway_audit_event_present"] is False
    assert report.details["audit_evidence_present"] is False
    assert report.details["gateway_system_audit_event_present"] is True
    assert report.details["system_event_action"] == "gateway.operation_aware_composition_rejected"
    assert report.details["system_event_reason"] == "producer_context_rejected"


# ---------------------------------------------------------------------------
# 11. Semantic-invalid application is live but not ready.
# ---------------------------------------------------------------------------


def test_semantic_invalid_app_live_but_not_ready(demo_result: tuple[int, dict[str, Any]]) -> None:
    _, reports = demo_result
    report = reports["semantic-startup-failure"]
    assert report.passed
    assert report.details["health_status"] == 200
    assert report.details["ready_status"] == 503
    components = report.details["components"]
    assert components["operation_aware_mode_enabled"] is True
    assert components["operation_aware_bundle_loaded"] is True
    assert components["operation_aware_evaluator_initialized"] is True
    assert components["operation_aware_policy_semantically_valid"] is False


# ---------------------------------------------------------------------------
# 12. Enabled failed route returns non-404.
# ---------------------------------------------------------------------------


def test_semantic_invalid_route_returns_governed_failure_not_404(
    demo_result: tuple[int, dict[str, Any]],
) -> None:
    _, reports = demo_result
    report = reports["semantic-startup-failure"]
    assert report.details["operation_aware_route_status"] != 404
    assert report.details["operation_aware_route_status"] == 503
    assert report.details["operation_aware_route_error"] == "evaluator_unavailable"


# ---------------------------------------------------------------------------
# 13. Completed scenarios emit exactly one completed audit record.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["allow", "explicit-deny", "default-deny", "not-applicable"])
def test_completed_scenarios_emit_exactly_one_completed_record(
    demo_result: tuple[int, dict[str, Any]], name: str
) -> None:
    _, reports = demo_result
    report = reports[name]
    assert not any("exactly one completed audit record" in m for m in report.mismatches)
    assert report.details["evidence_id"] is not None


# ---------------------------------------------------------------------------
# 14. Gateway and kernel evidence IDs link correctly.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["allow", "explicit-deny", "default-deny", "not-applicable"])
def test_gateway_and_kernel_evidence_ids_link(
    demo_result: tuple[int, dict[str, Any]], name: str
) -> None:
    _, reports = demo_result
    report = reports[name]
    assert report.details["audit_evidence_id"] is not None
    assert report.details["audit_evidence_id"] == report.details["evidence_id"]


# ---------------------------------------------------------------------------
# 15. No pre-kernel rejection contains kernel evidence.
# ---------------------------------------------------------------------------


def test_pre_kernel_rejection_contains_no_kernel_evidence(
    demo_result: tuple[int, dict[str, Any]],
) -> None:
    _, reports = demo_result
    report = reports["untrusted-producer"]
    assert report.details["gateway_audit_event_present"] is False
    assert report.details["audit_evidence_present"] is False


# ---------------------------------------------------------------------------
# 16 / 17. No committed private key or bearer token in the demo directory.
# ---------------------------------------------------------------------------

_TEXT_SUFFIXES = {".py", ".md", ".json", ".txt"}


def _iter_demo_text_files() -> list[Path]:
    return [p for p in DEMO_DIR.rglob("*") if p.is_file() and p.suffix in _TEXT_SUFFIXES]


def test_no_committed_private_key() -> None:
    for path in _iter_demo_text_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert "BEGIN RSA PRIVATE KEY" not in text, f"{path} appears to contain a private key"
        assert "BEGIN PRIVATE KEY" not in text, f"{path} appears to contain a private key"


def test_no_committed_bearer_token() -> None:
    for path in _iter_demo_text_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert "Bearer ey" not in text, f"{path} appears to contain a literal bearer token"


# ---------------------------------------------------------------------------
# 18. Output does not contain raw JWTs or private key material.
# ---------------------------------------------------------------------------


def test_output_contains_no_raw_jwt_or_key_material(capsys: pytest.CaptureFixture[str]) -> None:
    run_demo.run_demo(scenario="allow", json_output=True)
    captured = capsys.readouterr()
    assert "BEGIN PRIVATE KEY" not in captured.out
    assert "BEGIN RSA PRIVATE KEY" not in captured.out
    assert "Bearer ey" not in captured.out
    # A compact JWT always starts with "eyJ" (base64 of '{"'); its presence
    # anywhere in stdout is the tell that a token leaked into output.
    assert "eyJ" not in captured.out


# ---------------------------------------------------------------------------
# 19. Runner works without network (static hermeticity guard).
# ---------------------------------------------------------------------------


def test_no_disallowed_network_or_process_imports_in_source() -> None:
    source = (DEMO_DIR / "run_demo.py").read_text(encoding="utf-8")
    banned_substrings = (
        "import requests",
        "import boto3",
        "import docker",
        "import kubernetes",
        "subprocess",
        "urllib.request",
        "socket.",
        "httpx.get(",
        "httpx.post(",
        "httpx.request(",
    )
    for needle in banned_substrings:
        assert needle not in source, f"run_demo.py must not use {needle!r}"


# ---------------------------------------------------------------------------
# 20. Runner output is deterministic in stable semantic fields.
# ---------------------------------------------------------------------------


def test_runner_output_deterministic_in_stable_fields() -> None:
    _, reports_a = run_demo.run_demo(scenario="allow", json_output=False)
    _, reports_b = run_demo.run_demo(scenario="allow", json_output=False)
    stable_keys = (
        "http_status",
        "evaluation_status",
        "outcome",
        "failure_reason",
        "disposition",
        "composed_action",
        "composed_resource",
        "matched_rule_ids",
        "enforcement_action",
    )
    a = {key: reports_a[0].details[key] for key in stable_keys}
    b = {key: reports_b[0].details[key] for key in stable_keys}
    assert a == b
    # Dynamic identifiers, by contrast, are expected to differ per run.
    assert reports_a[0].details["request_id"] != reports_b[0].details["request_id"]


# ---------------------------------------------------------------------------
# 21. Runner returns non-zero when an expectation is deliberately mutated.
# ---------------------------------------------------------------------------


def test_runner_returns_nonzero_when_expectation_mutated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mutated = json.loads(run_demo.EXPECTED_SUMMARY_PATH.read_text(encoding="utf-8"))
    mutated["allow"]["http_status"] = 999
    mutated_path = tmp_path / "mutated-scenario-summary.json"
    mutated_path.write_text(json.dumps(mutated), encoding="utf-8")

    monkeypatch.setattr(run_demo, "EXPECTED_SUMMARY_PATH", mutated_path)
    exit_code, reports = run_demo.run_demo(scenario="allow", json_output=False)

    assert exit_code != 0
    assert reports[0].passed is False
    assert any("http_status" in m for m in reports[0].mismatches)


# ---------------------------------------------------------------------------
# 22. Documentation links resolve.
# ---------------------------------------------------------------------------


def test_readme_relative_links_resolve() -> None:
    text = (DEMO_DIR / "README.md").read_text(encoding="utf-8")
    for match in re.finditer(r"\]\(([^)]+)\)", text):
        target = match.group(1)
        if target.startswith(("http://", "https://", "#")):
            continue
        target_path = target.split("#", 1)[0]
        resolved = (DEMO_DIR / target_path).resolve()
        assert resolved.exists(), f"README.md link target does not exist: {target}"


# ---------------------------------------------------------------------------
# 23 / 24. README states no physical execution occurs; console integration
# is future work.
# ---------------------------------------------------------------------------


def test_readme_states_no_physical_execution() -> None:
    text = (DEMO_DIR / "README.md").read_text(encoding="utf-8").lower()
    assert "physical execution" in text or "no physical-state change" in text


def test_readme_states_console_integration_is_future_work() -> None:
    text = (DEMO_DIR / "README.md").read_text(encoding="utf-8").lower()
    assert "neither console mode is implemented" in text or "future work" in text


# ---------------------------------------------------------------------------
# 25. No new gateway request field such as `mode` or `console_mode` was
# added.
# ---------------------------------------------------------------------------


def test_no_new_gateway_request_field_added() -> None:
    from basis_gateway.api.operation_aware_schemas import OperationAwareEvaluateRequest
    from basis_gateway.api.schemas import EvaluateRequest

    for model in (OperationAwareEvaluateRequest, EvaluateRequest):
        field_names = set(model.model_fields.keys())
        assert "mode" not in field_names
        assert "console_mode" not in field_names


# ---------------------------------------------------------------------------
# Import-boundary guard (demo-specific, mirrors the repository-wide check).
# ---------------------------------------------------------------------------


def test_demo_does_not_import_basis_core_evaluation_internals() -> None:
    source = (DEMO_DIR / "run_demo.py").read_text(encoding="utf-8")
    assert "basis_core.evaluation" not in source
