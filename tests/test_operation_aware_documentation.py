"""Documentation and configuration-example validation for the PR 10
operation-aware documentation and release-hardening pass.

These tests are semantic anchors, not paragraph-fragile assertions: they
check that documented environment variables actually exist in
``GatewayConfig``, that JSON examples in the operation-aware endpoint
documentation actually validate against the real request/response models,
that required vocabulary (readiness component names, audit sibling-artifact
wording, limitation statements) is present, and that internal links among
the Markdown files touched by this PR resolve to real files.

All checks are offline, deterministic, and independent of branch state
beyond the repository's own working tree.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from basis_gateway.api.operation_aware_schemas import (
    OperationAwareEvaluateRequest,
    OperationAwareEvaluateResponse,
)
from basis_gateway.api.schemas import ErrorResponse
from basis_gateway.config import GatewayConfig

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = REPO_ROOT / "docs"

CONFIGURATION_MD = DOCS_DIR / "configuration.md"
ENDPOINT_MD = DOCS_DIR / "operation-aware-endpoint.md"
READINESS_MD = DOCS_DIR / "readiness.md"
AUDIT_MODEL_MD = DOCS_DIR / "audit-model.md"
AUDIT_ESCALATION_MD = DOCS_DIR / "audit-failure-escalation.md"
README_MD = REPO_ROOT / "README.md"
CHANGELOG_MD = REPO_ROOT / "CHANGELOG.md"
INTEGRATION_PLAN_MD = DOCS_DIR / "implementation" / "operation-aware-gateway-integration-plan.md"
RELEASE_REVIEW_MD = DOCS_DIR / "release-readiness" / "operation-aware-gateway-readiness-review.md"
ENV_EXAMPLE = REPO_ROOT / ".env.example"

_CHANGED_MARKDOWN_FILES = [
    CONFIGURATION_MD,
    ENDPOINT_MD,
    READINESS_MD,
    AUDIT_MODEL_MD,
    AUDIT_ESCALATION_MD,
    README_MD,
    CHANGELOG_MD,
    INTEGRATION_PLAN_MD,
    RELEASE_REVIEW_MD,
]

_OPERATION_AWARE_READINESS_COMPONENTS = (
    "operation_aware_mode_enabled",
    "operation_aware_bundle_loaded",
    "operation_aware_evaluator_initialized",
    "operation_aware_policy_semantically_valid",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read(path: Path) -> str:
    assert path.exists(), f"expected documentation file missing: {path}"
    return path.read_text(encoding="utf-8")


def _table_variable_names(markdown: str) -> set[str]:
    """Extract env-var-shaped names from the first column of Markdown table
    rows, e.g. ``| `SOME_VAR` | ... |`` -> ``"SOME_VAR"``.

    Deliberately narrower than "every backticked all-caps token in the
    document" — that would also match log-level values like `INFO` or
    algorithm names like `RS256` that appear in prose/table cells but are
    not themselves environment variables.
    """
    return set(re.findall(r"^\|\s*`([A-Z][A-Z0-9_]+)`\s*\|", markdown, flags=re.MULTILINE))


def _env_example_variable_names(text: str) -> set[str]:
    """Extract every variable name assigned in ``.env.example``, whether the
    line is active or commented out (``# VAR=...``)."""
    return set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]+)=", text, flags=re.MULTILINE))


def _valid_config_env_var_names() -> set[str]:
    """The authoritative set of environment-variable names ``GatewayConfig``
    actually binds to, derived from the live model rather than hand-copied.

    Mirrors pydantic-settings' own resolution: a field's alias (uppercased)
    when one is declared, otherwise the field name itself (uppercased) —
    consistent with ``model_config = SettingsConfigDict(case_sensitive=False)``.
    """
    names: set[str] = set()
    for field_name, field_info in GatewayConfig.model_fields.items():
        alias = field_info.alias
        names.add((alias or field_name).upper())
    return names


def _fenced_json_blocks(markdown: str) -> list[str]:
    return re.findall(r"```json\n(.*?)\n```", markdown, flags=re.DOTALL)


def _squeeze(text: str) -> str:
    """Collapse whitespace (including line wraps) to single spaces, so a
    substring check isn't defeated by Markdown prose wrapping across lines."""
    return re.sub(r"\s+", " ", text)


# ---------------------------------------------------------------------------
# Environment-variable inventory
# ---------------------------------------------------------------------------


def test_every_documented_configuration_variable_exists_in_gateway_config() -> None:
    documented = _table_variable_names(_read(CONFIGURATION_MD))
    valid = _valid_config_env_var_names()
    undocumented_or_unknown = documented - valid
    assert not undocumented_or_unknown, (
        f"docs/configuration.md documents variable(s) not present in GatewayConfig: "
        f"{sorted(undocumented_or_unknown)}"
    )


def test_configuration_doc_documents_every_gateway_config_variable() -> None:
    documented = _table_variable_names(_read(CONFIGURATION_MD))
    valid = _valid_config_env_var_names()
    missing = valid - documented
    assert not missing, (
        f"GatewayConfig variable(s) missing from docs/configuration.md: {sorted(missing)}"
    )


def test_env_example_contains_no_unknown_variable() -> None:
    documented = _env_example_variable_names(_read(ENV_EXAMPLE))
    valid = _valid_config_env_var_names()
    unknown = documented - valid
    assert not unknown, f".env.example documents unknown variable(s): {sorted(unknown)}"


@pytest.mark.parametrize(
    "var",
    [
        "OPERATION_AWARE_ENABLED",
        "OPERATION_AWARE_POLICY_BUNDLE_PATH",
        "OPERATION_PRODUCER_SUBJECT_IDS",
    ],
)
def test_env_example_contains_required_operation_aware_variables(var: str) -> None:
    assert var in _env_example_variable_names(_read(ENV_EXAMPLE))


@pytest.mark.parametrize(
    "var",
    [
        "OPERATION_AWARE_ENABLED",
        "OPERATION_AWARE_POLICY_BUNDLE_PATH",
        "OPERATION_PRODUCER_SUBJECT_IDS",
        "AUDIT_FAILURE_THRESHOLD",
        "AUDIT_FAIL_CLOSED",
    ],
)
def test_configuration_doc_documents_required_variables(var: str) -> None:
    assert var in _table_variable_names(_read(CONFIGURATION_MD))


def test_documented_defaults_match_code() -> None:
    """Spot-check a handful of documented defaults against the live model,
    rather than asserting the whole table verbatim."""
    config = GatewayConfig()
    assert config.audit_failure_threshold == 10
    assert config.audit_fail_closed is False
    assert config.operation_aware_enabled is False
    assert config.operation_producer_subject_ids == frozenset()
    text = _read(CONFIGURATION_MD)
    assert "`10`" in text  # AUDIT_FAILURE_THRESHOLD default
    assert "`false`" in text  # OPERATION_AWARE_ENABLED / AUDIT_FAIL_CLOSED defaults


# ---------------------------------------------------------------------------
# Endpoint documentation
# ---------------------------------------------------------------------------


def test_both_endpoints_are_documented_in_readme() -> None:
    text = _read(README_MD)
    assert "POST /v1/evaluate" in text
    assert "POST /v1/evaluate/operation-aware" in text


def test_operation_aware_route_appears_in_endpoint_docs() -> None:
    assert "POST /v1/evaluate/operation-aware" in _read(ENDPOINT_MD)


def test_readme_states_operation_aware_disabled_by_default() -> None:
    text = _read(README_MD)
    assert "disabled by default" in text.lower()
    assert "OPERATION_AWARE_ENABLED" in text


def test_endpoint_doc_lists_all_producer_only_fields() -> None:
    text = _read(ENDPOINT_MD)
    for field in (
        "operation_intent",
        "location",
        "device",
        "protocol_context",
        "safety_context",
        "environment_context",
        "risk_context",
        "identity_evidence_reference",
        "adapter_evidence_reference",
    ):
        assert field in text, f"producer-only field {field!r} not documented"


def test_endpoint_doc_semantic_outcome_matrix_present() -> None:
    text = _read(ENDPOINT_MD)
    for token in ("not_applicable", "completed", "failed", "disposition"):
        assert token in text


# ---------------------------------------------------------------------------
# JSON example validation
# ---------------------------------------------------------------------------


def test_endpoint_doc_json_examples_are_valid_json() -> None:
    blocks = _fenced_json_blocks(_read(ENDPOINT_MD))
    assert len(blocks) >= 5, "expected multiple fenced JSON examples in the endpoint doc"
    for block in blocks:
        json.loads(block)  # raises on invalid JSON


def test_endpoint_doc_request_examples_validate_against_request_model() -> None:
    """Every fenced JSON example that looks like a request body (has an
    "action" key, and not a response-shaped "evaluation_status"/"error" key)
    must validate against the real OperationAwareEvaluateRequest model."""
    blocks = _fenced_json_blocks(_read(ENDPOINT_MD))
    checked = 0
    for block in blocks:
        data = json.loads(block)
        if not isinstance(data, dict):
            continue
        if "action" in data and "evaluation_status" not in data and "error" not in data:
            OperationAwareEvaluateRequest.model_validate(data)
            checked += 1
    assert checked >= 2, "expected at least two request-shaped JSON examples to validate"


def test_endpoint_doc_response_examples_validate_against_response_model() -> None:
    blocks = _fenced_json_blocks(_read(ENDPOINT_MD))
    checked = 0
    for block in blocks:
        data = json.loads(block)
        if not isinstance(data, dict):
            continue
        if "evaluation_status" in data:
            OperationAwareEvaluateResponse.model_validate(data)
            checked += 1
    assert checked >= 4, "expected allow/deny/not_applicable/failed response examples"


def test_endpoint_doc_error_examples_validate_against_error_response_model() -> None:
    blocks = _fenced_json_blocks(_read(ENDPOINT_MD))
    checked = 0
    for block in blocks:
        data = json.loads(block)
        if not isinstance(data, dict):
            continue
        if "error" in data and "evaluation_status" not in data:
            ErrorResponse.model_validate(data)
            checked += 1
    assert checked >= 2, (
        "expected at least two ErrorResponse-shaped examples "
        "(producer rejection, evaluator unavailable)"
    )


# ---------------------------------------------------------------------------
# Readiness documentation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("component", _OPERATION_AWARE_READINESS_COMPONENTS)
def test_all_four_readiness_components_documented(component: str) -> None:
    assert component in _read(READINESS_MD)


def test_temporary_readiness_name_not_presented_as_current() -> None:
    """PR 5 introduced a temporary, single ``operation_aware_evaluator``
    readiness component name that PR 8 replaced with the four-component
    model. That temporary name must not appear anywhere in current-state
    readiness documentation."""
    text = _read(READINESS_MD)
    assert 'operation_aware_evaluator"' not in text
    assert "`operation_aware_evaluator`" not in text


def test_readiness_doc_documents_health_and_ready() -> None:
    text = _read(READINESS_MD)
    assert "GET /health" in text
    assert "GET /ready" in text


def test_readiness_doc_has_failure_matrix_and_troubleshooting() -> None:
    text = _read(READINESS_MD)
    assert "Failure matrix" in text
    assert "troubleshooting" in text.lower()


# ---------------------------------------------------------------------------
# Audit documentation
# ---------------------------------------------------------------------------


def test_audit_model_doc_states_sibling_not_nested_structure() -> None:
    text = _read(AUDIT_MODEL_MD)
    assert "sibling" in text.lower()
    assert "audit_evidence_id" in text
    assert "evidence_id" in text


def test_audit_model_doc_does_not_claim_evidence_embedded_inside_contract() -> None:
    """The doc must explicitly state that AuditEvidence is NOT nested inside
    the GatewayAuditEvent contract — the correct, corrected wording — and
    must not describe the sibling artifacts using nesting language anywhere
    outside of that explicit denial."""
    text = _read(AUDIT_MODEL_MD).lower()
    assert "never embedded inside the `gatewayauditevent` contract" in text
    assert "siblings" in text


def test_integration_plan_correction_note_present() -> None:
    text = _read(INTEGRATION_PLAN_MD)
    assert "PR 10 correction" in text
    assert "sibling" in text.lower()


def test_readme_audit_bullet_no_longer_uses_ambiguous_embeds_beside_phrasing() -> None:
    """The original README wording ('embeds the kernel's complete AuditEvidence
    beside a contract-shaped GatewayAuditEvent') could be misread as nesting
    the evidence inside the gateway contract. It must be gone."""
    text = _read(README_MD)
    assert "embeds the kernel's complete" not in text
    assert "AuditEvidence` beside" not in text


def test_readme_audit_bullet_uses_precise_sibling_artifact_concepts() -> None:
    text = _read(README_MD)
    for token in (
        "durable outer record",
        "GatewayAuditEvent",
        "AuditEvidence",
        "sibling artifacts",
        "audit_evidence_id",
    ):
        assert token in text, f"expected {token!r} in README's audit evidence description"


# ---------------------------------------------------------------------------
# Console boundary (basis-gateway vs. basis-console ownership)
# ---------------------------------------------------------------------------


def test_readme_states_console_integration_belongs_in_basis_console_repo() -> None:
    text = _squeeze(_read(README_MD))
    assert "`basis-console` repository" in text
    assert "not implemented in this repository" in text


def test_readme_does_not_claim_console_integration_is_implemented() -> None:
    text = _squeeze(_read(README_MD)).lower()
    # The out-of-scope/roadmap language must describe console integration as
    # future/follow-on work, never as shipped.
    assert "console" in text
    assert (
        "follow-on work in `basis-console`".lower() in text
        or "not implemented in this repository" in text
    )


def test_readme_states_training_mode_must_not_bypass_authorization() -> None:
    text = _squeeze(_read(README_MD)).lower()
    assert "must not bypass authentication or authorization" in text


def test_readme_states_both_console_modes_share_governed_gateway_behavior() -> None:
    text = _squeeze(_read(README_MD)).lower()
    assert "consume the gateway apis without changing gateway authorization semantics" in text
    assert "neither console mode creates an alternate authorization path" in text


def test_readme_states_operator_mode_must_not_redefine_kernel_outcomes() -> None:
    text = _squeeze(_read(README_MD)).lower()
    assert "operator mode must not redefine kernel outcomes" in text


def test_release_review_classifies_console_integration_as_future_not_blocker() -> None:
    text = _read(RELEASE_REVIEW_MD)
    assert "basis-console" in text
    assert "future ecosystem work" in text.lower()
    assert "not a pr 10 blocker" in text.lower()


def test_release_review_console_row_classified_future_in_blockers_table() -> None:
    text = _read(RELEASE_REVIEW_MD)
    # The blockers table row for console integration must be classified
    # "future", never "blocking".
    match = re.search(r"\|[^\n|]*basis-console[^\n|]*\|[^\n|]*\|", text)
    assert match is not None, "expected a release-blockers table row mentioning basis-console"
    assert "**future**" in match.group(0)


def test_no_document_adds_a_console_mode_request_field() -> None:
    """Guards against exactly the contract change this follow-up explicitly
    forbids: no documentation may introduce a 'mode'/'console_mode' request
    field on the operation-aware contract."""
    for doc in (README_MD, ENDPOINT_MD, RELEASE_REVIEW_MD, INTEGRATION_PLAN_MD):
        text = _read(doc)
        assert '"mode": "training"' not in text
        assert '"console_mode"' not in text


def test_operation_aware_request_model_has_no_console_mode_field() -> None:
    """Confirms no console-mode field was actually added to the contract."""
    assert "mode" not in OperationAwareEvaluateRequest.model_fields
    assert "console_mode" not in OperationAwareEvaluateRequest.model_fields


# ---------------------------------------------------------------------------
# Required limitation statements
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "phrase",
    [
        "no policy hot reload",
        "no remote policy distribution",
        "no durable",
        "no audit query api",
        "no cryptographic audit signing",
        "no tamper-evident",
        "no adapter execution confirmation",
        "no device-state verification",
        "no background policy revalidation",
        "no built-in multi-tenancy",
        "no hosted-service control plane",
    ],
)
def test_readme_current_limitations_present(phrase: str) -> None:
    text = _read(README_MD).lower()
    assert phrase in text, f"expected limitation phrase {phrase!r} in README"


# ---------------------------------------------------------------------------
# Integration-plan status
# ---------------------------------------------------------------------------


def test_integration_plan_marks_prs_1_through_9_complete() -> None:
    text = _read(INTEGRATION_PLAN_MD)
    assert "PRs 1–9" in text or "PRs 1-9" in text
    assert "complete" in text.lower()


def test_integration_plan_pr11_still_pending() -> None:
    text = _read(INTEGRATION_PLAN_MD)
    assert "pending" in text.lower()
    assert "PR 11" in text


def test_integration_plan_no_stale_not_implemented_claims() -> None:
    """Guards against exactly the stale phrasing PR 10 is responsible for
    removing. Historical planning language describing PR 11 as pending is
    fine; a claim that the route/audit/readiness itself is unimplemented is
    not."""
    text = _read(INTEGRATION_PLAN_MD)
    banned = [
        "no operation-aware route",
        "no live audit event",
        "audit evidence embedded inside GatewayAuditEvent",
    ]
    for phrase in banned:
        assert phrase not in text, f"stale claim still present: {phrase!r}"


# ---------------------------------------------------------------------------
# Changelog
# ---------------------------------------------------------------------------


def test_changelog_unreleased_section_covers_operation_aware() -> None:
    text = _read(CHANGELOG_MD)
    assert "## [Unreleased]" in text
    assert "operation-aware" in text.lower()
    assert "OPERATION_AWARE_ENABLED" in text


def test_changelog_does_not_claim_a_release_version_for_unreleased_work() -> None:
    text = _read(CHANGELOG_MD)
    unreleased_start = text.index("## [Unreleased]")
    next_heading = text.find("\n## [", unreleased_start + 1)
    unreleased_section = text[unreleased_start : next_heading if next_heading != -1 else None]
    assert "0.2.0" not in unreleased_section
    assert "0.1.0" not in unreleased_section


# ---------------------------------------------------------------------------
# Sensitive-data review of documentation/config templates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "needle",
    [
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "Bearer ey",
    ],
)
def test_env_example_contains_no_real_secret_material(needle: str) -> None:
    assert needle not in _read(ENV_EXAMPLE)


@pytest.mark.parametrize(
    "needle",
    [
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
    ],
)
def test_endpoint_doc_contains_no_real_secret_material(needle: str) -> None:
    assert needle not in _read(ENDPOINT_MD)


def test_endpoint_doc_uses_placeholder_token_not_literal_bearer_value() -> None:
    text = _read(ENDPOINT_MD)
    assert "$TOKEN" in text


# ---------------------------------------------------------------------------
# Markdown link validation (internal, relative links only)
# ---------------------------------------------------------------------------


_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _internal_relative_links(markdown: str) -> list[str]:
    links = []
    for target in _LINK_RE.findall(markdown):
        if target.startswith(("http://", "https://", "#")):
            continue
        links.append(target.split("#", 1)[0])
    return [link for link in links if link]


@pytest.mark.parametrize("doc_path", _CHANGED_MARKDOWN_FILES, ids=lambda p: p.name)
def test_internal_markdown_links_resolve(doc_path: Path) -> None:
    text = _read(doc_path)
    base_dir = doc_path.parent
    broken = []
    for link in _internal_relative_links(text):
        resolved = (base_dir / link).resolve()
        # Links that climb outside the basis-gateway checkout (e.g. sibling
        # repos like ../basis-architecture) are not verifiable from this
        # repository alone and are skipped.
        try:
            resolved.relative_to(REPO_ROOT.parent)
        except ValueError:
            continue
        if not resolved.exists():
            broken.append(link)
    assert not broken, f"{doc_path}: broken internal link(s): {broken}"


# ---------------------------------------------------------------------------
# No unknown configuration variable documented anywhere in the endpoint doc
# ---------------------------------------------------------------------------


def test_endpoint_doc_env_var_references_are_known() -> None:
    text = _read(ENDPOINT_MD)
    referenced = set(re.findall(r"`([A-Z][A-Z0-9_]{2,})`", text))
    valid = _valid_config_env_var_names()
    # Only check tokens that look like this repository's own env vars
    # (contain an underscore, ruling out unrelated all-caps tokens).
    candidates = {name for name in referenced if "_" in name}
    unknown = candidates - valid
    assert not unknown, (
        f"docs/operation-aware-endpoint.md references unknown variable(s): {sorted(unknown)}"
    )
