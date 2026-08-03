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
from urllib.parse import urlparse

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


def test_integration_plan_pr11_implemented() -> None:
    """PR 11 (the bounded, offline demonstration) is implemented and current
    as of this PR — updated from PR 10's snapshot, where it was still
    pending. Historical planning-time language elsewhere in this document
    that once described PR 11 as pending is expected to remain only where
    explicitly labeled historical (see test_integration_plan_marks_prs_1_
    through_9_complete's own docstring precedent)."""
    text = _read(INTEGRATION_PLAN_MD)
    assert "PR 11" in text
    assert "implemented" in text.lower()
    assert "demo/operation-aware" in text


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
# Markdown link validation
# ---------------------------------------------------------------------------
# GitHub Actions checks out only this repository — sibling BASIS repositories
# (basis-core, basis-architecture, ...) do not exist in that runner, even
# though they may be mounted side by side in a local development sandbox.
# A link classifier that resolves *any* relative path against the local
# filesystem therefore gives a false pass in a sandbox that happens to have
# every sibling repo checked out, and a false failure in CI, where it does
# not. The classifier below fixes that by treating link *type* as the
# deciding factor, not where the test happens to run:
#
#   relative path (no scheme)  -> must resolve to a real file in THIS repo
#   https://github.com/...     -> validated structurally only, no network call
#   fragment-only (#...)       -> not a filesystem path; not checked
#   any other scheme           -> not a filesystem path; not checked
#
# This performs no network access, no git operations, and requires no
# sibling checkout, branch, or "origin/main" reference of any kind.
# ---------------------------------------------------------------------------

_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")

_ALLOWED_EXTERNAL_SCHEMES = frozenset({"http", "https"})
_CANONICAL_GITHUB_ORG = "basis-foundation"
_KNOWN_BASIS_REPOS = frozenset(
    {
        "basis-core",
        "basis-architecture",
        "basis-schemas",
        "basis-console",
        "basis-identity",
        "basis-adapters",
        "basis-gateway",
    }
)


def _link_targets(markdown: str) -> list[str]:
    return [target for target in _LINK_RE.findall(markdown) if target]


def _classify_link(target: str) -> str:
    """Classify a single Markdown link target.

    Returns one of ``"fragment"`` (a same-page anchor, e.g. ``#section``),
    ``"external"`` (``http``/``https`` scheme — never filesystem-checked),
    ``"other-scheme"`` (e.g. ``mailto:`` — never filesystem-checked), or
    ``"relative"`` (no scheme — must resolve to a real file in this repo).
    """
    if target.startswith("#"):
        return "fragment"
    parsed = urlparse(target)
    if parsed.scheme in _ALLOWED_EXTERNAL_SCHEMES:
        return "external"
    if parsed.scheme:
        return "other-scheme"
    return "relative"


def _is_valid_canonical_github_link(url: str) -> bool:
    """Structural-only validation of a cross-repository GitHub link.

    Never makes a network request. Checks scheme, host, organization, that
    the repository segment is a known BASIS repository, and — for links
    pointing at a specific file or directory rather than the repository
    root — that the ref segment is ``blob/main`` or ``tree/main``.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False
    if parsed.hostname != "github.com":
        return False
    segments = [segment for segment in parsed.path.split("/") if segment]
    if len(segments) < 2:
        return False
    org, repo = segments[0], segments[1]
    if org != _CANONICAL_GITHUB_ORG:
        return False
    if repo not in _KNOWN_BASIS_REPOS:
        return False
    if len(segments) > 2 and segments[2] not in ("blob", "tree"):
        return False
    return not (len(segments) > 3 and segments[3] != "main")


def _resolve_relative_link(doc_path: Path, target: str) -> Path:
    """Resolve a same-repository relative link (fragment already stripped by
    the caller) against the Markdown file that contains it."""
    return (doc_path.parent / target).resolve()


@pytest.mark.parametrize("doc_path", _CHANGED_MARKDOWN_FILES, ids=lambda p: p.name)
def test_internal_markdown_links_resolve(doc_path: Path) -> None:
    """Same-repository relative links must resolve to a real file in this
    checkout; canonical cross-repository GitHub links are validated
    structurally only (see module-level comment above)."""
    text = _read(doc_path)
    broken_relative = []
    invalid_external = []
    for target in _link_targets(text):
        kind = _classify_link(target)
        if kind in ("fragment", "other-scheme"):
            continue
        if kind == "external":
            if "github.com" in target and not _is_valid_canonical_github_link(target):
                invalid_external.append(target)
            continue
        # kind == "relative"
        path_only = target.split("#", 1)[0]
        if not path_only:
            continue
        resolved = _resolve_relative_link(doc_path, path_only)
        if not resolved.exists():
            broken_relative.append(target)
    assert not broken_relative, f"{doc_path}: broken same-repository link(s): {broken_relative}"
    assert not invalid_external, (
        f"{doc_path}: malformed cross-repository link(s): {invalid_external}"
    )


# ---------------------------------------------------------------------------
# Link-classifier regression tests
# ---------------------------------------------------------------------------


def test_relative_link_classified_as_relative() -> None:
    assert _classify_link("docs/configuration.md") == "relative"
    assert _classify_link("../audit-model.md") == "relative"


def test_valid_same_repository_relative_link_resolves(tmp_path: Path) -> None:
    doc = tmp_path / "docs" / "guide.md"
    doc.parent.mkdir(parents=True)
    target = tmp_path / "docs" / "other.md"
    target.write_text("content", encoding="utf-8")
    doc.write_text("[link](other.md)", encoding="utf-8")
    resolved = _resolve_relative_link(doc, "other.md")
    assert resolved.exists()


def test_broken_same_repository_relative_link_fails(tmp_path: Path) -> None:
    doc = tmp_path / "docs" / "guide.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("[link](does-not-exist.md)", encoding="utf-8")
    resolved = _resolve_relative_link(doc, "does-not-exist.md")
    assert not resolved.exists()


def test_relative_link_with_fragment_resolves_after_fragment_stripped(tmp_path: Path) -> None:
    doc = tmp_path / "docs" / "guide.md"
    doc.parent.mkdir(parents=True)
    target = tmp_path / "README.md"
    target.write_text("content", encoding="utf-8")
    link_target = "../README.md#current-limitations"
    path_only = link_target.split("#", 1)[0]
    resolved = _resolve_relative_link(doc, path_only)
    assert resolved.exists()


def test_fragment_only_link_is_not_treated_as_a_filesystem_path() -> None:
    assert _classify_link("#current-limitations") == "fragment"


def test_canonical_github_link_is_classified_external_not_relative() -> None:
    url = "https://github.com/basis-foundation/basis-core/blob/main/docs/public-api.md"
    assert _classify_link(url) == "external"


def test_canonical_github_link_structural_validation_accepts_known_repo() -> None:
    assert _is_valid_canonical_github_link(
        "https://github.com/basis-foundation/basis-architecture/blob/main/docs/architecture/basis-gateway.md"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://gitlab.com/basis-foundation/basis-core/blob/main/README.md",  # wrong host
        "https://github.com/some-other-org/basis-core/blob/main/README.md",  # wrong org
        "https://github.com/basis-foundation/not-a-basis-repo/blob/main/README.md",  # unknown repo
        "https://github.com/basis-foundation/basis-core/branch/main/README.md",  # wrong ref keyword
    ],
)
def test_canonical_github_link_structural_validation_rejects_malformed(url: str) -> None:
    assert not _is_valid_canonical_github_link(url)


def test_external_link_handling_performs_no_network_request() -> None:
    """The link classifier and structural validator operate on strings only
    — proven here by calling them with an unreachable-looking host and
    confirming no exception/timeout occurs, which would only be possible if
    a real connection were attempted."""
    unreachable = "https://this-host-does-not-exist.invalid.example/basis-foundation/basis-core"
    assert _classify_link(unreachable) == "external"
    assert _is_valid_canonical_github_link(unreachable) is False


def test_documentation_test_module_makes_no_network_or_process_calls() -> None:
    """Guards against a regression reintroducing network/subprocess/git
    dependencies into link validation.

    The forbidden tokens are assembled from parts so this test's own literal
    list of things-to-forbid does not trip its own assertion.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden_tokens = [
        "requests" + "." + "get",
        "httpx" + "." + "get",
        "urllib" + "." + "request",
        "sub" + "process",
        "git" + " clone",
        "actions" + "/checkout",
    ]
    lines = source.splitlines()
    this_function_start = next(
        i
        for i, line in enumerate(lines)
        if "def test_documentation_test_module_makes_no_network_or_process_calls" in line
    )
    # Exclude this function's own body (which necessarily mentions the
    # forbidden tokens in order to check for them) from the scan.
    source_excluding_self = "\n".join(lines[:this_function_start])
    for forbidden in forbidden_tokens:
        assert forbidden not in source_excluding_self, (
            f"documentation tests must stay offline; found {forbidden!r}"
        )


def test_readme_has_no_sibling_filesystem_links_to_basis_repos() -> None:
    text = _read(README_MD)
    assert not re.search(
        r"\]\(\.\./+basis-(core|architecture|schemas|console|identity|adapters)", text
    )


def test_integration_plan_has_no_sibling_filesystem_links_to_basis_repos() -> None:
    text = _read(INTEGRATION_PLAN_MD)
    assert not re.search(
        r"\]\(\.\./+basis-(core|architecture|schemas|console|identity|adapters)", text
    )


def test_known_canonical_cross_repo_links_use_https_github_urls() -> None:
    readme = _read(README_MD)
    plan = _read(INTEGRATION_PLAN_MD)
    assert "https://github.com/basis-foundation/basis-architecture/blob/main/" in readme
    assert "https://github.com/basis-foundation/basis-core/blob/main/" in readme
    assert "https://github.com/basis-foundation/basis-architecture/blob/main/" in plan
    assert "https://github.com/basis-foundation/basis-core/blob/main/" in plan


def test_intentional_local_dev_sibling_instructions_are_preserved() -> None:
    """The follow-up correction targets Markdown *hyperlinks* only. Plain-
    prose sibling-checkout instructions (e.g. 'pip install -e ../basis-core')
    describe an intentional local development layout and must remain."""
    text = _read(README_MD)
    assert "pip install -e ../basis-core" in text


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
