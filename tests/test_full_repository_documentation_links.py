"""Repository-wide Markdown link validation.

Extends the narrower, PR-scoped link check in
``tests/test_operation_aware_documentation.py`` (which covers only the
Markdown files that PR touched) to every tracked Markdown file in the
repository, using the shared classifier in ``tests/doc_link_helpers.py`` so
the classification/resolution rules are defined exactly once.

Failures are reported per broken link (source file, link text, target,
resolved target) rather than as a single opaque assertion, so a failure is
immediately actionable.

All checks are offline:

- Relative-link resolution and heading-anchor extraction touch only the
  local filesystem.
- Canonical ``github.com`` links are validated structurally only (scheme,
  host, organization, known repository, ``blob``/``tree`` + ref shape) --
  never a network request.
- Cross-repository (BASIS sibling) links are additionally verified against a
  mounted sibling checkout when one is available in this sandbox; when it is
  not (the normal case in GitHub Actions, which checks out only this
  repository), the test reports the link as "not locally verifiable"
  instead of failing -- see ``test_cross_repository_links_verified_when_sibling_available``.
- No network call, git clone, or GitHub API request is made anywhere in this
  module.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from doc_link_helpers import (
    REPO_ROOT,
    THIS_REPO,
    LinkRecord,
    all_markdown_files,
    classify_link,
    evaluate_links_in_file,
    git_ref_has_path,
    github_link_parts,
    heading_anchors,
    image_targets,
    is_valid_canonical_github_link,
    link_targets,
    read,
    resolve_relative_link,
    sibling_repo_path,
)

ALL_MARKDOWN_FILES = all_markdown_files()


# ---------------------------------------------------------------------------
# Sanity: the inventory itself
# ---------------------------------------------------------------------------


def test_markdown_inventory_is_non_empty_and_covers_known_files() -> None:
    rel = {str(p.relative_to(REPO_ROOT)) for p in ALL_MARKDOWN_FILES}
    for expected in (
        "README.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "docs/releases/v0.1.0.md",
        "docs/releases/v0.2.0.md",
        "demo/operation-aware/README.md",
        ".github/pull_request_template.md",
    ):
        assert expected in rel, f"expected {expected!r} in the Markdown inventory"


def test_markdown_inventory_excludes_caches_and_build_output() -> None:
    rel = {str(p.relative_to(REPO_ROOT)) for p in ALL_MARKDOWN_FILES}
    assert not any(part.startswith(".pytest_cache") for part in rel)
    assert not any(part.startswith(".venv") for part in rel)
    assert not any(part.startswith("dist/") for part in rel)
    assert not any(part.startswith("build/") for part in rel)


# ---------------------------------------------------------------------------
# Full-repository link sweep, one parametrized case per file so a failure
# names the exact file (and, via the assertion message, the exact link).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "doc_path", ALL_MARKDOWN_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT))
)
def test_all_links_in_file_are_valid(doc_path: Path) -> None:
    records = evaluate_links_in_file(doc_path)
    broken = [r for r in records if not r.valid]
    assert not broken, "\n".join(
        f"{r.source_file}: broken {r.link_type} link [{r.link_text}]({r.target}) -- {r.detail}"
        for r in broken
    )


@pytest.mark.parametrize(
    "doc_path", ALL_MARKDOWN_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT))
)
def test_all_images_in_file_resolve(doc_path: Path) -> None:
    text = read(doc_path)
    broken = []
    for alt_text, target in image_targets(text):
        if classify_link(target) != "relative":
            continue
        resolved = resolve_relative_link(doc_path, target)
        if not resolved.exists():
            broken.append((alt_text, target))
    assert not broken, f"{doc_path.relative_to(REPO_ROOT)}: broken image reference(s): {broken}"


# ---------------------------------------------------------------------------
# Cross-repository (BASIS sibling) link verification against a mounted
# checkout, when available. Never required, never network-dependent.
# ---------------------------------------------------------------------------


def _all_cross_repo_github_links() -> list[tuple[str, str, str, str, str]]:
    """(source_file, target, repo, ref, path) for every canonical GitHub
    link that points at a *different* BASIS repository than this one."""
    found = []
    for doc_path in ALL_MARKDOWN_FILES:
        rel = str(doc_path.relative_to(REPO_ROOT))
        for _, target in link_targets(read(doc_path)):
            if "github.com" not in target:
                continue
            parts = github_link_parts(target)
            if parts is None:
                continue
            repo, ref, path = parts
            if repo == THIS_REPO:
                continue
            found.append((rel, target, repo, ref, path))
    return found


def test_cross_repository_links_verified_when_sibling_available() -> None:
    cross_repo_links = _all_cross_repo_github_links()
    missing = []
    unverifiable = []
    for source_file, target, repo, ref, path in cross_repo_links:
        sibling = sibling_repo_path(repo)
        if sibling is None:
            unverifiable.append(target)
            continue
        exists = git_ref_has_path(sibling, ref, path)
        if exists is None:
            unverifiable.append(target)
        elif not exists:
            missing.append(f"{source_file}: {target}")
    assert not missing, f"cross-repository link target(s) not found in sibling checkout: {missing}"
    # A sibling repository not being mounted (the normal case in CI, which
    # checks out only this repository) is expected and not a failure --
    # this assertion exists so a run *with* every sibling mounted still
    # proves something rather than silently skipping all of them.
    if not unverifiable:
        assert cross_repo_links, "expected at least one cross-repository link to check"


# ---------------------------------------------------------------------------
# Required regression cases (offline, deterministic, using tmp_path so they
# do not depend on any real repository content)
# ---------------------------------------------------------------------------


def test_valid_local_relative_file_link(tmp_path: Path) -> None:
    doc = tmp_path / "docs" / "guide.md"
    doc.parent.mkdir(parents=True)
    (tmp_path / "docs" / "other.md").write_text("content", encoding="utf-8")
    doc.write_text("[link](other.md)", encoding="utf-8")
    records = _evaluate_outside_repo(doc)
    assert records and records[0].valid


def _evaluate_outside_repo(doc_path: Path) -> list[LinkRecord]:
    """A tmp_path-rooted equivalent of evaluate_links_in_file for regression
    tests that must not depend on being inside REPO_ROOT."""
    from doc_link_helpers import (
        classify_link as _classify,
    )
    from doc_link_helpers import (
        heading_anchors as _anchors,
    )
    from doc_link_helpers import (
        link_targets as _targets,
    )
    from doc_link_helpers import (
        read as _read,
    )
    from doc_link_helpers import (
        resolve_relative_link as _resolve,
    )
    from doc_link_helpers import (
        strip_query_and_fragment as _strip,
    )

    text = _read(doc_path)
    records = []
    for link_text, target in _targets(text):
        kind = _classify(target)
        if kind == "relative":
            path_only = _strip(target)
            resolved = _resolve(doc_path, path_only)
            exists = resolved.exists()
            records.append(
                LinkRecord(str(doc_path), link_text, target, kind, str(resolved), exists)
            )
        elif kind == "fragment":
            frag = target[1:]
            valid = frag in _anchors(doc_path)
            records.append(LinkRecord(str(doc_path), link_text, target, kind, None, valid))
    return records


def test_broken_local_relative_file_link(tmp_path: Path) -> None:
    doc = tmp_path / "docs" / "guide.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("[link](does-not-exist.md)", encoding="utf-8")
    records = _evaluate_outside_repo(doc)
    assert records and not records[0].valid


def test_valid_local_file_with_fragment(tmp_path: Path) -> None:
    doc = tmp_path / "docs" / "guide.md"
    doc.parent.mkdir(parents=True)
    (tmp_path / "README.md").write_text("# Title\n\n## Current Limitations\n", encoding="utf-8")
    doc.write_text("[link](../README.md#current-limitations)", encoding="utf-8")
    resolved = resolve_relative_link(doc, "../README.md")
    assert resolved.exists()
    assert "current-limitations" in heading_anchors(resolved)


def test_missing_local_anchor(tmp_path: Path) -> None:
    target = tmp_path / "README.md"
    target.write_text("# Title\n\n## Something Else\n", encoding="utf-8")
    assert "current-limitations" not in heading_anchors(target)


def test_valid_same_document_anchor(tmp_path: Path) -> None:
    doc = tmp_path / "guide.md"
    doc.write_text(
        "# Guide\n\n## Configuration\n\nSee [above](#configuration).\n", encoding="utf-8"
    )
    assert "configuration" in heading_anchors(doc)


def test_malformed_github_url_rejected() -> None:
    assert not is_valid_canonical_github_link("https://github.com/basis-foundation")
    assert not is_valid_canonical_github_link("not-even-a-url")
    assert not is_valid_canonical_github_link(
        "https://github.com/basis-foundation/basis-core/branch/main/README.md"
    )


def test_wrong_organization_rejected() -> None:
    assert not is_valid_canonical_github_link(
        "https://github.com/some-other-org/basis-core/blob/main/README.md"
    )


def test_wrong_repository_rejected() -> None:
    assert not is_valid_canonical_github_link(
        "https://github.com/basis-foundation/not-a-basis-repo/blob/main/README.md"
    )


def test_release_link_using_nonexistent_tag_flagged_by_git_verification() -> None:
    exists = git_ref_has_path(REPO_ROOT, "v9.9.9-does-not-exist", "README.md")
    assert exists is None or exists is False


def test_tag_pinned_target_absent_from_tag_detected() -> None:
    # tests/doc_link_helpers.py itself did not exist at the v0.1.0 tag.
    exists = git_ref_has_path(REPO_ROOT, "v0.1.0", "tests/doc_link_helpers.py")
    assert exists is False


def test_tag_pinned_target_present_at_tag_detected() -> None:
    exists = git_ref_has_path(REPO_ROOT, "v0.2.0", "README.md")
    assert exists is True


def test_prohibited_sibling_filesystem_markdown_link_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    repo = workspace / "basis-gateway"
    sibling = workspace / "basis-core"
    (repo / "docs").mkdir(parents=True)
    sibling.mkdir(parents=True)
    (sibling / "README.md").write_text("sibling content", encoding="utf-8")
    doc = repo / "docs" / "guide.md"
    doc.write_text("[sibling](../../basis-core/README.md)", encoding="utf-8")

    import doc_link_helpers as helpers

    monkeypatch.setattr(helpers, "REPO_ROOT", repo)
    records = helpers.evaluate_links_in_file(doc)

    assert records
    assert records[0].link_type == "sibling-filesystem"
    assert not records[0].valid


def test_canonical_external_github_link_not_treated_as_local_path() -> None:
    url = "https://github.com/basis-foundation/basis-core/blob/main/docs/public-api.md"
    assert classify_link(url) == "external"
    assert is_valid_canonical_github_link(url)


def test_no_network_calls_during_normal_test_run() -> None:
    """Guards against a regression reintroducing a real network dependency
    into this module. Forbidden tokens are assembled from parts so this
    test's own literal list does not trip its own assertion."""
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden_tokens = [
        "requests" + "." + "get",
        "httpx" + "." + "get",
        "urllib" + "." + "request",
        "socket" + "." + "connect",
    ]
    lines = source.splitlines()
    this_function_start = next(
        i
        for i, line in enumerate(lines)
        if "def test_no_network_calls_during_normal_test_run" in line
    )
    source_excluding_self = "\n".join(lines[:this_function_start])
    for forbidden in forbidden_tokens:
        assert forbidden not in source_excluding_self, (
            f"documentation link tests must stay network-free; found {forbidden!r}"
        )


def test_mailto_scheme_accepted() -> None:
    assert classify_link("mailto:security@example.com") == "mailto"


def test_unsafe_schemes_rejected() -> None:
    for scheme_target in ("file:///etc/passwd", "javascript:alert(1)", "data:text/html,x"):
        assert classify_link(scheme_target) == "unsafe-scheme"


def test_repository_contains_no_unsafe_scheme_links() -> None:
    offenders = [r for r in _all_records() if r.link_type == "unsafe-scheme"]
    assert not offenders, f"unsafe URL scheme link(s) found: {offenders}"


def _all_records() -> list[LinkRecord]:
    records: list[LinkRecord] = []
    for doc_path in ALL_MARKDOWN_FILES:
        records.extend(evaluate_links_in_file(doc_path))
    return records
