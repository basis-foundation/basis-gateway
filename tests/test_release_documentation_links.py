"""Release-note portability tests.

GitHub renders a Release description's relative Markdown links against
``/releases/tag/<tag>``, not against the repository tree. A same-repository
relative link that resolves correctly when ``docs/releases/v0.2.0.md`` is
read in this repository (e.g. on GitHub's normal blob view, or by a clone)
is therefore silently broken once the same text is pasted into
https://github.com/basis-foundation/basis-gateway/releases/tag/v0.2.0 -- the
defect this sweep exists to fix. These tests prove the two release-note
source files are portable: every repository-document link in them is an
absolute, tag-pinned GitHub URL that resolves correctly regardless of which
context renders the file.

Companion to ``tests/test_release_metadata.py`` (release-metadata content
checks) and ``tests/test_version.py`` (version-drift guard); this module is
link- and portability-focused only. Shared classification/resolution logic
lives in ``tests/doc_link_helpers.py``.

All checks are offline. Tag-pinned local-target verification uses
``git cat-file -e <tag>:<path>`` against this repository's own local git
history -- never a network request.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from doc_link_helpers import (
    REPO_ROOT,
    THIS_REPO,
    evaluate_links_in_file,
    git_ref_has_path,
    github_link_parts,
    link_targets,
    read,
)

V010 = REPO_ROOT / "docs" / "releases" / "v0.1.0.md"
V020 = REPO_ROOT / "docs" / "releases" / "v0.2.0.md"
RELEASE_NOTES = [V010, V020]
RELEASE_TAG_FOR = {V010: "v0.1.0", V020: "v0.2.0"}

_LOCAL_PATH_RE = re.compile(r"(?:^|[\s(`\"'])(/Users/[^\s)`\"']+|/home/[^\s)`\"']+)")


# ---------------------------------------------------------------------------
# 1 & 2 — release files exist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", RELEASE_NOTES, ids=lambda p: p.name)
def test_release_notes_file_exists(path: Path) -> None:
    assert path.exists(), f"expected release notes file missing: {path.relative_to(REPO_ROOT)}"


# ---------------------------------------------------------------------------
# 3 — no repository-relative Markdown navigation links in either release file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", RELEASE_NOTES, ids=lambda p: p.name)
def test_release_notes_contain_no_repository_relative_navigation_links(path: Path) -> None:
    text = read(path)
    offending = [target for _, target in link_targets(text) if _looks_relative(target)]
    assert not offending, (
        f"{path.relative_to(REPO_ROOT)} contains repository-relative navigation link(s) that "
        f"will not resolve when pasted into a GitHub Release description: {offending}"
    )


def _looks_relative(target: str) -> bool:
    if target.startswith("#"):
        return False
    return "://" not in target and not target.startswith("mailto:")


# ---------------------------------------------------------------------------
# 4 — tag-pinned basis-gateway links use the release tag matching the file
#     they appear in
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", RELEASE_NOTES, ids=lambda p: p.name)
def test_tag_pinned_basis_gateway_links_use_a_real_release_tag(path: Path) -> None:
    """Every basis-gateway link in a release-notes file must be pinned to
    either that file's own release tag (the common case) or to another
    basis-gateway release tag that legitimately existed at the time (e.g.
    v0.2.0's notes linking to the historical v0.1.0 release notes at the
    v0.1.0 tag). It must never be pinned to a tag that does not exist."""
    text = read(path)
    known_tags = {RELEASE_TAG_FOR[p] for p in RELEASE_NOTES}
    for _, target in link_targets(text):
        parts = github_link_parts(target)
        if parts is None:
            continue
        repo, ref, _ = parts
        if repo != THIS_REPO:
            continue
        assert ref in known_tags, (
            f"{path.relative_to(REPO_ROOT)}: link to {target!r} is pinned to ref {ref!r}, "
            f"which is not a known basis-gateway release tag {sorted(known_tags)}"
        )


# ---------------------------------------------------------------------------
# 5 — every tag-pinned local target exists at the referenced tag
# ---------------------------------------------------------------------------


def _tag_pinned_basis_gateway_targets(path: Path) -> list[tuple[str, str, str]]:
    text = read(path)
    found = []
    for _, target in link_targets(text):
        parts = github_link_parts(target)
        if parts is None:
            continue
        repo, ref, file_path = parts
        if repo == THIS_REPO and file_path:
            found.append((target, ref, file_path))
    return found


@pytest.mark.parametrize("path", RELEASE_NOTES, ids=lambda p: p.name)
def test_tag_pinned_targets_exist_at_the_referenced_tag(path: Path) -> None:
    missing = []
    not_locally_verifiable = []
    for target, ref, file_path in _tag_pinned_basis_gateway_targets(path):
        exists = git_ref_has_path(REPO_ROOT, ref, file_path)
        if exists is None:
            not_locally_verifiable.append(target)
        elif not exists:
            missing.append(target)
    assert not missing, (
        f"{path.relative_to(REPO_ROOT)}: tag-pinned link target(s) do not exist at their "
        f"referenced tag: {missing}"
    )
    # Not locally verifiable (e.g. git unavailable) is reported, not failed --
    # this suite must stay green in any environment with a working local
    # git binary and this repository's own history, which is the only
    # dependency it actually requires (no sibling checkout, no network).
    if not_locally_verifiable:
        pytest.skip(
            f"could not locally verify tag-pinned target(s) (no git / no local history): "
            f"{not_locally_verifiable}"
        )


# ---------------------------------------------------------------------------
# 6 — no developer-local filesystem paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", RELEASE_NOTES, ids=lambda p: p.name)
def test_release_notes_contain_no_local_filesystem_paths(path: Path) -> None:
    text = read(path)
    matches = _LOCAL_PATH_RE.findall(text)
    assert not matches, (
        f"{path.relative_to(REPO_ROOT)} contains local filesystem path(s): {matches}"
    )


# ---------------------------------------------------------------------------
# 7 — no localhost link presented as public documentation navigation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", RELEASE_NOTES, ids=lambda p: p.name)
def test_release_notes_contain_no_localhost_navigation_links(path: Path) -> None:
    text = read(path)
    localhost_links = [target for _, target in link_targets(text) if "localhost" in target]
    assert not localhost_links, (
        f"{path.relative_to(REPO_ROOT)} contains localhost link(s) presented as navigation: "
        f"{localhost_links}"
    )


# ---------------------------------------------------------------------------
# 8 — no stale "prepared for release" language after publication
# ---------------------------------------------------------------------------

_STALE_PREPARATION_PATTERNS = [
    re.compile(r"prepared for release", re.IGNORECASE),
    re.compile(r"pending publication", re.IGNORECASE),
    re.compile(r"tag.{0,20}have not yet been created", re.IGNORECASE),
    re.compile(r"not yet (been )?tagged", re.IGNORECASE),
    re.compile(r"after this PR merges", re.IGNORECASE),
]


@pytest.mark.parametrize("path", RELEASE_NOTES, ids=lambda p: p.name)
def test_release_notes_contain_no_stale_preparation_language(path: Path) -> None:
    text = read(path)
    for pattern in _STALE_PREPARATION_PATTERNS:
        assert not pattern.search(text), (
            f"{path.relative_to(REPO_ROOT)} still contains stale pre-publication language "
            f"matching {pattern.pattern!r}"
        )


# ---------------------------------------------------------------------------
# 9 — v0.1.0 remains historically scoped
# ---------------------------------------------------------------------------


def test_v010_release_notes_remain_historically_scoped() -> None:
    text = read(V010)
    assert "v0.1.0" in text
    assert "0.2.0" not in text, "v0.1.0 release notes must not reference the later v0.2.0 release"
    assert "**Release date:** 2026-06-08" in text
    assert "**Status:** Initial public release" in text


# ---------------------------------------------------------------------------
# 10 — v0.2.0 identifies itself as published
# ---------------------------------------------------------------------------


def test_v020_release_notes_identify_as_published() -> None:
    text = read(V020)
    assert "**Status:** Published release" in text
    assert "**Release date:** 2026-08-03" in text


# ---------------------------------------------------------------------------
# 11 — no release document claims a tag/release is pending when it already
#      exists
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", RELEASE_NOTES, ids=lambda p: p.name)
def test_release_notes_do_not_claim_own_tag_is_pending(path: Path) -> None:
    text = read(path).lower()
    assert "tag and github release have not yet been created" not in text
    assert "have not yet been created" not in text


# ---------------------------------------------------------------------------
# 12 — no source-branch name appears as current release status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", RELEASE_NOTES, ids=lambda p: p.name)
def test_release_notes_do_not_cite_a_branch_name_as_release_status(path: Path) -> None:
    text = read(path)
    assert "release/v0.2.0-preparation" not in text
    assert "docs/repository-documentation-sweep" not in text


# ---------------------------------------------------------------------------
# 13 — release-note links use HTTPS
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", RELEASE_NOTES, ids=lambda p: p.name)
def test_release_notes_external_links_use_https(path: Path) -> None:
    text = read(path)
    for _, target in link_targets(text):
        if target.startswith("http://"):
            pytest.fail(f"{path.relative_to(REPO_ROOT)}: insecure http:// link: {target}")


# ---------------------------------------------------------------------------
# 14 — Related sections contain usable absolute links
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", RELEASE_NOTES, ids=lambda p: p.name)
def test_related_section_links_are_absolute(path: Path) -> None:
    text = read(path)
    marker = "## Related"
    assert marker in text, f"{path.relative_to(REPO_ROOT)} is missing a 'Related' section"
    related_section = text[text.index(marker) :]
    targets = [target for _, target in link_targets(related_section)]
    assert targets, f"{path.relative_to(REPO_ROOT)}'s Related section has no links"
    for target in targets:
        assert "://" in target, (
            f"{path.relative_to(REPO_ROOT)}: Related section link {target!r} is not an absolute URL"
        )


# ---------------------------------------------------------------------------
# 15 — file and heading anchors are valid where they can be validated locally
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", RELEASE_NOTES, ids=lambda p: p.name)
def test_release_notes_links_all_valid(path: Path) -> None:
    records = evaluate_links_in_file(path)
    broken = [r for r in records if not r.valid]
    assert not broken, f"{path.relative_to(REPO_ROOT)}: broken link(s): {broken}"
