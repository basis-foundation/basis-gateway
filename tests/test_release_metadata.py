"""Release-metadata checks for the v0.2.0 release-preparation PR.

These tests are semantic, not textual: they check that specific facts are stated somewhere in
the relevant document (a version, a variable name, a dependency bound, an unchecked checklist
box) rather than asserting exact paragraph wording, so that future copy-editing of the prose
does not spuriously break the suite.

Companion to ``tests/test_version.py`` (which owns the version-drift guard itself); this module
focuses on the release-notes/changelog/checklist content and the historical-document boundary.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.2.0"

RELEASE_NOTES = REPO_ROOT / "docs" / "releases" / "v0.2.0.md"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
README = REPO_ROOT / "README.md"
RELEASE_CHECKLIST = REPO_ROOT / "docs" / "release-checklist.md"
V010_NOTES = REPO_ROOT / "docs" / "releases" / "v0.1.0.md"

_DATE_RE = re.compile(r"##\s*\[0\.2\.0\]\s*-\s*(\d{4}-\d{2}-\d{2})")


def _read(path: Path) -> str:
    assert path.exists(), f"expected file to exist: {path.relative_to(REPO_ROOT)}"
    return path.read_text(encoding="utf-8")


# 1 & 2 — package version matches pyproject.toml, and is the expected release version.
# (Full coverage lives in tests/test_version.py; repeated narrowly here as release-metadata
# context so this module is self-contained for a reviewer reading only this file.)


def test_package_version_is_expected_release_version() -> None:
    import basis_gateway

    assert basis_gateway.__version__ == EXPECTED_VERSION


def test_expected_release_version_selected() -> None:
    assert EXPECTED_VERSION == "0.2.0"


# 3 — release notes exist for that version.


def test_release_notes_exist_for_release_version() -> None:
    assert RELEASE_NOTES.exists()


# 4 — changelog contains the version.


def test_changelog_contains_release_version() -> None:
    text = _read(CHANGELOG)
    assert f"[{EXPECTED_VERSION}]" in text


# 5 — changelog date is valid.


def test_changelog_release_date_is_valid() -> None:
    text = _read(CHANGELOG)
    match = _DATE_RE.search(text)
    assert match is not None, "could not find a dated ## [0.2.0] - YYYY-MM-DD heading"
    date_str = match.group(1)
    import datetime

    # Raises ValueError (failing the test) if not a real calendar date.
    datetime.date.fromisoformat(date_str)


# 6 — README links to the release notes.


def test_readme_links_to_release_notes() -> None:
    text = _read(README)
    assert "docs/releases/v0.2.0.md" in text


# 7 — release notes mention both endpoints.


def test_release_notes_mention_both_endpoints() -> None:
    text = _read(RELEASE_NOTES)
    assert "/v1/evaluate" in text
    assert "/v1/evaluate/operation-aware" in text


# 8 — release notes state operation-aware is disabled by default.


def test_release_notes_state_operation_aware_disabled_by_default() -> None:
    text = _read(RELEASE_NOTES)
    assert re.search(r"disabled by default", text, re.IGNORECASE)
    assert "OPERATION_AWARE_ENABLED" in text


# 9 — release notes state /v1/evaluate remains supported.


def test_release_notes_state_v01_endpoint_remains_supported() -> None:
    text = _read(RELEASE_NOTES)
    assert re.search(r"/v1/evaluate.{0,80}remains supported", text, re.DOTALL)


# 10 — release notes state the required basis-core dependency floor.


def test_release_notes_state_basis_core_dependency_floor() -> None:
    text = _read(RELEASE_NOTES)
    assert "basis-core>=0.2.1,<0.3.0" in text or ">=0.2.1,<0.3.0" in text


# 11 — release notes include known limitations.


def test_release_notes_include_known_limitations() -> None:
    text = _read(RELEASE_NOTES)
    assert re.search(r"^##\s*Known limitations", text, re.MULTILINE)


# 12, 13, 14 — release notes do not claim production readiness, device execution, or
# completed console integration.
#
# These check for an *affirmative* (non-negated) claim only: the release notes are expected to
# explicitly say what they do NOT claim (e.g. "does not confirm device execution"), so a bare
# substring/regex match would false-positive on the negation itself. Each check requires that no
# occurrence of the claim phrase appears without a negation word shortly before it.

_NEGATION_WINDOW = 20


def _has_unnegated_match(text: str, pattern: str) -> bool:
    negation_re = re.compile(r"\b(not|no|never|n't|without)\b", re.IGNORECASE)
    for match in re.finditer(pattern, text, re.IGNORECASE | re.DOTALL):
        preceding = text[max(0, match.start() - _NEGATION_WINDOW) : match.start()]
        if not negation_re.search(preceding):
            return True
    return False


def test_release_notes_do_not_claim_production_readiness() -> None:
    text = _read(RELEASE_NOTES)
    assert not _has_unnegated_match(text, r"production[- ]ready")
    assert not _has_unnegated_match(text, r"production[- ]certifi")


def test_release_notes_do_not_claim_device_execution_confirmed() -> None:
    text = _read(RELEASE_NOTES)
    assert "No adapter execution confirmation" in text
    assert not _has_unnegated_match(
        text, r"confirms?\s+(that\s+)?(a\s+)?(physical\s+)?device\s+execut"
    )


def test_release_notes_do_not_claim_console_integration_complete() -> None:
    text = _read(RELEASE_NOTES)
    assert re.search(r"not\s+implemented\s+in\s+this\s+repository", text)
    assert not _has_unnegated_match(text, r"console.{0,40}(integration|UI).{0,40}complete")


# 15 — release checklist leaves tag/publication steps incomplete.


def test_release_checklist_leaves_tag_and_publish_steps_incomplete() -> None:
    text = _read(RELEASE_CHECKLIST)
    post_merge_marker = "### Performed only after merge"
    assert post_merge_marker in text
    post_merge_section = text.split(post_merge_marker, 1)[1]
    # Stop at the next top-level heading so we only inspect this section.
    post_merge_section = post_merge_section.split("\n## ", 1)[0]
    checked_boxes = re.findall(r"- \[x\]", post_merge_section, re.IGNORECASE)
    assert not checked_boxes, "post-merge release steps must remain unchecked"
    assert "- [ ]" in post_merge_section


# 16 — no stale current-state 0.1.0 claim remains outside historical documents.
# (Covered exhaustively in tests/test_version.py, which owns the general check across every
# current-state document; re-asserted here narrowly for README as the highest-traffic one.)


def test_readme_does_not_claim_current_version_is_0_1_0() -> None:
    text = _read(README)
    assert not re.search(r"is released as v0\.1\.0 and is intended", text)


# 17 — historical v0.1.0 release notes remain unchanged and valid.


def test_historical_v010_release_notes_remain_valid() -> None:
    text = _read(V010_NOTES)
    assert "# basis-gateway v0.1.0 Release Notes" in text
    assert "**Release date:**" in text
    assert "0.2.0" not in text


# 18 — no release artifact is committed unless policy requires it.


def test_no_dist_or_build_artifacts_are_tracked_in_git() -> None:
    result = subprocess.run(
        ["git", "ls-files", "dist", "build"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    tracked = [line for line in result.stdout.splitlines() if line.strip()]
    assert tracked == [], f"unexpected tracked release artifacts: {tracked}"


def test_gitignore_covers_dist_and_build() -> None:
    gitignore = _read(REPO_ROOT / ".gitignore")
    assert "dist/" in gitignore
    assert "build/" in gitignore
