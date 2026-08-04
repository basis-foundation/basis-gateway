"""Version-drift guard for the v0.2.0 release preparation.

Verifies that every authoritative version declaration in the repository
agrees, is valid SemVer syntax, and is exactly the release version selected
by repository policy (``0.2.0`` — see ``docs/releases/v0.2.0.md`` and the
version-decision rationale in this release-preparation PR's completion
report). Also verifies that no current-state documentation still identifies
the package as being at ``0.1.0`` (historical documents, such as
``docs/releases/v0.1.0.md``, are explicitly exempt).
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# ``tomllib`` is stdlib only from Python 3.11+; this repository supports
# Python 3.10 (``requires-python = ">=3.10"``), and adding a ``tomli``
# dependency for a single test is out of scope for this release-preparation
# PR (no new dependencies). A narrow regex extraction of the ``[project]``
# table's ``version`` key is sufficient here and avoids a full TOML parser.
_PYPROJECT_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)

EXPECTED_VERSION = "0.2.0"

# Files that legitimately reference "0.1.0" as a historical fact (the prior
# release), a compatibility/dependency example, or a point-in-time record.
# Anything under these paths is not a "current-state" claim and is exempt
# from the stale-version check below.
HISTORICAL_EXEMPT_PATHS = {
    REPO_ROOT / "docs" / "releases" / "v0.1.0.md",
    REPO_ROOT / "docs" / "release-candidate-assessment.md",
    REPO_ROOT / "CHANGELOG.md",
}

# Doc files that are current-state (not historical) and therefore must not
# assert the package is at 0.1.0 anymore.
CURRENT_STATE_DOCS = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "docs" / "release-readiness.md",
]

_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?"
    r"(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$"
)


def _pyproject_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = _PYPROJECT_VERSION_RE.search(text)
    assert match is not None, 'could not find version = "..." in pyproject.toml [project] table'
    return match.group(1)


def _package_version() -> str:
    import basis_gateway

    return basis_gateway.__version__


def test_pyproject_version_parses() -> None:
    version = _pyproject_version()
    assert version, "pyproject.toml [project].version must be non-empty"


def test_package_version_attribute_exists() -> None:
    import basis_gateway

    assert hasattr(basis_gateway, "__version__")


def test_package_and_pyproject_versions_match() -> None:
    assert _package_version() == _pyproject_version()


def test_version_is_valid_semver() -> None:
    version = _package_version()
    assert _SEMVER_RE.match(version), f"{version!r} is not valid SemVer syntax"


def test_version_matches_repository_selected_release_version() -> None:
    assert _package_version() == EXPECTED_VERSION
    assert _pyproject_version() == EXPECTED_VERSION


def test_fastapi_app_openapi_version_matches_package_version() -> None:
    """The FastAPI app's OpenAPI ``version`` (visible at ``/openapi.json`` and ``/docs``) is a
    fourth authoritative version declaration beyond pyproject.toml/__init__.py — it must track
    the package version, not a separately hardcoded string, or API consumers see stale metadata.
    """
    from basis_gateway.main import create_app

    app = create_app()
    assert app.version == _package_version()


def test_no_current_state_documentation_claims_version_0_1_0() -> None:
    """Current-state docs must not still say the package IS 0.1.0.

    This is a narrow, semantic check: it looks for the specific "current
    version" phrasing patterns these docs use, not every incidental
    substring "0.1.0" (e.g. a dependency floor example naming a different
    package's 0.1.0 is fine).
    """
    stale_patterns = [
        re.compile(r"\bv0\.1\.0\b.{0,40}\bcurrent\b", re.IGNORECASE),
        re.compile(r"\bcurrent(ly)?\b.{0,40}\bv0\.1\.0\b", re.IGNORECASE),
        re.compile(r"^\s*\*\*Status:\*\*\s*current", re.IGNORECASE | re.MULTILINE),
    ]
    for doc_path in CURRENT_STATE_DOCS:
        if not doc_path.exists():
            continue
        text = doc_path.read_text(encoding="utf-8")
        for pattern in stale_patterns:
            assert not pattern.search(text), (
                f"{doc_path.relative_to(REPO_ROOT)} appears to still claim "
                f"the package is currently at 0.1.0 (matched {pattern.pattern!r})"
            )


def test_historical_release_notes_still_say_0_1_0() -> None:
    """The v0.1.0 release notes are a point-in-time document and must not be rewritten."""
    v010_notes = REPO_ROOT / "docs" / "releases" / "v0.1.0.md"
    assert v010_notes.exists()
    text = v010_notes.read_text(encoding="utf-8")
    assert "v0.1.0" in text
    assert "0.2.0" not in text
