"""Unit-level regression coverage for the tag/ref-availability diagnostic.

``tests/doc_link_helpers.py``'s ``verify_paths_at_ref`` (used by
``tests/test_release_documentation_links.py``) must distinguish "the
referenced release tag does not resolve in this checkout" (a CI checkout-
configuration problem -- GitHub Actions' default shallow, tagless checkout)
from "the tag resolves, but this specific file is missing at it" (a real
content defect). Getting this wrong is exactly what broke every Python
matrix job: a checkout without ``fetch-depth: 0`` / ``fetch-tags: true``
made every single tag-pinned link in the release notes look like a broken
file reference, when the real cause was that no tag existed to check
against at all.

These are unit-level tests against small, disposable, local-only git
repositories built with a subprocess ``git init``/``commit``/``tag`` --
never against this repository's own real tags (those are covered
separately, at the integration level, by
``tests/test_release_documentation_links.py``, which is free to depend on
this checkout's real ``v0.1.0``/``v0.2.0`` tags) and never over the network.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from doc_link_helpers import (
    describe_unavailable_ref,
    git_ref_exists,
    verify_paths_at_ref,
)


def _run_git(repo_dir: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603
        ["git", *args],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def tiny_tagged_repo(tmp_path: Path) -> Path:
    """A small local git repository, fully offline, with one commit tagged
    ``v1.0.0`` containing ``docs/example.md`` (and no other tag)."""
    repo = tmp_path / "tiny-repo"
    repo.mkdir()
    _run_git(repo, "init", "-q")
    _run_git(repo, "config", "user.email", "test@example.invalid")
    _run_git(repo, "config", "user.name", "Test")
    (repo / "docs").mkdir()
    (repo / "docs" / "example.md").write_text("# Example\n", encoding="utf-8")
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-q", "-m", "initial commit")
    _run_git(repo, "tag", "v1.0.0")
    return repo


# ---------------------------------------------------------------------------
# 1 — an available tag with an existing path passes
# ---------------------------------------------------------------------------


def test_available_tag_with_existing_path_passes(tiny_tagged_repo: Path) -> None:
    result = verify_paths_at_ref(tiny_tagged_repo, "v1.0.0", ["docs/example.md"])
    assert result.ref_available is True
    assert not result.ref_unavailable
    assert not result.ref_undeterminable
    assert result.missing_paths == ()
    assert result.checked_paths == ("docs/example.md",)


# ---------------------------------------------------------------------------
# 2 — an available tag with a missing path fails as a missing target
# ---------------------------------------------------------------------------


def test_available_tag_with_missing_path_fails_as_missing_target(tiny_tagged_repo: Path) -> None:
    result = verify_paths_at_ref(tiny_tagged_repo, "v1.0.0", ["docs/does-not-exist.md"])
    assert result.ref_available is True
    assert not result.ref_unavailable, "a resolvable ref with a missing file is not 'unavailable'"
    assert result.missing_paths == ("docs/does-not-exist.md",)


def test_available_tag_with_mixed_paths_reports_only_the_missing_one(
    tiny_tagged_repo: Path,
) -> None:
    result = verify_paths_at_ref(
        tiny_tagged_repo, "v1.0.0", ["docs/example.md", "docs/does-not-exist.md"]
    )
    assert result.ref_available is True
    assert result.missing_paths == ("docs/does-not-exist.md",)
    assert "docs/example.md" not in result.missing_paths


# ---------------------------------------------------------------------------
# 3 — an unavailable tag fails with the checkout/history diagnostic
# ---------------------------------------------------------------------------


def test_unavailable_tag_reported_as_ref_unavailable(tiny_tagged_repo: Path) -> None:
    result = verify_paths_at_ref(tiny_tagged_repo, "v9.9.9-never-tagged", ["docs/example.md"])
    assert result.ref_available is False
    assert result.ref_unavailable
    assert not result.ref_undeterminable


def test_unavailable_ref_diagnostic_message_is_actionable() -> None:
    message = describe_unavailable_ref("v0.2.0")
    assert "v0.2.0" in message
    assert "fetch" in message.lower()
    assert "fetch-depth" in message or "fetch-depth: 0" in message


# ---------------------------------------------------------------------------
# 4 — the unavailable-tag diagnostic does not list every path as though each
#     were independently absent
# ---------------------------------------------------------------------------


def test_unavailable_tag_does_not_enumerate_paths_as_individually_missing(
    tiny_tagged_repo: Path,
) -> None:
    many_paths = [f"docs/file-{i}.md" for i in range(25)]
    result = verify_paths_at_ref(tiny_tagged_repo, "v9.9.9-never-tagged", many_paths)
    # The whole point: when the ref itself can't be resolved, no individual
    # path is checked (and therefore none can be reported as "missing") --
    # there is exactly one fact to report ("ref unavailable"), not 25.
    assert result.checked_paths == ()
    assert result.missing_paths == ()
    assert result.ref_unavailable


# ---------------------------------------------------------------------------
# 5 — no network access is attempted
# ---------------------------------------------------------------------------

_NETWORK_ARG_TOKENS = ("http://", "https://", "git://", "ssh://", "clone", "fetch", "pull", "push")


def test_ref_verification_never_invokes_a_network_capable_git_subcommand(
    tiny_tagged_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_commands: list[list[str]] = []
    real_run = subprocess.run

    def _spying_run(cmd, *args, **kwargs):  # type: ignore[no-untyped-def]
        observed_commands.append(list(cmd))
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", _spying_run)

    verify_paths_at_ref(tiny_tagged_repo, "v1.0.0", ["docs/example.md"])
    verify_paths_at_ref(tiny_tagged_repo, "v9.9.9-never-tagged", ["docs/example.md"])

    assert observed_commands, "expected at least one git invocation to be observed"
    for command in observed_commands:
        joined = " ".join(command)
        for token in _NETWORK_ARG_TOKENS:
            assert token not in joined, f"unexpected network-capable git invocation: {command}"
        assert command[:2] == ["git", "rev-parse"] or command[:2] == ["git", "cat-file"], (
            f"unexpected git subcommand invoked during ref/path verification: {command}"
        )


# ---------------------------------------------------------------------------
# 6 — no fallback to main occurs
# ---------------------------------------------------------------------------


def test_unresolvable_ref_is_never_silently_replaced_with_main(
    tiny_tagged_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_refs: list[str] = []
    real_run = subprocess.run

    def _spying_run(cmd, *args, **kwargs):  # type: ignore[no-untyped-def]
        if len(cmd) >= 2 and cmd[0] == "git" and cmd[1] == "rev-parse":
            # cmd looks like ["git", "rev-parse", "--verify", "--quiet", "<ref>^{commit}"]
            observed_refs.append(cmd[-1])
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", _spying_run)

    result = git_ref_exists(tiny_tagged_repo, "v9.9.9-never-tagged")

    assert result is False
    assert observed_refs, "expected a rev-parse invocation to be observed"
    for ref_arg in observed_refs:
        assert ref_arg.startswith("v9.9.9-never-tagged"), (
            f"ref verification substituted an unexpected ref: {ref_arg!r}"
        )
        assert not ref_arg.startswith("main"), "unavailable ref must never fall back to 'main'"


def test_missing_path_lookup_uses_the_requested_ref_not_main(
    tiny_tagged_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_specs: list[str] = []
    real_run = subprocess.run

    def _spying_run(cmd, *args, **kwargs):  # type: ignore[no-untyped-def]
        if len(cmd) >= 2 and cmd[0] == "git" and cmd[1] == "cat-file":
            observed_specs.append(cmd[-1])
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", _spying_run)

    verify_paths_at_ref(tiny_tagged_repo, "v1.0.0", ["docs/does-not-exist.md"])

    assert observed_specs == ["v1.0.0:docs/does-not-exist.md"]
