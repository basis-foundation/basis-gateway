"""Shared Markdown documentation-link validation helpers.

This module is importable as ``from doc_link_helpers import ...`` from any
test file because pytest adds the ``tests/`` directory to sys.path when
``tests/`` has no ``__init__.py`` (importmode=prepend, the default) -- see
``tests/helpers.py`` for the existing precedent this follows.

Used by ``tests/test_release_documentation_links.py`` (release-note
portability checks) and ``tests/test_full_repository_documentation_links.py``
(repository-wide link sweep), so link classification, relative-link
resolution, GitHub-URL structural validation, and heading-anchor resolution
are each defined exactly once rather than duplicated across test modules.

Two rendering contexts, one classifier
---------------------------------------
Repository-rendered Markdown (README.md, docs/*.md, ...) resolves a
same-repository relative link against the file that contains it -- normal
GitHub blob rendering. Release-rendered Markdown (docs/releases/*.md, once
pasted into a GitHub Release description) resolves relative links against
``/releases/tag/<tag>`` instead, so a same-repository relative link that
works in the first context is silently broken in the second. This module
does not special-case *which* context a file belongs to -- callers decide
that (see ``tests/test_release_documentation_links.py``, which forbids
repository-relative navigation links specifically in the two release-note
files) -- it only classifies and resolves link targets correctly for
whichever context is being checked.

Everything here is offline and deterministic:

- Relative-link resolution and heading-anchor extraction touch only the
  local filesystem.
- ``is_valid_canonical_github_link`` performs *structural* validation only
  (scheme/host/org/repo/ref shape) -- it never makes a network request.
- ``git_ref_has_path`` and ``sibling_repo_path`` shell out to a local ``git``
  invocation against an already-checked-out repository (this one, or a
  sibling BASIS repository mounted alongside it) -- a local object-database
  lookup, never a network fetch. Both return ``None`` (never raise) when the
  answer cannot be determined locally (git missing, ref unresolvable, sibling
  not checked out), so callers can distinguish "verified false" from "not
  locally verifiable" instead of treating an unavailable sibling checkout as
  a hard failure.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]

THIS_REPO = "basis-gateway"
CANONICAL_GITHUB_ORG = "basis-foundation"
KNOWN_BASIS_REPOS = frozenset(
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

_EXCLUDED_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "node_modules",
        "__pycache__",
    }
)

# Non-image links only -- a leading "!" (image syntax) is excluded via the
# negative lookbehind so image targets are never double-counted as links.
_LINK_RE = re.compile(r"(?<!!)\[([^\]]*)\]\(([^)]+)\)")
_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")

_ALLOWED_URL_SCHEMES = frozenset({"http", "https"})
_ALLOWED_OTHER_SCHEMES = frozenset({"mailto"})
_UNSAFE_SCHEMES = frozenset({"file", "javascript", "data", "vbscript"})


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def all_markdown_files() -> list[Path]:
    """Every Markdown file in the repository, excluding caches/build output.

    Deliberately filesystem-based (``Path.rglob``) rather than ``git
    ls-files``, so this list -- and everything built on it -- has no
    subprocess/git dependency and works identically in a shallow CI checkout.
    """
    files = [
        p
        for p in REPO_ROOT.rglob("*.md")
        if not any(part in _EXCLUDED_DIR_NAMES for part in p.relative_to(REPO_ROOT).parts)
    ]
    return sorted(files)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _strip_code_blocks(text: str) -> str:
    """Drop fenced-code-block lines so link/heading regexes never match
    inside a code example (e.g. ``pip install -e ../basis-core``, which is an
    intentional local-development instruction, not a Markdown hyperlink)."""
    lines = text.splitlines()
    out = []
    in_code = False
    for line in lines:
        if line.strip().startswith("```"):
            in_code = not in_code
            continue
        if not in_code:
            out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Link extraction and classification
# ---------------------------------------------------------------------------


def link_targets(markdown: str) -> list[tuple[str, str]]:
    """(link_text, target) pairs for every non-image Markdown link, skipping
    fenced code blocks."""
    text = _strip_code_blocks(markdown)
    return [(m.group(1), m.group(2)) for m in _LINK_RE.finditer(text) if m.group(2)]


def image_targets(markdown: str) -> list[tuple[str, str]]:
    """(alt_text, target) pairs for every Markdown image, skipping fenced
    code blocks."""
    text = _strip_code_blocks(markdown)
    return [(m.group(1), m.group(2)) for m in _IMAGE_RE.finditer(text) if m.group(2)]


def classify_link(target: str) -> str:
    """Classify a single Markdown link target.

    One of ``"fragment"`` (same-page anchor), ``"external"`` (``http``/
    ``https``), ``"mailto"``, ``"unsafe-scheme"`` (``file:``/``javascript:``/
    ``data:``/``vbscript:`` -- never followed), ``"other-scheme"`` (anything
    else with an explicit scheme), or ``"relative"`` (no scheme -- a
    same-repository filesystem path, query strings and fragments stripped
    before lookup by the caller).
    """
    if target.startswith("#"):
        return "fragment"
    parsed = urlparse(target)
    scheme = parsed.scheme.lower()
    if scheme in _ALLOWED_URL_SCHEMES:
        return "external"
    if scheme in _ALLOWED_OTHER_SCHEMES:
        return "mailto"
    if scheme in _UNSAFE_SCHEMES:
        return "unsafe-scheme"
    if scheme:
        return "other-scheme"
    return "relative"


def strip_query_and_fragment(target: str) -> str:
    return target.split("#", 1)[0].split("?", 1)[0]


def resolve_relative_link(doc_path: Path, target: str) -> Path:
    """Resolve a same-repository relative link (query string/fragment
    already stripped by the caller) against the Markdown file containing
    it."""
    return (doc_path.parent / target).resolve()


def relative_link_escapes_repository(resolved: Path) -> bool:
    """True if a resolved relative-link target falls outside this repository
    checkout entirely (e.g. ``../../basis-core/README.md``) -- a sibling-
    filesystem Markdown link. Such a link may happen to resolve in a local
    sandbox with every BASIS repository checked out side by side, but it is
    not portable: GitHub Actions checks out only this repository, and GitHub
    itself has no notion of a sibling checkout at all. Cross-repository
    references must use an absolute GitHub URL instead."""
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError:
        return True
    return False


# ---------------------------------------------------------------------------
# Canonical GitHub link structural validation (no network request)
# ---------------------------------------------------------------------------


def is_valid_canonical_github_link(url: str) -> bool:
    """Structural-only validation of a ``github.com`` link: scheme, host,
    organization, that the repository segment is a known BASIS repository,
    and -- for a link to a specific file or directory rather than the
    repository root -- that the third segment is ``blob``/``tree`` and a
    (non-empty) ref segment follows. The ref itself is not restricted to
    ``main``: a tag name (``v0.2.0``) is equally valid structurally; whether
    it is the *correct* tag for the document it appears in is a separate,
    semantic check (see ``tag_pinned_ref`` / release-note-specific tests).
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
    if org != CANONICAL_GITHUB_ORG:
        return False
    if repo not in KNOWN_BASIS_REPOS:
        return False
    if len(segments) > 2:
        if segments[2] not in ("blob", "tree"):
            return False
        if len(segments) < 4 or not segments[3]:
            return False
    return True


def github_link_parts(url: str) -> tuple[str, str, str] | None:
    """``(repo, ref, path)`` for a structurally valid ``blob``/``tree`` GitHub
    link, or ``None`` if the link does not point at a specific file/directory
    (e.g. a bare repository-root link) or is not a canonical BASIS link."""
    if not is_valid_canonical_github_link(url):
        return None
    parsed = urlparse(url)
    segments = [segment for segment in parsed.path.split("/") if segment]
    if len(segments) < 4:
        return None
    repo, ref = segments[1], segments[3]
    path = "/".join(segments[4:])
    return repo, ref, path


# ---------------------------------------------------------------------------
# Local, offline git verification (never a network call)
# ---------------------------------------------------------------------------

_SIBLING_REPOS_ROOT = REPO_ROOT.parent


def sibling_repo_path(repo_name: str) -> Path | None:
    """Filesystem path to a mounted sibling BASIS repository, or ``None`` if
    it is not checked out alongside this repository (expected in CI, which
    checks out only this repository)."""
    if repo_name == THIS_REPO:
        return REPO_ROOT
    candidate = _SIBLING_REPOS_ROOT / repo_name
    if (candidate / ".git").exists():
        return candidate
    return None


def git_ref_has_path(repo_dir: Path, ref: str, path: str) -> bool | None:
    """True/False if ``path`` exists at ``ref`` in the local ``repo_dir``
    checkout, or ``None`` if this cannot be determined locally (``git``
    missing, ref not resolvable in this checkout, timeout). Uses
    ``git cat-file -e <ref>:<path>``, a local object-database lookup --
    never a network operation."""
    if not path:
        return None
    try:
        result = subprocess.run(  # noqa: S603
            ["git", "cat-file", "-e", f"{ref}:{path}"],
            cwd=repo_dir,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Heading-anchor resolution (GitHub-compatible slugs)
# ---------------------------------------------------------------------------


def slugify_heading(heading: str) -> str:
    """Approximate GitHub's own Markdown-heading-to-anchor slug algorithm:
    strip inline links/code spans, lowercase, drop punctuation other than
    hyphen/underscore/space, collapse whitespace to hyphens."""
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", heading.strip())
    text = text.replace("`", "")
    text = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"\s+", "-", text.strip())


def heading_anchors(path: Path) -> set[str]:
    """Every valid anchor slug reachable in ``path`` via a fragment link,
    accounting for GitHub's ``-1``, ``-2``, ... suffixing of repeated
    headings."""
    text = read(path)
    lines = text.splitlines()
    in_code = False
    seen: dict[str, int] = {}
    anchors: set[str] = set()
    for line in lines:
        if line.strip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        match = _HEADING_RE.match(line)
        if not match:
            continue
        slug = slugify_heading(match.group(2))
        if not slug:
            continue
        n = seen.get(slug, 0)
        anchors.add(slug if n == 0 else f"{slug}-{n}")
        seen[slug] = n + 1
    return anchors


# ---------------------------------------------------------------------------
# Structured, whole-file link evaluation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LinkRecord:
    """One classified, validated Markdown link (or image)."""

    source_file: str
    link_text: str
    target: str
    link_type: str
    resolved_target: str | None
    valid: bool
    detail: str = ""


def evaluate_links_in_file(doc_path: Path) -> list[LinkRecord]:
    """Structured, offline evaluation of every link in one Markdown file.
    No network access; canonical GitHub links are validated structurally
    only unless the caller separately consults ``git_ref_has_path``."""
    rel = str(doc_path.relative_to(REPO_ROOT))
    text = read(doc_path)
    records: list[LinkRecord] = []

    for link_text, target in link_targets(text):
        kind = classify_link(target)

        if kind == "fragment":
            frag = target[1:]
            valid = frag in heading_anchors(doc_path)
            detail = "" if valid else f"no heading anchor #{frag} in {rel}"
            records.append(LinkRecord(rel, link_text, target, kind, None, valid, detail))

        elif kind == "relative":
            path_only = strip_query_and_fragment(target)
            if not path_only:
                # Fragment-only reached via a scheme-less "#..." is handled
                # above; an empty path with a query string is not a real
                # filesystem reference.
                records.append(LinkRecord(rel, link_text, target, kind, None, True))
                continue
            resolved = resolve_relative_link(doc_path, path_only)
            if relative_link_escapes_repository(resolved):
                records.append(
                    LinkRecord(
                        rel,
                        link_text,
                        target,
                        "sibling-filesystem",
                        str(resolved),
                        False,
                        "relative link escapes the repository root; use an absolute "
                        "GitHub URL for cross-repository references",
                    )
                )
                continue
            exists = resolved.exists()
            valid = exists
            detail = "" if exists else f"broken relative link target {resolved}"
            if exists and "#" in target and resolved.suffix == ".md":
                frag = target.split("#", 1)[1]
                if frag not in heading_anchors(resolved):
                    valid = False
                    detail = f"missing anchor #{frag} in {resolved.relative_to(REPO_ROOT)}"
            records.append(LinkRecord(rel, link_text, target, kind, str(resolved), valid, detail))

        elif kind == "external":
            if "github.com" in target:
                ok = is_valid_canonical_github_link(target)
                detail = "" if ok else "malformed canonical GitHub link"
                records.append(
                    LinkRecord(rel, link_text, target, "external-github", None, ok, detail)
                )
            else:
                records.append(LinkRecord(rel, link_text, target, "external-other", None, True))

        elif kind == "mailto":
            records.append(LinkRecord(rel, link_text, target, kind, None, True))

        elif kind == "unsafe-scheme":
            records.append(
                LinkRecord(rel, link_text, target, kind, None, False, "unsafe URL scheme")
            )

        else:  # other-scheme
            records.append(LinkRecord(rel, link_text, target, kind, None, True))

    return records


def evaluate_repository_links() -> list[LinkRecord]:
    records: list[LinkRecord] = []
    for doc in all_markdown_files():
        records.extend(evaluate_links_in_file(doc))
    return records
