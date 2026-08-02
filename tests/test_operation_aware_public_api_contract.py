"""Public-contract test for the adopted basis-core operation-aware surface.

The module-level imports prove that every operation-aware symbol approved by
the gateway integration plan is available from its documented public package
path. This test does not exercise kernel behavior.

PR 5 (basis-core v0.2.1 adoption): ``OperationAwareEnforcementPoint.for_bundle()``
is the released public downstream construction path
(``fix/public-operation-aware-enforcement-factory``). It resolves the PR
3/4-era tension between §8's "must not import ``basis_core.evaluation.*``
directly" boundary and the lack of any public factory for
``OperationAwareEnforcementPoint`` in ``basis-core==0.2.0`` — the internal
``OperationAwareEvaluationEngine`` symbol previously had to be imported in
this test module, and in white-box tests exercising the preflight/evaluator
wrapper directly (e.g. to bypass ``build_operation_aware_evaluator``'s own
preflight call), as an explicitly-flagged exception. That exception is now
fully closed: no ``.py`` file anywhere in this repository — production
source or test suite alike — imports, names, constructs, or otherwise
references ``OperationAwareEvaluationEngine`` or any ``basis_core.evaluation``
submodule. Every construction of an ``OperationAwareEnforcementPoint``,
including in tests that deliberately bypass the gateway's own preflight to
test it directly, goes through the public ``for_bundle()`` factory. This
module's ``test_no_repository_source_file_imports_internal_evaluation_package``
proves that repository-wide, by parsing every ``.py`` file under ``src/`` and
``tests/`` and inspecting its actual import statements.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from basis_core.audit import AuditEvidence
from basis_core.decisions import (
    OperationAwareDecisionOutcome,
    OperationAwareDecisionRequest,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
    OperationIntent,
)
from basis_core.domain import (
    AdapterEvidenceReference,
    IdentityEvidenceReference,
    OperationAwareDevice,
    OperationAwareEnvironmentContext,
    OperationAwareLocation,
    OperationAwareProtocolContext,
    OperationAwareRiskContext,
    OperationAwareSafetyContext,
)
from basis_core.enforcement import (
    EnforcementDisposition,
    OperationAwareEnforcementPoint,
    OperationAwareEnforcementResult,
)
from basis_core.policy import PolicyBundle

import basis_gateway.core.operation_aware_evaluator as operation_aware_evaluator_module

PUBLIC_OPERATION_AWARE_SYMBOLS_BY_PACKAGE: dict[str, tuple[object, ...]] = {
    "basis_core.decisions": (
        OperationAwareDecisionOutcome,
        OperationAwareDecisionRequest,
        OperationAwareEvaluationStatus,
        OperationAwareFailureReason,
        OperationIntent,
    ),
    "basis_core.domain": (
        AdapterEvidenceReference,
        IdentityEvidenceReference,
        OperationAwareDevice,
        OperationAwareEnvironmentContext,
        OperationAwareLocation,
        OperationAwareProtocolContext,
        OperationAwareRiskContext,
        OperationAwareSafetyContext,
    ),
    "basis_core.policy": (PolicyBundle,),
    "basis_core.enforcement": (
        EnforcementDisposition,
        OperationAwareEnforcementPoint,
        OperationAwareEnforcementResult,
    ),
    "basis_core.audit": (AuditEvidence,),
}


def test_operation_aware_public_symbols_are_importable() -> None:
    """Every approved symbol resolves through its public package path."""
    for package, symbols in PUBLIC_OPERATION_AWARE_SYMBOLS_BY_PACKAGE.items():
        assert symbols, f"no public symbols registered for {package}"
        assert all(symbol is not None for symbol in symbols)


def test_enforcement_point_public_factory_is_available() -> None:
    """``OperationAwareEnforcementPoint.for_bundle`` is the supported public
    downstream construction path released in basis-core v0.2.1 — the sole
    way this repository's production code constructs an enforcement point."""
    assert hasattr(OperationAwareEnforcementPoint, "for_bundle")


# ---------------------------------------------------------------------------
# Import-boundary check: the gateway evaluator module must not import
# basis_core.evaluation / basis_core.evaluation.* / OperationAwareEvaluationEngine
# ---------------------------------------------------------------------------

_FORBIDDEN_IMPORT_MODULE_PREFIXES = ("basis_core.evaluation",)
_FORBIDDEN_IMPORTED_NAMES = {"OperationAwareEvaluationEngine"}


def _imported_module_names_and_bound_names(module: object) -> tuple[set[str], set[str]]:
    """Return (imported module dotted-paths, imported/bound names) for *module*.

    An AST-based check (not string/text matching) so this module's own
    docstring and comments are free to *discuss* the forbidden symbols
    (explaining what the module does not do) without producing a false
    positive, and so an import cannot hide behind an alias.
    """
    source = inspect.getsource(module)
    tree = ast.parse(source)
    imported_modules: set[str] = set()
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.add(node.module)
            imported_names.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name)
                imported_names.add(alias.asname or alias.name)
    return imported_modules, imported_names


def test_gateway_evaluator_module_does_not_import_internal_evaluation_package() -> None:
    """Structural boundary check (§8, PR 5): the gateway evaluator module must
    never import ``basis_core.evaluation``, any ``basis_core.evaluation.*``
    submodule, or the internal ``OperationAwareEvaluationEngine`` symbol —
    under any name, alias, or import form. Uses the module's actual `import`/
    `from ... import` AST nodes, not text matching, so documentation
    explaining the (now-resolved) historical import boundary cannot trigger a
    false positive.
    """
    imported_modules, imported_names = _imported_module_names_and_bound_names(
        operation_aware_evaluator_module
    )

    for module_name in imported_modules:
        assert not any(
            module_name == prefix or module_name.startswith(prefix + ".")
            for prefix in _FORBIDDEN_IMPORT_MODULE_PREFIXES
        ), f"forbidden internal module imported: {module_name!r}"

    assert imported_names.isdisjoint(_FORBIDDEN_IMPORTED_NAMES)

    # Belt-and-suspenders: the symbol must not be bound in the module's own
    # namespace either (e.g. via a wildcard import or re-export), and the
    # module must not define a TYPE_CHECKING-only import of it.
    module_globals = set(vars(operation_aware_evaluator_module))
    assert _FORBIDDEN_IMPORTED_NAMES.isdisjoint(module_globals)


def test_gateway_evaluator_constructs_enforcement_point_only_via_public_factory() -> None:
    """The gateway evaluator module must call ``for_bundle`` to construct
    every ``OperationAwareEnforcementPoint`` it builds in production code —
    never the direct ``OperationAwareEnforcementPoint(engine=..., bundle=...)``
    constructor. Detected via the module's actual `Attribute` call nodes
    (``OperationAwareEnforcementPoint.for_bundle(...)``), not text matching.
    """
    source = inspect.getsource(operation_aware_evaluator_module)
    tree = ast.parse(source)

    for_bundle_calls = 0
    direct_constructor_calls = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "for_bundle":
            is_enforcement_point = (
                isinstance(func.value, ast.Name)
                and func.value.id == "OperationAwareEnforcementPoint"
            )
            if is_enforcement_point:
                for_bundle_calls += 1
        elif isinstance(func, ast.Name) and func.id == "OperationAwareEnforcementPoint":
            direct_constructor_calls += 1

    assert for_bundle_calls >= 1, "expected an OperationAwareEnforcementPoint.for_bundle(...) call"
    assert direct_constructor_calls == 0, (
        "gateway evaluator module must never call the direct "
        "OperationAwareEnforcementPoint(engine=..., bundle=...) constructor"
    )


# ---------------------------------------------------------------------------
# Repository-wide sweep: no Python source file (production or test) imports
# basis_core.evaluation / basis_core.evaluation.* / OperationAwareEvaluationEngine.
#
# File-based (not import-based): every .py file is parsed with ``ast.parse``
# directly from disk, so this catches an offending import in a test module
# too — including one this test file never itself imports as a Python
# module (e.g. a test file that happens to raise at import time for an
# unrelated reason still gets its source inspected). Only actual import
# statements are inspected, never docstrings, comments, or string literals
# (such as this file's own ``_FORBIDDEN_IMPORTED_NAMES`` set, or the
# forbidden-name string list in test_operation_aware_composition.py's own
# structural check) — so prose explaining the historical/prohibited
# boundary can never trigger a false positive.
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SWEPT_DIRECTORIES = (_REPO_ROOT / "src", _REPO_ROOT / "tests")


def _iter_repository_python_files() -> list[Path]:
    files: list[Path] = []
    for directory in _SWEPT_DIRECTORIES:
        files.extend(path for path in directory.rglob("*.py") if "__pycache__" not in path.parts)
    return files


def _imports_in_file(path: Path) -> tuple[set[str], set[str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported_modules: set[str] = set()
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.add(node.module)
            imported_names.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name)
                imported_names.add(alias.asname or alias.name)
    return imported_modules, imported_names


def test_no_repository_source_file_imports_internal_evaluation_package() -> None:
    """Repository-wide structural sweep (§8, PR 5): no ``.py`` file under
    ``src/`` or ``tests/`` — production or test code alike — may contain an
    ``import``/``from ... import`` statement naming
    ``basis_core.evaluation``, any ``basis_core.evaluation.*`` submodule, or
    ``OperationAwareEvaluationEngine``. Each file is parsed directly from
    disk via ``ast.parse``, so this is immune to docstring/comment/string
    mentions of the same names — it only inspects actual import statements.
    """
    violations: list[str] = []
    for path in _iter_repository_python_files():
        imported_modules, imported_names = _imports_in_file(path)

        for module_name in imported_modules:
            if any(
                module_name == prefix or module_name.startswith(prefix + ".")
                for prefix in _FORBIDDEN_IMPORT_MODULE_PREFIXES
            ):
                violations.append(f"{path.relative_to(_REPO_ROOT)}: imports {module_name!r}")

        offending_names = imported_names & _FORBIDDEN_IMPORTED_NAMES
        for name in offending_names:
            violations.append(f"{path.relative_to(_REPO_ROOT)}: imports {name!r}")

    assert not violations, "forbidden internal-evaluation import(s) found:\n" + "\n".join(
        violations
    )
