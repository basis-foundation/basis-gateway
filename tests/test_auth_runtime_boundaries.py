"""Import/behavior boundary tests for the runtime auth-mode wiring.

Verifies basis_gateway.auth.runtime (and the touched config/main/routes
modules) stay a thin dispatcher: no basis_identity import, no basis_core
import, no token issuance or signing, no private key handling or
generation, no key loading from files, no JWKS fetching, and no
policy-evaluation or authorization-decision vocabulary added to auth.
"""

from __future__ import annotations

import ast
import inspect

import basis_gateway.api.routes as routes_mod
import basis_gateway.config as config_mod
import basis_gateway.main as main_mod
from basis_gateway.auth import runtime as auth_runtime


def _top_level_imported_modules(module: object) -> set[str]:
    source = inspect.getsource(module)
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


# ---------------------------------------------------------------------------
# No basis_identity anywhere in the runtime auth-mode wiring
# ---------------------------------------------------------------------------


def test_runtime_does_not_import_basis_identity():
    assert "basis_identity" not in _top_level_imported_modules(auth_runtime)


def test_no_basis_identity_import_in_touched_modules():
    for module in (auth_runtime, routes_mod, config_mod, main_mod):
        assert "basis_identity" not in _top_level_imported_modules(module), (
            f"{module.__name__} must not import basis_identity"
        )


# ---------------------------------------------------------------------------
# basis_gateway.auth.runtime import surface
# ---------------------------------------------------------------------------


def test_runtime_does_not_import_basis_core():
    assert "basis_core" not in _top_level_imported_modules(auth_runtime)


def test_runtime_only_expected_top_level_modules_imported():
    allowed = {"__future__", "json", "typing", "basis_gateway"}
    assert _top_level_imported_modules(auth_runtime) <= allowed


def test_runtime_does_not_import_web_framework():
    imported = _top_level_imported_modules(auth_runtime)
    assert "fastapi" not in imported
    assert "starlette" not in imported


# ---------------------------------------------------------------------------
# No issuance / signing / key handling / JWKS fetching in the dispatcher
# ---------------------------------------------------------------------------


def test_runtime_has_no_key_generation():
    source = inspect.getsource(auth_runtime)
    assert "generate_private_key(" not in source
    assert "rsa.generate" not in source


def test_runtime_has_no_key_loading_from_file():
    source = inspect.getsource(auth_runtime)
    assert "open(" not in source


def test_runtime_has_no_jwks_fetching():
    imported = _top_level_imported_modules(auth_runtime)
    assert "httpx" not in imported
    assert "requests" not in imported
    source = inspect.getsource(auth_runtime)
    assert "fetch_jwks" not in source
    assert "PyJWKClient" not in source


def test_runtime_has_no_signing_primitive():
    source = inspect.getsource(auth_runtime)
    assert "jwt.encode" not in source


def test_runtime_has_no_policy_evaluation_call():
    source = inspect.getsource(auth_runtime)
    assert "EnforcementPoint" not in source
    assert "PolicyEngine" not in source


def test_runtime_has_no_authorization_decision_vocabulary():
    """The auth-mode dispatcher authenticates only; it must never carry an
    authorization decision, permission, grant, or enforcement-result term."""
    source = inspect.getsource(auth_runtime).lower()
    forbidden = ("permission", '"grant"', "'grant'", "matched_rule", "obligation")
    for term in forbidden:
        assert term not in source, f"forbidden term {term!r} found in auth/runtime.py"


# ---------------------------------------------------------------------------
# config.py stays auth-agnostic (no deep trust-config construction)
# ---------------------------------------------------------------------------


def test_config_module_does_not_import_basis_local_token_verifier():
    """config.py should only parse/validate presence of env-sourced strings;
    BasisLocalTokenTrustConfig construction lives in auth/runtime.py, not
    config.py, keeping config.py free of any basis_gateway.auth import."""
    assert "basis_gateway.auth" not in _top_level_imported_modules_raw(config_mod)
    source = inspect.getsource(config_mod)
    assert "BasisLocalTokenTrustConfig" not in source
    assert "verify_basis_local_identity_token" not in source


def _top_level_imported_modules_raw(module: object) -> set[str]:
    """Full dotted import targets (unlike _top_level_imported_modules, which
    truncates to the first path segment)."""
    source = inspect.getsource(module)
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names
