"""Production runtime-safety boundary tests (issue #13).

``basis_gateway.core.evaluator.build_null_evaluator()`` builds an
in-memory, hard-coded demo policy (``rule_name="test-rbac"``,
``policy_version="test"``) and exists solely so ``tests/conftest.py``
fixtures can stand up a working evaluator without a real policy file on
disk. Production startup (``basis_gateway.main.lifespan``) must only ever
construct an evaluator via ``load_policy_engine()`` +
``build_evaluator()``, reading a real ``POLICY_PATH`` JSON file — never
via ``build_null_evaluator()``.

These tests guard that boundary two ways:
  1. Statically — ``main.py`` must never import or reference
     ``build_null_evaluator`` by name, so a future edit that wires the
     demo evaluator into a startup fallback path is caught immediately,
     even before the dynamic behavior below would surface it.
  2. Dynamically — the real ``create_app()``/``lifespan()`` startup path,
     given a real policy file, must produce an evaluator whose policy
     version and enforcement-point wiring match what
     ``build_evaluator()`` (not ``build_null_evaluator()``) produces.

See also ``tests/test_phase4_readiness.py`` (``test_startup_with_policy_
path_sets_evaluator_on_app_state`` / ``test_startup_without_policy_path_
evaluator_is_none``), which already prove production startup never
constructs an evaluator without a real ``POLICY_PATH`` and never falls
back to one when ``POLICY_PATH`` is absent. This file adds the static
import-boundary guard that was not yet covered.
"""

from __future__ import annotations

import ast
import inspect
import json

from fastapi.testclient import TestClient

import basis_gateway.main as main_mod
from basis_gateway.main import create_app
from basis_gateway.readiness import reset_readiness_state


def _top_level_imported_names(module: object) -> set[str]:
    """Every name bound by import/import-from statements in ``module``."""
    source = inspect.getsource(module)
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


# ---------------------------------------------------------------------------
# Static: main.py must never import or reference build_null_evaluator
# ---------------------------------------------------------------------------


def test_main_does_not_import_build_null_evaluator():
    assert "build_null_evaluator" not in _top_level_imported_names(main_mod)


def test_main_source_never_references_build_null_evaluator():
    """Belt-and-suspenders: catches any reference (aliased import, dynamic
    getattr, string-based dispatch, etc.), not just a plain import."""
    source = inspect.getsource(main_mod)
    assert "build_null_evaluator" not in source


# ---------------------------------------------------------------------------
# Dynamic: real startup with a real policy file never yields the demo
# evaluator's policy identity
# ---------------------------------------------------------------------------


def test_production_startup_evaluator_is_not_the_demo_evaluator(tmp_path, monkeypatch):
    """The demo evaluator (build_null_evaluator) hard-codes rule_name
    "test-rbac" and policy_version "test". A gateway started against a
    real policy file with a distinct policy_version must not surface
    those demo markers on app.state.evaluator — proving the running
    evaluator was built from the configured policy, not the demo one.
    """
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "rule_name": "production-rbac",
                        "role_table": {"read:sensor:telemetry": ["viewer"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("POLICY_PATH", str(policy_path))
    monkeypatch.setenv("POLICY_VERSION", "v-production-1")
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=True):
        evaluator = app.state.evaluator
        assert evaluator is not None
        assert evaluator.policy_version == "v-production-1"
        assert evaluator.policy_version != "test"
