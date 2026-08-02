"""Regression tests for operation-aware router registration (PR 6 review fix).

Architectural review of the initial PR 6 implementation found that
registering ``operation_aware_router`` from a throwaway ``load_config()``
call inside ``create_app()`` (before the protected lifespan startup
boundary) changed existing startup-failure behavior: a malformed
environment could crash application construction itself instead of letting
``/health`` stay up while ``/ready`` reports ``503``, and configuration was
loaded twice with no guarantee both loads agreed.

The fix moves registration inside ``lifespan()``, driven by the same
``config`` object the lifespan already treats as authoritative, guarded so
it never runs more than once per app instance. This module tests that fix
directly — see ``tests/test_operation_aware_endpoint.py`` and
``tests/test_operation_aware_startup.py`` for the broader route-behavior and
startup-configuration matrices, which continue to pass unmodified (aside
from the one test renamed in the initial PR 6 pass, per that file's own
docstring).

These tests deliberately avoid introspecting Starlette/FastAPI's internal
route representation (which varies across FastAPI versions — this
repository's installed FastAPI wraps included routers in an internal,
version-specific ``_IncludedRouter`` node rather than a flat ``Route``
list). Instead, registration state is observed the same way a real caller
or the readiness probe would: HTTP behavior (404 vs. reachable) and the
``app.state.operation_aware_router_registered`` guard flag this fix
introduces, plus a call-count spy on ``FastAPI.include_router`` for the
"registered at most once" requirement specifically.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from basis_gateway.api.routes import operation_aware_router
from basis_gateway.main import create_app
from basis_gateway.readiness import reset_readiness_state

VALID_BUNDLE: dict = {
    "bundle_id": "router-registration-bundle",
    "bundle_version": "1.0.0",
    "schema_version": "1.0.0",
    "policy_owner": "test-owner",
    "rules": [{"rule_id": "rule-1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
}


def write_bundle(tmp_path: Path, data: object, filename: str = "bundle.json") -> str:
    p = tmp_path / filename
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# create_app() itself performs no configuration loading / no registration
# ---------------------------------------------------------------------------


def test_create_app_does_not_set_registration_flag_before_lifespan_runs(monkeypatch) -> None:
    """Before the ASGI lifespan startup event ever fires, create_app() alone
    must not have registered the operation-aware router — proving
    registration was moved out of create_app() and into lifespan. The guard
    flag is simply absent (never set to anything) until lifespan runs."""
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", "/tmp/whatever-not-loaded-yet.json")
    reset_readiness_state()
    app = create_app()
    # No `with TestClient(app):` yet — lifespan has not run.
    assert getattr(app.state, "operation_aware_router_registered", None) is None


def test_registration_flag_set_only_after_lifespan_runs(monkeypatch) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", "/tmp/whatever-not-loaded-yet.json")
    reset_readiness_state()
    app = create_app()
    assert getattr(app.state, "operation_aware_router_registered", None) is None
    with TestClient(app):
        assert app.state.operation_aware_router_registered is True


# ---------------------------------------------------------------------------
# Feature gating (re-derived from the lifespan-driven path specifically)
# ---------------------------------------------------------------------------


def test_disabled_never_registers_route() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as c:
        assert getattr(app.state, "operation_aware_router_registered", None) is None
        resp = c.post("/v1/evaluate/operation-aware", json={"action": "read:ahu"})
        assert resp.status_code == 404


def test_enabled_and_valid_registers_route_and_requires_auth(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as c:
        assert app.state.operation_aware_router_registered is True
        resp = c.post("/v1/evaluate/operation-aware", json={"action": "read:ahu"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Enabled but evaluator initialization fails: registered, real 503, driven
# entirely by the natural lifespan flow (no manual app.state override).
# ---------------------------------------------------------------------------


def test_enabled_but_evaluator_init_fails_route_registered_returns_503_after_auth(
    monkeypatch, mock_verifier
) -> None:
    """OPERATION_AWARE_ENABLED=true with OPERATION_AWARE_POLICY_BUNDLE_PATH
    pointing at a nonexistent file, so operation-aware evaluator
    construction fails during lifespan — the exact 'enabled but evaluator
    unavailable' case this fix is about. Authentication itself succeeds for
    real, via the same mock-OIDC-verifier-injected-after-lifespan pattern
    ``conftest.py``'s own ``evaluate_client``/``capture_client`` fixtures
    already use for the v0.1 path (a live IdP is not available in this test
    environment; a mock verifier standing in for a live OIDC discovery
    round-trip is this repository's established pattern, not a weaker
    substitute). Route registration and evaluator-unavailability are driven
    entirely by the real, unmodified lifespan — only the OIDC verifier
    construction step (which would otherwise require network access) is
    replaced with the mock."""
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv(
        "OPERATION_AWARE_POLICY_BUNDLE_PATH", "/tmp/basis-gateway-router-reg-test-missing.json"
    )
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        assert app.state.operation_aware_router_registered is True
        assert app.state.operation_aware_evaluator is None
        app.state.verifier = mock_verifier

        resp = c.post(
            "/v1/evaluate/operation-aware",
            json={"action": "read:ahu"},
            headers={"Authorization": "Bearer fake"},
        )
    assert resp.status_code == 503
    assert resp.json()["error"] == "evaluator_unavailable"


# ---------------------------------------------------------------------------
# Malformed startup configuration still allows construction + /health
# ---------------------------------------------------------------------------


def test_malformed_configuration_still_constructs_app_and_serves_health(monkeypatch) -> None:
    """An invalid LOG_LEVEL fails GatewayConfig() construction itself
    (pydantic ValidationError) inside lifespan's own try/except — this is
    pre-existing behavior this fix must not regress. The app must still be
    constructible and /health must still respond; /ready must report 503."""
    monkeypatch.setenv("LOG_LEVEL", "NOT_A_REAL_LEVEL")
    reset_readiness_state()
    app = create_app()  # must not raise
    with TestClient(app) as c:
        health_resp = c.get("/health")
        assert health_resp.status_code == 200
        ready_resp = c.get("/ready")
        assert ready_resp.status_code == 503


def test_malformed_configuration_with_operation_aware_enabled_still_serves_health(
    monkeypatch,
) -> None:
    """Same as above, but with OPERATION_AWARE_ENABLED=true set too — proves
    the operation-aware registration step itself never executes (config
    never successfully loads, so step 1a is never reached) and does not
    change this failure mode."""
    monkeypatch.setenv("LOG_LEVEL", "NOT_A_REAL_LEVEL")
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    reset_readiness_state()
    app = create_app()  # must not raise
    with TestClient(app) as c:
        assert c.get("/health").status_code == 200
        assert c.get("/ready").status_code == 503
        # The route was never reached by the registration step because
        # config loading itself failed before step 1a ever runs.
        assert getattr(app.state, "operation_aware_router_registered", None) is None
        resp = c.post("/v1/evaluate/operation-aware", json={"action": "read:ahu"})
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Registration occurs at most once per app instance
# ---------------------------------------------------------------------------


def test_router_registered_only_once_across_repeated_lifespan_runs(monkeypatch, tmp_path) -> None:
    """Re-entering the ASGI lifespan (startup -> shutdown -> startup) against
    the *same* FastAPI app instance must call ``include_router`` with
    ``operation_aware_router`` at most once — proving the
    ``operation_aware_router_registered`` guard actually prevents redundant
    registration rather than merely happening to not be exercised by these
    tests."""
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)

    calls: list[object] = []
    original_include_router = FastAPI.include_router

    def counting_include_router(self: FastAPI, router: object, *args: object, **kwargs: object):
        calls.append(router)
        return original_include_router(self, router, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(FastAPI, "include_router", counting_include_router)

    reset_readiness_state()
    app = create_app()

    with TestClient(app):
        pass
    reset_readiness_state()
    with TestClient(app):
        pass
    reset_readiness_state()
    with TestClient(app):
        assert app.state.operation_aware_router_registered is True

    operation_aware_registrations = [c for c in calls if c is operation_aware_router]
    assert len(operation_aware_registrations) == 1


def test_registration_guard_flag_set_after_first_registration(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert app.state.operation_aware_router_registered is True


def test_include_router_called_exactly_once_for_single_lifespan_run(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)

    calls: list[object] = []
    original_include_router = FastAPI.include_router

    def counting_include_router(self: FastAPI, router: object, *args: object, **kwargs: object):
        calls.append(router)
        return original_include_router(self, router, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(FastAPI, "include_router", counting_include_router)

    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        pass

    operation_aware_registrations = [c for c in calls if c is operation_aware_router]
    assert len(operation_aware_registrations) == 1


# ---------------------------------------------------------------------------
# /v1/evaluate remains completely unaffected
# ---------------------------------------------------------------------------


def test_v1_evaluate_unaffected_when_operation_aware_disabled() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as c:
        resp = c.post(
            "/v1/evaluate", json={"action": "read:ahu"}, headers={"Authorization": "Bearer fake"}
        )
        assert resp.status_code != 404


def test_v1_evaluate_unaffected_when_operation_aware_enabled(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as c:
        resp = c.post(
            "/v1/evaluate", json={"action": "read:ahu"}, headers={"Authorization": "Bearer fake"}
        )
        assert resp.status_code != 404


def test_v1_evaluate_behavior_identical_regardless_of_operation_aware_flag(
    monkeypatch, tmp_path
) -> None:
    """Same unauthenticated /v1/evaluate request, same expected 401,
    whether or not OPERATION_AWARE_ENABLED is set — proving router
    registration for the new endpoint never touches the existing router's
    behavior."""
    path = write_bundle(tmp_path, VALID_BUNDLE)

    reset_readiness_state()
    app_disabled = create_app()
    with TestClient(app_disabled) as c_disabled:
        disabled_status = c_disabled.post("/v1/evaluate", json={"action": "read:ahu"}).status_code

    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app_enabled = create_app()
    with TestClient(app_enabled) as c_enabled:
        enabled_status = c_enabled.post("/v1/evaluate", json={"action": "read:ahu"}).status_code

    assert disabled_status == enabled_status == 401
