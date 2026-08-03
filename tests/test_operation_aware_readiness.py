"""Focused readiness/diagnostics tests for the operation-aware gateway path
(PR 8, §13 of ``docs/implementation/operation-aware-gateway-integration-plan.md``).

Replaces PR 5's temporary, single ``operation_aware_evaluator`` readiness
component with the full four-component staged model:

  - ``operation_aware_mode_enabled``
  - ``operation_aware_bundle_loaded``
  - ``operation_aware_evaluator_initialized``
  - ``operation_aware_policy_semantically_valid``

Every test below drives the real ``/ready``/``/health`` endpoints through
the real, unmodified ``main.py`` lifespan — no readiness state is poked
directly except where a test is explicitly a generic ``ReadinessState`` unit
test (see ``tests/test_readiness_state.py`` instead). All fixtures are
hermetic and offline: no network, no Docker, no live identity provider.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from basis_gateway.audit.writer import GatewayAuditWriter
from basis_gateway.core.operation_aware_evaluator import OperationAwareGatewayEvaluator
from basis_gateway.main import create_app
from basis_gateway.readiness import get_readiness_state, reset_readiness_state

_OPERATION_AWARE_COMPONENTS = (
    "operation_aware_mode_enabled",
    "operation_aware_bundle_loaded",
    "operation_aware_evaluator_initialized",
    "operation_aware_policy_semantically_valid",
)

VALID_BUNDLE: dict = {
    "bundle_id": "readiness-bundle",
    "bundle_version": "1.0.0",
    "schema_version": "1.0.0",
    "policy_owner": "test-owner",
    "rules": [{"rule_id": "rule-1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
}

DUPLICATE_RULE_ID_BUNDLE: dict = {
    "bundle_id": "dup-bundle",
    "bundle_version": "1.0.0",
    "schema_version": "1.0.0",
    "policy_owner": "test-owner",
    "rules": [
        {"rule_id": "r1", "effect": "allow", "match": {"actions": ["read:ahu"]}},
        {"rule_id": "r1", "effect": "deny", "match": {"actions": ["write:ahu"]}},
    ],
}

# Matches the startup preflight's own reserved synthetic action
# (basis_gateway.core.operation_aware_evaluator._PREFLIGHT_ACTION) so this
# rule's conditions are actually evaluated during preflight, exercising the
# bad operator.
UNSUPPORTED_OPERATOR_BUNDLE: dict = {
    "bundle_id": "bad-operator-bundle",
    "bundle_version": "1.0.0",
    "schema_version": "1.0.0",
    "policy_owner": "test-owner",
    "rules": [
        {
            "rule_id": "r1",
            "effect": "allow",
            "match": {"actions": ["read:basis_gateway_preflight"]},
            "conditions": [
                {
                    "condition_id": "c1",
                    "field_path": "risk_context.classification",
                    "operator": "not_a_real_operator",
                    "expected_value": "low",
                }
            ],
        }
    ],
}


def write_bundle(tmp_path: Path, data: object, filename: str = "bundle.json") -> str:
    p = tmp_path / filename
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


_SENSITIVE_SUBSTRINGS = (
    "token",
    "authorization",
    "cookie",
    "credential",
    "private_key",
    "public_key",
    "raw_request",
    "raw_policy",
    "policy_contents",
    "stack_trace",
    "environ",
)


def _assert_operation_aware_reasons_are_safe(reasons: dict[str, str]) -> None:
    """Scoped to the four components this PR actually introduces/updates —
    pre-existing, out-of-scope components (e.g. ``basis_local_token_configured``)
    may legitimately mention "public key"/"private key" as descriptive
    English prose about key *shape*, not exposed key material, and are not
    part of this PR's diagnostic surface."""
    for name in _OPERATION_AWARE_COMPONENTS:
        if name not in reasons:
            continue
        reason = reasons[name]
        lowered = reason.lower()
        for needle in _SENSITIVE_SUBSTRINGS:
            assert needle not in lowered, (
                f"readiness reason for {name!r} contains sensitive substring {needle!r}: {reason!r}"
            )


# ---------------------------------------------------------------------------
# Disabled mode
# ---------------------------------------------------------------------------


def test_disabled_mode_registers_none_of_the_four_components() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        components = get_readiness_state().components
        for name in _OPERATION_AWARE_COMPONENTS:
            assert name not in components
        assert client.get("/ready").status_code == 200


def test_disabled_mode_temporary_component_absent() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert "operation_aware_evaluator" not in get_readiness_state().components


def test_disabled_mode_ready_unchanged() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        response = client.get("/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"


def test_disabled_mode_route_absent() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        resp = client.post("/v1/evaluate/operation-aware", json={"action": "read:ahu"})
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Enabled and fully valid
# ---------------------------------------------------------------------------


def test_enabled_valid_all_four_components_ready(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        components = get_readiness_state().components
        for name in _OPERATION_AWARE_COMPONENTS:
            assert components.get(name) is True, (
                f"{name} expected ready, got {components.get(name)!r}"
            )


def test_enabled_valid_temporary_component_absent(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert "operation_aware_evaluator" not in get_readiness_state().components


def test_enabled_valid_evaluator_present(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert isinstance(app.state.operation_aware_evaluator, OperationAwareGatewayEvaluator)


def test_enabled_valid_route_present(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        resp = client.post("/v1/evaluate/operation-aware", json={"action": "read:ahu"})
        assert resp.status_code == 401  # reachable, not 404 — just unauthenticated


def test_enabled_valid_ready_returns_200(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        assert client.get("/ready").status_code == 200


def test_enabled_valid_startup_preflight_writes_no_operational_audit_event(
    monkeypatch, tmp_path
) -> None:
    """Same technique as tests/test_operation_aware_startup.py's own
    equivalent test: monkeypatch the concrete inner LogAuditWriter with a
    capturing double *before* TestClient triggers the ASGI lifespan, so
    every event actually delegated to the writer's inner during the whole
    startup sequence (including preflight) is captured."""

    class _CapturingInnerWriter:
        def __init__(self) -> None:
            self.events: list[object] = []

        def write(self, event: object) -> None:
            self.events.append(event)

    captured_holder: dict[str, _CapturingInnerWriter] = {}

    def _factory() -> _CapturingInnerWriter:
        inner = _CapturingInnerWriter()
        captured_holder["inner"] = inner
        return inner

    monkeypatch.setattr("basis_gateway.audit.writer.LogAuditWriter", _factory)

    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert (
            get_readiness_state().components.get("operation_aware_policy_semantically_valid")
            is True
        )

    assert captured_holder["inner"].events == []


# ---------------------------------------------------------------------------
# Missing bundle path
# ---------------------------------------------------------------------------


def test_missing_bundle_path_stage_attribution(monkeypatch) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        components = get_readiness_state().components
        assert components.get("operation_aware_mode_enabled") is True
        assert components.get("operation_aware_bundle_loaded") is False
        assert components.get("operation_aware_evaluator_initialized") is False
        assert components.get("operation_aware_policy_semantically_valid") is False
        assert app.state.operation_aware_evaluator is None
        assert app.state.operation_aware_router_registered is True
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503
        _assert_operation_aware_reasons_are_safe(get_readiness_state().all_reasons)


# ---------------------------------------------------------------------------
# Missing bundle file
# ---------------------------------------------------------------------------


def test_missing_bundle_file_stage_attribution(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(tmp_path / "does-not-exist.json"))
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        components = get_readiness_state().components
        assert components.get("operation_aware_mode_enabled") is True
        assert components.get("operation_aware_bundle_loaded") is False
        assert components.get("operation_aware_evaluator_initialized") is False
        assert components.get("operation_aware_policy_semantically_valid") is False
        assert app.state.operation_aware_evaluator is None
        assert app.state.operation_aware_router_registered is True
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503
        _assert_operation_aware_reasons_are_safe(get_readiness_state().all_reasons)


# ---------------------------------------------------------------------------
# Malformed JSON
# ---------------------------------------------------------------------------


def test_malformed_json_stage_attribution(monkeypatch, tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(path))
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        components = get_readiness_state().components
        assert components.get("operation_aware_mode_enabled") is True
        assert components.get("operation_aware_bundle_loaded") is False
        assert components.get("operation_aware_evaluator_initialized") is False
        assert components.get("operation_aware_policy_semantically_valid") is False
        assert client.get("/ready").status_code == 503
        _assert_operation_aware_reasons_are_safe(get_readiness_state().all_reasons)


# ---------------------------------------------------------------------------
# Structurally invalid bundle
# ---------------------------------------------------------------------------


def test_structurally_invalid_bundle_stage_attribution(monkeypatch, tmp_path) -> None:
    """A bundle missing a required top-level field (policy_owner) fails
    PolicyBundle.model_validate() inside load_operation_aware_policy_bundle
    — i.e. structural loading, per that module's own documented boundary
    ("Structural vs. semantic validation"). Attributed to
    operation_aware_bundle_loaded, the same stage as missing-path/
    missing-file/malformed-JSON, because all four are the same *structural*
    loading step in the real loader architecture — not the semantic
    preflight (see test_semantic_preflight_failure_* below for the
    structurally-valid-but-semantically-invalid case)."""
    invalid = dict(VALID_BUNDLE)
    del invalid["policy_owner"]
    path = write_bundle(tmp_path, invalid)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        components = get_readiness_state().components
        assert components.get("operation_aware_mode_enabled") is True
        assert components.get("operation_aware_bundle_loaded") is False
        assert components.get("operation_aware_evaluator_initialized") is False
        assert components.get("operation_aware_policy_semantically_valid") is False
        assert client.get("/ready").status_code == 503
        _assert_operation_aware_reasons_are_safe(get_readiness_state().all_reasons)


# ---------------------------------------------------------------------------
# Evaluator-construction failure (lifecycle coverage, not a canonical policy
# scenario — see module docstring / PR-8 completion report for why: with a
# structurally-valid, already-loaded PolicyBundle,
# OperationAwareEnforcementPoint.for_bundle() has no governed failure mode.
# This test proves the *stage-transition machinery* behaves correctly if
# construction ever did raise, via a narrowly patched construction function.
# ---------------------------------------------------------------------------


def test_evaluator_construction_failure_stage_attribution(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)

    def _explode(bundle: object) -> object:
        raise RuntimeError("simulated deterministic construction failure")

    monkeypatch.setattr("basis_gateway.main.construct_operation_aware_evaluator", _explode)

    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        components = get_readiness_state().components
        assert components.get("operation_aware_mode_enabled") is True
        assert components.get("operation_aware_bundle_loaded") is True
        assert components.get("operation_aware_evaluator_initialized") is False
        assert components.get("operation_aware_policy_semantically_valid") is False
        assert app.state.operation_aware_evaluator is None
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503
        _assert_operation_aware_reasons_are_safe(get_readiness_state().all_reasons)


# ---------------------------------------------------------------------------
# Semantic preflight failure
# ---------------------------------------------------------------------------


def test_semantic_preflight_failure_duplicate_rule_ids(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, DUPLICATE_RULE_ID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        components = get_readiness_state().components
        assert components.get("operation_aware_mode_enabled") is True
        assert components.get("operation_aware_bundle_loaded") is True
        assert components.get("operation_aware_evaluator_initialized") is True
        assert components.get("operation_aware_policy_semantically_valid") is False
        assert app.state.operation_aware_evaluator is None
        assert client.get("/ready").status_code == 503
        _assert_operation_aware_reasons_are_safe(get_readiness_state().all_reasons)


def test_semantic_preflight_failure_unsupported_operator(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, UNSUPPORTED_OPERATOR_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        components = get_readiness_state().components
        assert components.get("operation_aware_mode_enabled") is True
        assert components.get("operation_aware_bundle_loaded") is True
        assert components.get("operation_aware_evaluator_initialized") is True
        assert components.get("operation_aware_policy_semantically_valid") is False
        assert app.state.operation_aware_evaluator is None
        assert client.get("/ready").status_code == 503
        _assert_operation_aware_reasons_are_safe(get_readiness_state().all_reasons)


# ---------------------------------------------------------------------------
# Repeated application construction — no leakage between separate apps
# ---------------------------------------------------------------------------


def test_repeated_app_construction_does_not_leak_readiness_state(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)

    reset_readiness_state()
    app_one = create_app()
    with TestClient(app_one):
        components_one = dict(get_readiness_state().components)

    reset_readiness_state()
    monkeypatch.delenv("OPERATION_AWARE_ENABLED", raising=False)
    app_two = create_app()
    with TestClient(app_two):
        components_two = get_readiness_state().components

    for name in _OPERATION_AWARE_COMPONENTS:
        assert components_one.get(name) is True
        assert name not in components_two


# ---------------------------------------------------------------------------
# Lifespan re-entry — components not duplicated, route registered once
# ---------------------------------------------------------------------------


def test_lifespan_reentry_components_not_duplicated_route_registered_once(
    monkeypatch, tmp_path
) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)

    reset_readiness_state()
    app = create_app()

    with TestClient(app):
        pass
    reset_readiness_state()
    with TestClient(app):
        pass
    reset_readiness_state()
    with TestClient(app) as client:
        components = get_readiness_state().components
        for name in _OPERATION_AWARE_COMPONENTS:
            assert components.get(name) is True
        assert len(components) == len(set(components))  # dict keys are inherently unique
        assert app.state.operation_aware_router_registered is True
        resp = client.post("/v1/evaluate/operation-aware", json={"action": "read:ahu"})
        assert resp.status_code == 401  # reachable exactly once, not duplicated/404


# ---------------------------------------------------------------------------
# v0.1-only compatibility
# ---------------------------------------------------------------------------


def test_v01_only_no_operation_aware_components(tmp_path, monkeypatch) -> None:
    p = tmp_path / "policy.json"
    p.write_text(
        json.dumps(
            {"rules": [{"rule_name": "r", "role_table": {"read:sensor:telemetry": ["viewer"]}}]}
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("POLICY_PATH", str(p))
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        components = get_readiness_state().components
        for name in _OPERATION_AWARE_COMPONENTS:
            assert name not in components
        assert components.get("policy_loaded") is True
        assert components.get("evaluator_initialized") is True
        assert client.get("/ready").status_code == 200
        assert app.state.evaluator is not None


# ---------------------------------------------------------------------------
# Both modes enabled
# ---------------------------------------------------------------------------


def test_both_modes_enabled_all_components_present_one_shared_writer(monkeypatch, tmp_path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        rsa_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    v01_policy_path = tmp_path / "v01-policy.json"
    v01_policy_path.write_text(
        json.dumps(
            {
                "rules": [
                    {"rule_name": "test-rbac", "role_table": {"read:sensor:telemetry": ["viewer"]}}
                ]
            }
        ),
        encoding="utf-8",
    )
    op_aware_path = write_bundle(tmp_path, VALID_BUNDLE)

    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.setenv("AUTH_MODE", "basis_local_token")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_ISSUER", "https://identity.basis.example.com")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_AUDIENCE", "basis-gateway")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON", json.dumps({"key-1": public_pem}))
    monkeypatch.setenv("POLICY_PATH", str(v01_policy_path))
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", op_aware_path)

    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        components = get_readiness_state().components
        assert components.get("basis_local_token_configured") is True
        assert components.get("policy_loaded") is True
        assert components.get("evaluator_initialized") is True
        for name in _OPERATION_AWARE_COMPONENTS:
            assert components.get(name) is True

        assert isinstance(app.state.audit_writer, GatewayAuditWriter)
        assert app.state.evaluator is not None
        assert isinstance(app.state.operation_aware_evaluator, OperationAwareGatewayEvaluator)

        assert client.get("/ready").status_code == 200


# ---------------------------------------------------------------------------
# Earlier authentication failure (before operation-aware bundle processing)
# ---------------------------------------------------------------------------


def test_earlier_authentication_failure_leaves_honest_pending_diagnostics(
    monkeypatch, tmp_path
) -> None:
    """A deterministic, local, network-free authentication-configuration
    failure (mirrors tests/test_operation_aware_audit_writer_lifecycle.py):
    BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON's one entry looks like a private key,
    which BasisLocalTokenTrustConfig rejects at construction time (step 3)
    — before step 6 (operation-aware bundle processing) ever runs. Proves
    the audit writer and operation_aware_mode_enabled (registered early, at
    step 1c) both survive; the other three operation-aware components stay
    in their honest "not yet reached" pending state — never fabricated as a
    bundle-semantic failure that never actually occurred.
    """
    monkeypatch.setenv("AUTH_MODE", "basis_local_token")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_ISSUER", "https://identity.basis.example.com")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_AUDIENCE", "basis-gateway")
    monkeypatch.setenv(
        "BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON",
        json.dumps(
            {"key-1": "-----BEGIN PRIVATE KEY-----\nnotarealkey\n-----END PRIVATE KEY-----"}
        ),
    )
    monkeypatch.setenv("POLICY_PATH", str(tmp_path / "unused-policy.json"))
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    bundle_path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", bundle_path)

    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        assert isinstance(app.state.audit_writer, GatewayAuditWriter)
        assert get_readiness_state().components.get("audit_writer") is True

        components = get_readiness_state().components
        assert components.get("operation_aware_mode_enabled") is True
        assert components.get("operation_aware_bundle_loaded") is False
        assert components.get("operation_aware_evaluator_initialized") is False
        assert components.get("operation_aware_policy_semantically_valid") is False
        assert components.get("basis_local_token_configured") is False

        # Bundle processing (step 6) never ran — no evaluator was
        # constructed, and the pending reason must not claim a semantic (or
        # any other) bundle defect that was never actually evaluated.
        assert app.state.operation_aware_evaluator is None
        all_reasons = get_readiness_state().all_reasons
        bundle_reason = all_reasons["operation_aware_bundle_loaded"].lower()
        assert "semantically" not in bundle_reason
        assert "invalid" not in bundle_reason
        _assert_operation_aware_reasons_are_safe(all_reasons)

        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503


# ---------------------------------------------------------------------------
# v0.1 policy failure before operation-aware processing (both enabled)
# ---------------------------------------------------------------------------


def test_v01_policy_failure_before_operation_aware_processing(monkeypatch, tmp_path) -> None:
    """POLICY_PATH points at a nonexistent file (step 4 fails) while
    operation-aware is enabled with an otherwise-valid bundle. Step 6 never
    runs, so operation_aware_mode_enabled (registered at step 1c) stays
    ready while the other three remain honestly pending — mirrors the
    authentication-failure case above but for a v0.1-path failure instead.
    """
    monkeypatch.setenv("POLICY_PATH", str(tmp_path / "does-not-exist-policy.json"))
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    bundle_path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", bundle_path)

    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        components = get_readiness_state().components
        assert components.get("policy_loaded") is False
        assert components.get("operation_aware_mode_enabled") is True
        assert components.get("operation_aware_bundle_loaded") is False
        assert components.get("operation_aware_evaluator_initialized") is False
        assert components.get("operation_aware_policy_semantically_valid") is False
        assert app.state.evaluator is None
        assert app.state.operation_aware_evaluator is None
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503


# ---------------------------------------------------------------------------
# Diagnostic reason sanity (belt-and-suspenders on top of the per-scenario
# _assert_operation_aware_reasons_are_safe calls above)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bundle_data",
    [DUPLICATE_RULE_ID_BUNDLE, UNSUPPORTED_OPERATOR_BUNDLE],
    ids=["duplicate_rule_ids", "unsupported_operator"],
)
def test_semantic_preflight_failure_reason_identifies_stage_not_raw_content(
    monkeypatch, tmp_path, bundle_data
) -> None:
    path = write_bundle(tmp_path, bundle_data)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False):
        reason = get_readiness_state().all_reasons["operation_aware_policy_semantically_valid"]
        # Safe to report: governed evaluation_status/failure_reason vocabulary
        # only — never raw policy content, condition values, or bundle text.
        assert "not_a_real_operator" not in reason
        assert "risk_context.classification" not in reason
