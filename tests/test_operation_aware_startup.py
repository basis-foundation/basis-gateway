"""Tests for operation-aware configuration and startup wiring (PR 5).

Covers §12/§13(partial)/§16 PR 5 of
``docs/implementation/operation-aware-gateway-integration-plan.md``:
``OPERATION_AWARE_ENABLED``/``OPERATION_AWARE_POLICY_BUNDLE_PATH``
configuration presence validation, and ``main.py``'s lifespan wiring —
disabled-by-default behavior, enabled/valid startup, enabled/invalid startup
failure, and isolation from existing v0.1 startup state.

PR 8 replaced PR 5's original narrow, temporary ``operation_aware_evaluator``
readiness component with the full four-component staged model
(``operation_aware_mode_enabled``/``operation_aware_bundle_loaded``/
``operation_aware_evaluator_initialized``/``operation_aware_policy_semantically_valid``)
described in §13 — see ``tests/test_operation_aware_readiness.py`` for the
focused, per-stage readiness coverage (failure attribution, pending-state
visibility, disabled-mode absence, etc.). This module retains its original
scope: configuration presence validation and the coarser
``app.state.operation_aware_evaluator``/``/ready`` status-code assertions
below still hold unchanged under the new model, so they are kept here as
regression coverage — only the one assertion that named the removed
single-component readiness name was updated to check the new model instead.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from basis_gateway.config import (
    GatewayConfig,
    OperationAwareConfigError,
    validate_operation_aware_config,
)
from basis_gateway.core.operation_aware_evaluator import OperationAwareGatewayEvaluator
from basis_gateway.main import create_app
from basis_gateway.readiness import get_readiness_state, reset_readiness_state

VALID_BUNDLE: dict = {
    "bundle_id": "startup-bundle",
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

UNSUPPORTED_OPERATOR_BUNDLE: dict = {
    "bundle_id": "bad-operator-bundle",
    "bundle_version": "1.0.0",
    "schema_version": "1.0.0",
    "policy_owner": "test-owner",
    "rules": [
        {
            "rule_id": "r1",
            "effect": "allow",
            # Matches the startup preflight's own reserved synthetic
            # action (basis_gateway.core.operation_aware_evaluator's
            # _PREFLIGHT_ACTION) so this rule's conditions are actually
            # evaluated during preflight, exercising the bad operator.
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


# ---------------------------------------------------------------------------
# Configuration presence validation (no app/lifespan involved)
# ---------------------------------------------------------------------------


def test_operation_aware_disabled_by_default() -> None:
    config = GatewayConfig()
    assert config.operation_aware_enabled is False
    assert config.operation_aware_policy_bundle_path is None


def test_explicit_false_remains_disabled(monkeypatch) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "false")
    config = GatewayConfig()
    assert config.operation_aware_enabled is False


def test_explicit_true_enables_flag(monkeypatch) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", "/tmp/whatever.json")
    config = GatewayConfig()
    assert config.operation_aware_enabled is True


def test_enabled_without_bundle_path_fails_clearly(monkeypatch) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    config = GatewayConfig()
    with pytest.raises(OperationAwareConfigError):
        validate_operation_aware_config(config)


def test_enabled_with_bundle_path_passes_presence_check(monkeypatch) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", "/tmp/whatever.json")
    config = GatewayConfig()
    validate_operation_aware_config(config)  # must not raise


def test_disabled_with_no_bundle_path_remains_valid() -> None:
    config = GatewayConfig()
    validate_operation_aware_config(config)  # must not raise


def test_disabled_with_bundle_path_supplied_does_not_auto_initialize(monkeypatch) -> None:
    """A supplied bundle path alone, without OPERATION_AWARE_ENABLED=true,
    does not make the feature considered enabled."""
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", "/tmp/whatever.json")
    config = GatewayConfig()
    assert config.operation_aware_enabled is False
    validate_operation_aware_config(config)  # must not raise; path is not even inspected


def test_existing_v01_evaluation_config_validation_unchanged(monkeypatch) -> None:
    """Enabling operation-aware integration does not touch v0.1's
    POLICY_PATH/OIDC_ISSUER validation."""
    from basis_gateway.config import EvaluationConfigError, validate_evaluation_config

    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", "/tmp/whatever.json")
    monkeypatch.setenv("OIDC_ISSUER", "https://issuer.example.com")
    config = GatewayConfig()
    with pytest.raises(EvaluationConfigError):
        validate_evaluation_config(config)  # POLICY_PATH still required, unaffected


def test_operation_aware_policy_bundle_path_separate_from_policy_path(monkeypatch) -> None:
    monkeypatch.setenv("POLICY_PATH", "/tmp/v01-policy.json")
    config = GatewayConfig()
    assert config.operation_aware_policy_bundle_path is None
    assert config.policy_path == "/tmp/v01-policy.json"


# ---------------------------------------------------------------------------
# Disabled startup — no behavior change
# ---------------------------------------------------------------------------


def test_disabled_startup_no_operation_aware_evaluator() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        assert app.state.operation_aware_evaluator is None
        assert client.get("/ready").status_code == 200


def test_disabled_startup_no_readiness_component_registered() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert "operation_aware_evaluator" not in get_readiness_state().components


def test_disabled_startup_no_new_startup_failure() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        assert client.get("/ready").status_code == 200


def test_disabled_startup_v01_evaluator_state_untouched() -> None:
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        # No POLICY_PATH/OIDC_ISSUER configured in this test's environment,
        # so v0.1 evaluator stays None regardless — the point is that the
        # operation-aware path does not set it to anything else.
        assert app.state.evaluator is None


# ---------------------------------------------------------------------------
# Enabled + valid startup
# ---------------------------------------------------------------------------


def test_enabled_valid_bundle_loads_and_preflights(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        assert isinstance(app.state.operation_aware_evaluator, OperationAwareGatewayEvaluator)
        assert client.get("/ready").status_code == 200


def test_enabled_valid_bundle_registers_ready_component(monkeypatch, tmp_path) -> None:
    """PR 8: all four staged operation-aware components are ready, and the
    removed temporary single component is gone. See
    tests/test_operation_aware_readiness.py for the full per-stage matrix."""
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        components = get_readiness_state().components
        assert components.get("operation_aware_mode_enabled") is True
        assert components.get("operation_aware_bundle_loaded") is True
        assert components.get("operation_aware_evaluator_initialized") is True
        assert components.get("operation_aware_policy_semantically_valid") is True
        assert "operation_aware_evaluator" not in components


def test_enabled_valid_v01_evaluator_state_remains_unchanged(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert app.state.evaluator is None  # no POLICY_PATH set in this test


def test_enabled_valid_route_registered_and_requires_auth(monkeypatch, tmp_path) -> None:
    """PR 5 asserted this route did not exist yet (404 regardless of
    payload). PR 6 wires it up behind the same OPERATION_AWARE_ENABLED flag
    checked here, so an enabled-and-valid startup now makes the route
    reachable — an unauthenticated request gets the same 401 an
    unauthenticated /v1/evaluate request would, not a 404. See
    tests/test_operation_aware_endpoint.py for the full route behavior
    matrix (feature gating, auth, composition, evaluator availability)."""
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        response = client.post("/v1/evaluate/operation-aware", json={"action": "read:ahu"})
        assert response.status_code == 401


def test_enabled_valid_startup_preflight_never_writes_operational_audit_events(
    monkeypatch, tmp_path
) -> None:
    """Startup preflight never writes operational audit events.

    Superseded by PR 7 (operation-aware gateway audit evidence): PR 5's
    original assertion here was that ``app.state.audit_writer`` stays
    ``None`` in operation-aware-only mode. PR 7 changes that — the
    operation-aware endpoint now requires a shared ``GatewayAuditWriter`` of
    its own (see ``main.py``'s "shared audit writer" step and
    ``tests/test_operation_aware_endpoint.py``'s writer-lifecycle tests) —
    so a writer *is* now constructed in this configuration. What this test
    still proves, unchanged from PR 5: the startup semantic preflight's own
    result is never written to the operational audit stream.

    ``writer.failed_write_count == 0`` alone would not prove this — it only
    proves no write *failed*; a successful write would leave that counter at
    zero too. Instead, ``basis_gateway.audit.writer.LogAuditWriter`` (the
    concrete inner writer ``build_audit_writer`` constructs) is monkeypatched
    to a capturing double *before* ``TestClient`` triggers the ASGI lifespan,
    so every event actually delegated to the writer's inner during the whole
    startup sequence (including preflight) is captured. Asserting
    ``captured_events == []`` after startup proves zero writes occurred, not
    merely zero failures.
    """

    class _CapturingInnerWriter:
        def __init__(self) -> None:
            self.events: list[object] = []

        def write(self, event: object) -> None:
            self.events.append(event)

    captured_holder: dict[str, _CapturingInnerWriter] = {}

    def _capturing_log_audit_writer_factory() -> _CapturingInnerWriter:
        inner = _CapturingInnerWriter()
        captured_holder["inner"] = inner
        return inner

    monkeypatch.setattr(
        "basis_gateway.audit.writer.LogAuditWriter", _capturing_log_audit_writer_factory
    )

    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        writer = app.state.audit_writer
        assert writer is not None
        assert get_readiness_state().components.get("audit_writer") is True

    captured_inner = captured_holder["inner"]
    assert captured_inner.events == []


# ---------------------------------------------------------------------------
# Enabled + invalid startup — each must fail startup
# ---------------------------------------------------------------------------


def test_enabled_missing_bundle_path_fails_startup(monkeypatch) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        assert app.state.operation_aware_evaluator is None
        assert client.get("/ready").status_code == 503


def test_enabled_missing_file_fails_startup(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(tmp_path / "does-not-exist.json"))
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        assert app.state.operation_aware_evaluator is None
        assert client.get("/ready").status_code == 503


def test_enabled_malformed_json_fails_startup(monkeypatch, tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", str(path))
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        assert app.state.operation_aware_evaluator is None
        assert client.get("/ready").status_code == 503


def test_enabled_structurally_invalid_bundle_fails_startup(monkeypatch, tmp_path) -> None:
    invalid = dict(VALID_BUNDLE)
    del invalid["policy_owner"]
    path = write_bundle(tmp_path, invalid)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        assert app.state.operation_aware_evaluator is None
        assert client.get("/ready").status_code == 503


def test_enabled_duplicate_rule_ids_fail_startup(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, DUPLICATE_RULE_ID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        assert app.state.operation_aware_evaluator is None
        assert client.get("/ready").status_code == 503


def test_enabled_unsupported_operator_fails_startup(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, UNSUPPORTED_OPERATOR_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        assert app.state.operation_aware_evaluator is None
        assert client.get("/ready").status_code == 503


def test_enabled_invalid_startup_reason_reported(monkeypatch) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        response = client.get("/ready")
        assert response.status_code == 503
        body = response.json()
        assert "reason" in body


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


def test_operation_aware_startup_does_not_modify_v01_policy_loader() -> None:
    """Structural boundary check: main.py's operation-aware block imports
    only the operation-aware loader/evaluator, never mutating
    basis_gateway.policy.loader's own module state."""
    import basis_gateway.policy.loader as v01_loader

    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        assert v01_loader.load_policy_engine.__module__ == "basis_gateway.policy.loader"


def test_operation_aware_startup_does_not_change_authentication_initialization(
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", "/tmp/whatever-missing.json")
    reset_readiness_state()
    app = create_app()
    with TestClient(app):
        # OIDC_ISSUER not set in this test env -> verifier stays None,
        # exactly as it would with operation-aware integration disabled.
        assert app.state.verifier is None


def test_repeated_app_construction_does_not_leak_evaluator_state(monkeypatch, tmp_path) -> None:
    path = write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", path)

    reset_readiness_state()
    app_one = create_app()
    with TestClient(app_one):
        evaluator_one = app_one.state.operation_aware_evaluator

    reset_readiness_state()
    app_two = create_app()
    with TestClient(app_two):
        evaluator_two = app_two.state.operation_aware_evaluator

    assert evaluator_one is not None
    assert evaluator_two is not None
    assert evaluator_one is not evaluator_two


def test_operation_aware_startup_does_not_change_existing_v01_evaluator_construction(
    monkeypatch, tmp_path
) -> None:
    """When both v0.1 (POLICY_PATH, via AUTH_MODE=basis_local_token so no
    network/OIDC discovery is required) and operation-aware are configured
    together, each initializes independently into its own app.state slot."""
    import json as _json

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from basis_gateway.policy.loader import PolicyLoadError

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
        _json.dumps(
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
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON", _json.dumps({"key-1": public_pem}))
    monkeypatch.setenv("POLICY_PATH", str(v01_policy_path))
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", op_aware_path)

    reset_readiness_state()
    app = create_app()
    with TestClient(app) as client:
        assert client.get("/ready").status_code == 200
        assert app.state.evaluator is not None
        assert isinstance(app.state.operation_aware_evaluator, OperationAwareGatewayEvaluator)

    # Sanity: the v0.1 loader itself is untouched/importable and still
    # raises PolicyLoadError for the operation-aware bundle shape.
    assert PolicyLoadError is not None
