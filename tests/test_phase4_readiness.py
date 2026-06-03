"""Phase 4 readiness and configuration tests.

Covers:
  - /ready exposes components dict
  - 503 when policy_loaded component not ready
  - 503 when evaluator_initialized component not ready
  - configuration validation: OIDC without POLICY_PATH fails startup
  - startup with POLICY_PATH wires evaluator and marks all components ready
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from basis_gateway.config import EvaluationConfigError, GatewayConfig, validate_evaluation_config
from basis_gateway.main import create_app
from basis_gateway.readiness import get_readiness_state, reset_readiness_state

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_policy(tmp_path: Path, data: object = None) -> str:
    if data is None:
        data = {
            "rules": [
                {
                    "rule_name": "test-rbac",
                    "role_table": {
                        "read:sensor:telemetry": ["viewer", "admin"],
                        "write:hvac:setpoint": ["admin"],
                    },
                }
            ]
        }
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# /ready components dict
# ---------------------------------------------------------------------------


def test_ready_includes_components_when_ready(client):
    response = client.get("/ready")
    assert response.status_code == 200
    body = response.json()
    assert "components" in body
    assert isinstance(body["components"], dict)


def test_ready_includes_components_when_not_ready(client):
    get_readiness_state().mark_not_ready("policy not loaded", component="policy_loaded")
    response = client.get("/ready")
    assert response.status_code == 503
    body = response.json()
    assert "components" in body
    assert body["components"]["policy_loaded"] is False


def test_ready_503_when_policy_loaded_not_ready(client):
    get_readiness_state().mark_not_ready("policy file missing", component="policy_loaded")
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


def test_ready_503_when_evaluator_not_ready(client):
    get_readiness_state().mark_not_ready("evaluator init failed", component="evaluator_initialized")
    response = client.get("/ready")
    assert response.status_code == 503


def test_ready_200_all_components_individually_ready(client):
    state = get_readiness_state()
    state.mark_ready("configuration_loaded")
    state.mark_ready("oidc_configured")
    state.mark_ready("jwks_available")
    state.mark_ready("policy_loaded")
    state.mark_ready("evaluator_initialized")
    response = client.get("/ready")
    assert response.status_code == 200
    components = response.json()["components"]
    for key in ("configuration_loaded", "oidc_configured", "jwks_available",
                "policy_loaded", "evaluator_initialized"):
        assert components[key] is True


def test_ready_503_if_any_single_component_not_ready(client):
    state = get_readiness_state()
    state.mark_ready("configuration_loaded")
    state.mark_ready("policy_loaded")
    state.mark_not_ready("evaluator failed", component="evaluator_initialized")
    response = client.get("/ready")
    assert response.status_code == 503


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------


def test_validate_evaluation_config_passes_without_oidc():
    config = GatewayConfig()
    # Should not raise — evaluation endpoint is not enabled.
    validate_evaluation_config(config)


def test_validate_evaluation_config_passes_with_oidc_and_policy(tmp_path):
    p = write_policy(tmp_path)
    config = GatewayConfig(oidc_issuer="https://issuer.example.com", policy_path=p)
    validate_evaluation_config(config)  # no exception


def test_validate_evaluation_config_fails_oidc_without_policy():
    config = GatewayConfig(oidc_issuer="https://issuer.example.com")
    with pytest.raises(EvaluationConfigError, match="POLICY_PATH"):
        validate_evaluation_config(config)


def test_validate_evaluation_config_policy_path_without_oidc_is_ok(tmp_path):
    p = write_policy(tmp_path)
    config = GatewayConfig(policy_path=p)
    validate_evaluation_config(config)  # allowed — evaluation not enabled


# ---------------------------------------------------------------------------
# Startup with POLICY_PATH — evaluator initialized
# ---------------------------------------------------------------------------


def test_startup_with_policy_path_marks_policy_loaded(tmp_path, monkeypatch):
    p = write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", p)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        response = c.get("/ready")
        assert response.status_code == 200
        components = response.json()["components"]
        assert components.get("policy_loaded") is True
        assert components.get("evaluator_initialized") is True


def test_startup_with_policy_path_sets_evaluator_on_app_state(tmp_path, monkeypatch):
    p = write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", p)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=True):
        assert app.state.evaluator is not None


def test_startup_without_policy_path_evaluator_is_none(monkeypatch):
    monkeypatch.delenv("POLICY_PATH", raising=False)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=True):
        assert app.state.evaluator is None


# ---------------------------------------------------------------------------
# Startup failure: bad policy file → /ready 503
# ---------------------------------------------------------------------------


def test_startup_missing_policy_file_returns_503(tmp_path, monkeypatch):
    monkeypatch.setenv("POLICY_PATH", str(tmp_path / "nonexistent.json"))
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        response = c.get("/ready")
        assert response.status_code == 503


def test_startup_invalid_policy_json_returns_503(tmp_path, monkeypatch):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json }", encoding="utf-8")
    monkeypatch.setenv("POLICY_PATH", str(bad))
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        response = c.get("/ready")
        assert response.status_code == 503


def test_startup_evaluator_fail_marks_not_ready_component(tmp_path, monkeypatch):
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")  # missing 'rules'
    monkeypatch.setenv("POLICY_PATH", str(bad))
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        body = c.get("/ready").json()
        assert body["status"] == "not_ready"
        # policy_loaded should be marked false
        assert body["components"].get("policy_loaded") is False


# ---------------------------------------------------------------------------
# Startup failure: OIDC enabled but POLICY_PATH absent
# ---------------------------------------------------------------------------


def test_startup_oidc_without_policy_path_not_ready(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER", "https://issuer.example.com")
    monkeypatch.delenv("POLICY_PATH", raising=False)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        response = c.get("/ready")
        assert response.status_code == 503
        assert "POLICY_PATH" in response.json()["reason"]
