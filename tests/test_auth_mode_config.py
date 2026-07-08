"""Tests for AUTH_MODE / BASIS-local token trust configuration (config.py).

Covers: the AuthMode enum, the default preserving pre-existing OIDC-only
behavior, presence validation for basis_local_token mode in
validate_evaluation_config, and independence between the two modes'
configuration surfaces (OIDC settings not required in basis_local_token
mode and vice versa).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from basis_gateway.config import (
    AuthMode,
    EvaluationConfigError,
    GatewayConfig,
    validate_evaluation_config,
)

# ---------------------------------------------------------------------------
# AUTH_MODE field
# ---------------------------------------------------------------------------


def test_default_auth_mode_is_oidc():
    config = GatewayConfig()
    assert config.auth_mode == AuthMode.OIDC


def test_auth_mode_oidc_accepted(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "oidc")
    config = GatewayConfig()
    assert config.auth_mode == AuthMode.OIDC


def test_auth_mode_basis_local_token_accepted(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "basis_local_token")
    config = GatewayConfig()
    assert config.auth_mode == AuthMode.BASIS_LOCAL_TOKEN


def test_invalid_auth_mode_rejected(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "saml")
    with pytest.raises(ValidationError):
        GatewayConfig()


def test_default_auth_mode_preserves_existing_oidc_behavior():
    """With AUTH_MODE unset, evaluation-enabled semantics are unchanged: driven
    by OIDC_ISSUER alone, exactly as before this field existed."""
    config = GatewayConfig(oidc_issuer="https://issuer.example.com")
    assert config.auth_mode == AuthMode.OIDC
    assert config.evaluation_enabled is True

    config_no_issuer = GatewayConfig()
    assert config_no_issuer.evaluation_enabled is False


# ---------------------------------------------------------------------------
# BASIS-local token trust field presence / defaults
# ---------------------------------------------------------------------------


def test_basis_local_token_fields_default_to_none_or_default_value():
    config = GatewayConfig()
    assert config.basis_local_token_issuer is None
    assert config.basis_local_token_audience is None
    assert config.basis_local_token_public_keys_json is None
    assert config.basis_local_token_allowed_algorithms == "RS256"
    assert config.basis_local_token_leeway_seconds == 0


def test_basis_local_token_leeway_negative_rejected(monkeypatch):
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_LEEWAY_SECONDS", "-1")
    with pytest.raises(ValidationError):
        GatewayConfig()


def test_basis_local_token_leeway_positive_accepted(monkeypatch):
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_LEEWAY_SECONDS", "5")
    config = GatewayConfig()
    assert config.basis_local_token_leeway_seconds == 5


def test_basis_local_token_env_overrides(monkeypatch):
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_ISSUER", "https://identity.basis.example.com")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_AUDIENCE", "basis-gateway")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON", '{"k1": "pem"}')
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_ALLOWED_ALGORITHMS", "RS256,RS384")
    config = GatewayConfig()
    assert config.basis_local_token_issuer == "https://identity.basis.example.com"
    assert config.basis_local_token_audience == "basis-gateway"
    assert config.basis_local_token_public_keys_json == '{"k1": "pem"}'
    assert config.basis_local_token_allowed_algorithms == "RS256,RS384"


# ---------------------------------------------------------------------------
# validate_evaluation_config: OIDC mode (default) — unchanged behavior
# ---------------------------------------------------------------------------


def test_validate_oidc_mode_without_issuer_is_ok():
    config = GatewayConfig()
    validate_evaluation_config(config)  # no exception


def test_validate_oidc_mode_with_issuer_and_policy_ok(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text("{}", encoding="utf-8")
    config = GatewayConfig(oidc_issuer="https://issuer.example.com", policy_path=str(p))
    validate_evaluation_config(config)


def test_validate_oidc_mode_with_issuer_without_policy_fails():
    config = GatewayConfig(oidc_issuer="https://issuer.example.com")
    with pytest.raises(EvaluationConfigError, match="POLICY_PATH"):
        validate_evaluation_config(config)


def test_validate_oidc_mode_does_not_require_basis_local_fields():
    """BASIS-local settings are not required for OIDC mode."""
    p = "policies/default.json"
    config = GatewayConfig(oidc_issuer="https://issuer.example.com", policy_path=p)
    # No BASIS_LOCAL_TOKEN_* fields set at all — must not raise.
    validate_evaluation_config(config)


# ---------------------------------------------------------------------------
# validate_evaluation_config: basis_local_token mode
# ---------------------------------------------------------------------------


def _basis_local_config(tmp_path, **overrides):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("{}", encoding="utf-8")
    defaults: dict[str, object] = {
        "auth_mode": AuthMode.BASIS_LOCAL_TOKEN,
        "basis_local_token_issuer": "https://identity.basis.example.com",
        "basis_local_token_audience": "basis-gateway",
        "basis_local_token_public_keys_json": (
            '{"key-1": "-----BEGIN PUBLIC KEY-----\\nabc\\n-----END PUBLIC KEY-----"}'
        ),
        "policy_path": str(policy_path),
    }
    defaults.update(overrides)
    return GatewayConfig(**defaults)


def test_validate_basis_local_token_mode_complete_config_ok(tmp_path):
    config = _basis_local_config(tmp_path)
    validate_evaluation_config(config)  # no exception


def test_validate_basis_local_token_mode_requires_issuer(tmp_path):
    config = _basis_local_config(tmp_path, basis_local_token_issuer=None)
    with pytest.raises(EvaluationConfigError, match="BASIS_LOCAL_TOKEN_ISSUER"):
        validate_evaluation_config(config)


def test_validate_basis_local_token_mode_requires_audience(tmp_path):
    config = _basis_local_config(tmp_path, basis_local_token_audience=None)
    with pytest.raises(EvaluationConfigError, match="BASIS_LOCAL_TOKEN_AUDIENCE"):
        validate_evaluation_config(config)


def test_validate_basis_local_token_mode_requires_public_keys(tmp_path):
    config = _basis_local_config(tmp_path, basis_local_token_public_keys_json=None)
    with pytest.raises(EvaluationConfigError, match="BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON"):
        validate_evaluation_config(config)


def test_validate_basis_local_token_mode_requires_policy_path(tmp_path):
    config = _basis_local_config(tmp_path, policy_path=None)
    with pytest.raises(EvaluationConfigError, match="POLICY_PATH"):
        validate_evaluation_config(config)


def test_validate_basis_local_token_mode_does_not_require_oidc_issuer(tmp_path):
    """OIDC settings are not required for BASIS-local mode."""
    config = _basis_local_config(tmp_path)
    assert config.oidc_issuer is None
    validate_evaluation_config(config)  # must not raise despite oidc_issuer being unset


def test_evaluation_enabled_true_for_basis_local_token_mode(tmp_path):
    config = _basis_local_config(tmp_path)
    assert config.evaluation_enabled is True
