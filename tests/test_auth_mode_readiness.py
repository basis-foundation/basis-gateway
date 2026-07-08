"""Readiness tests for auth-mode wiring.

Covers: the "basis_local_token_configured" component is reported in
basis_local_token mode, OIDC readiness components are simply not
registered (and therefore cannot block) in that mode and vice versa, and
incomplete/invalid BASIS-local configuration fails readiness rather than
crashing the process.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi.testclient import TestClient
from pydantic import ValidationError

from basis_gateway.config import GatewayConfig
from basis_gateway.main import create_app
from basis_gateway.readiness import reset_readiness_state

ISSUER = "https://identity.basis.example.com"
AUDIENCE = "basis-gateway"
KID = "basis-local-key-1"


@pytest.fixture(scope="module")
def rsa_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _public_pem(key: RSAPrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


def _write_policy(tmp_path) -> str:
    p = tmp_path / "policy.json"
    p.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "rule_name": "test-rbac",
                        "role_table": {"read:sensor:telemetry": ["viewer", "admin"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return str(p)


def _set_basis_local_env(monkeypatch, tmp_path, rsa_key: RSAPrivateKey, **overrides):
    env: dict[str, str | None] = {
        "AUTH_MODE": "basis_local_token",
        "BASIS_LOCAL_TOKEN_ISSUER": ISSUER,
        "BASIS_LOCAL_TOKEN_AUDIENCE": AUDIENCE,
        "BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON": json.dumps({KID: _public_pem(rsa_key)}),
        "POLICY_PATH": _write_policy(tmp_path),
    }
    env.update(overrides)
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    for key, value in env.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)


# ---------------------------------------------------------------------------
# BASIS-local trust readiness reported in basis_local_token mode
# ---------------------------------------------------------------------------


def test_basis_local_token_configured_ready_when_complete(monkeypatch, tmp_path, rsa_key):
    _set_basis_local_env(monkeypatch, tmp_path, rsa_key)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.get("/ready")
        assert resp.status_code == 200
        assert resp.json()["components"]["basis_local_token_configured"] is True


def test_oidc_components_not_registered_in_basis_local_token_mode(monkeypatch, tmp_path, rsa_key):
    """oidc_configured/jwks_available must not appear — and so never block readiness
    — when the gateway is explicitly in basis_local_token mode."""
    _set_basis_local_env(monkeypatch, tmp_path, rsa_key)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        components = c.get("/ready").json()["components"]
        assert "oidc_configured" not in components
        assert "jwks_available" not in components


def test_basis_local_token_mode_incomplete_config_fails_readiness(monkeypatch, tmp_path, rsa_key):
    _set_basis_local_env(monkeypatch, tmp_path, rsa_key, BASIS_LOCAL_TOKEN_AUDIENCE=None)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.get("/ready")
        assert resp.status_code == 503


def test_basis_local_token_mode_invalid_key_material_fails_readiness(
    monkeypatch, tmp_path, rsa_key
):
    """A private key supplied instead of a public key must fail readiness,
    not crash startup silently."""
    private_pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    _set_basis_local_env(
        monkeypatch,
        tmp_path,
        rsa_key,
        BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON=json.dumps({KID: private_pem}),
    )
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.get("/ready")
        assert resp.status_code == 503
        assert resp.json()["components"]["basis_local_token_configured"] is False


# ---------------------------------------------------------------------------
# OIDC readiness unaffected / not required in basis_local_token mode
# ---------------------------------------------------------------------------


def test_oidc_readiness_unchanged_in_oidc_mode(monkeypatch):
    """Default AUTH_MODE (oidc) without OIDC_ISSUER: unchanged pre-existing behavior."""
    monkeypatch.delenv("AUTH_MODE", raising=False)
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.delenv("POLICY_PATH", raising=False)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.get("/ready")
        assert resp.status_code == 200
        components = resp.json()["components"]
        assert "basis_local_token_configured" not in components
        assert "oidc_configured" not in components  # not registered when OIDC_ISSUER unset


def test_invalid_auth_mode_fails_at_construction(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "not-a-real-mode")
    with pytest.raises(ValidationError):
        GatewayConfig()
