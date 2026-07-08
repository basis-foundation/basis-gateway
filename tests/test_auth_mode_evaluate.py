"""Endpoint-level tests: POST /v1/evaluate with AUTH_MODE=basis_local_token.

Exercises the full lifespan-wired path (real BasisLocalTokenTrustConfig
built from environment variables, real policy engine, real
EnforcementPoint) — not a mocked auth dependency — so these tests prove the
runtime wiring end to end. Existing OIDC-mode /v1/evaluate tests
(tests/test_evaluate.py) are untouched and continue to pass unmodified.
"""

from __future__ import annotations

import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi.testclient import TestClient

from basis_gateway.main import create_app
from basis_gateway.readiness import reset_readiness_state

ISSUER = "https://identity.basis.example.com"
AUDIENCE = "basis-gateway"
KID = "basis-local-key-1"


@pytest.fixture(scope="module")
def rsa_private_key() -> RSAPrivateKey:
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


def _basis_local_claims(subject_id: str = "user-123", roles: tuple[str, ...] = ("admin",)) -> dict:
    now = int(time.time())
    return {
        "iss": ISSUER,
        "sub": subject_id,
        "aud": [AUDIENCE],
        "iat": now,
        "exp": now + 600,
        "jti": "tok-1",
        "typ": "basis-local-identity",
        "basis": {
            "session_id": "sess-1",
            "provider_id": "keycloak-primary",
            "authority_mode": "federated",
            "authentication_protocol": "oidc",
            "canonical_identity": {
                "subject": {
                    "subject_id": subject_id,
                    "roles": list(roles),
                    "display_name": "Alice",
                    "email": "alice@example.com",
                },
            },
        },
    }


def _basis_local_token(rsa_private_key: RSAPrivateKey, **claim_overrides: Any) -> str:
    claims = _basis_local_claims()
    claims.update(claim_overrides)
    return jwt.encode(claims, rsa_private_key, algorithm="RS256", headers={"kid": KID})


@pytest.fixture()
def basis_local_client(monkeypatch, tmp_path, rsa_private_key: RSAPrivateKey):
    """TestClient with the gateway fully lifespan-wired for AUTH_MODE=basis_local_token."""
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
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
        ),
        encoding="utf-8",
    )

    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.setenv("AUTH_MODE", "basis_local_token")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_ISSUER", ISSUER)
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_AUDIENCE", AUDIENCE)
    monkeypatch.setenv(
        "BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON",
        json.dumps({KID: _public_pem(rsa_private_key)}),
    )
    monkeypatch.setenv("POLICY_PATH", str(policy_path))

    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def _evaluate(client, token: str | None, action: str, resource_id: str = "sensor:ahu-1", **extra):
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    body = {"action": action, "resource_id": resource_id, **extra}
    return client.post("/v1/evaluate", json=body, headers=headers)


# ---------------------------------------------------------------------------
# Readiness
# ---------------------------------------------------------------------------


def test_ready_when_basis_local_token_mode_fully_configured(basis_local_client):
    resp = basis_local_client.get("/ready")
    assert resp.status_code == 200
    assert resp.json()["components"]["basis_local_token_configured"] is True


# ---------------------------------------------------------------------------
# Valid token → real basis-core decision
# ---------------------------------------------------------------------------


def test_evaluate_allows_with_valid_basis_local_token(basis_local_client, rsa_private_key):
    token = _basis_local_token(rsa_private_key, roles=("admin",))
    resp = _evaluate(basis_local_client, token, "read:sensor:telemetry")
    assert resp.status_code == 200
    assert resp.json()["outcome"] == "allow"


def test_evaluate_denies_with_insufficient_role(basis_local_client, rsa_private_key):
    token = _basis_local_token(
        rsa_private_key,
        basis={
            **_basis_local_claims()["basis"],
            "canonical_identity": {
                "subject": {
                    "subject_id": "user-123",
                    "roles": ["viewer"],
                    "display_name": "Alice",
                    "email": "alice@example.com",
                },
            },
        },
    )
    resp = _evaluate(basis_local_client, token, "write:hvac:setpoint")
    assert resp.status_code == 403
    assert resp.json()["outcome"] == "deny"


# ---------------------------------------------------------------------------
# Authentication failures
# ---------------------------------------------------------------------------


def test_evaluate_missing_token_rejected_in_basis_local_mode(basis_local_client):
    resp = _evaluate(basis_local_client, None, "read:sensor:telemetry")
    assert resp.status_code == 401


def test_evaluate_invalid_token_rejected_in_basis_local_mode(basis_local_client):
    resp = _evaluate(basis_local_client, "not-a-real-token", "read:sensor:telemetry")
    assert resp.status_code == 401


def test_evaluate_expired_token_rejected_in_basis_local_mode(basis_local_client, rsa_private_key):
    token = _basis_local_token(rsa_private_key, exp=int(time.time()) - 10)
    resp = _evaluate(basis_local_client, token, "read:sensor:telemetry")
    assert resp.status_code == 401


def test_evaluate_wrong_issuer_rejected_in_basis_local_mode(basis_local_client, rsa_private_key):
    token = _basis_local_token(rsa_private_key, iss="https://someone-else.example.com")
    resp = _evaluate(basis_local_client, token, "read:sensor:telemetry")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Caller-supplied subject still rejected
# ---------------------------------------------------------------------------


def test_evaluate_rejects_caller_supplied_subject_in_basis_local_mode(
    basis_local_client, rsa_private_key
):
    token = _basis_local_token(rsa_private_key)
    resp = _evaluate(
        basis_local_client,
        token,
        "read:sensor:telemetry",
        subject_id="someone-else",
    )
    assert resp.status_code == 400
