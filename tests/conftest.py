"""Shared pytest fixtures for basis-gateway tests."""

from __future__ import annotations

import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from basis_gateway.core.evaluator import GatewayEvaluator, build_null_evaluator
from basis_gateway.main import create_app
from basis_gateway.readiness import get_readiness_state, reset_readiness_state

# ---------------------------------------------------------------------------
# RSA key fixtures (session-scoped — generated once per test run)
# ---------------------------------------------------------------------------

KID = "test-key-1"


@pytest.fixture(scope="session")
def rsa_private_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def jwks_payload(rsa_private_key: RSAPrivateKey) -> dict[str, Any]:
    pub_jwk = json.loads(RSAAlgorithm.to_jwk(rsa_private_key.public_key()))
    pub_jwk["kid"] = KID
    pub_jwk["use"] = "sig"
    pub_jwk["alg"] = "RS256"
    return {"keys": [pub_jwk]}


def make_token(
    private_key: RSAPrivateKey,
    *,
    sub: str = "user1",
    iss: str = "https://test.example.com",
    aud: str | None = None,
    exp_offset: int = 600,
    kid: str = KID,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    payload: dict[str, Any] = {
        "sub": sub,
        "iss": iss,
        "exp": int(time.time()) + exp_offset,
        "iat": int(time.time()),
        "preferred_username": sub,
        "realm_access": {"roles": ["admin", "viewer"]},
    }
    if aud:
        payload["aud"] = aud
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


# ---------------------------------------------------------------------------
# Basic app fixtures (no OIDC, no evaluator — for health/ready/config tests)
# ---------------------------------------------------------------------------


@pytest.fixture()
def app():
    reset_readiness_state()
    return create_app()


@pytest.fixture()
def client(app):
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Mock OIDC verifier
# ---------------------------------------------------------------------------


class MockVerifier:
    """Test double for OIDCVerifier. Returns pre-configured claims."""

    def __init__(self, claims: dict[str, Any]) -> None:
        self._claims = claims
        self._should_raise: Exception | None = None

    def set_raise(self, exc: Exception) -> None:
        self._should_raise = exc

    def clear_raise(self) -> None:
        self._should_raise = None

    def verify(self, token: str) -> dict[str, Any]:
        if self._should_raise is not None:
            raise self._should_raise
        return dict(self._claims)


@pytest.fixture()
def mock_verifier() -> MockVerifier:
    return MockVerifier(
        claims={
            "sub": "user1",
            "iss": "https://test.example.com",
            "preferred_username": "alice",
            "realm_access": {"roles": ["admin", "viewer"]},
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
        }
    )


# ---------------------------------------------------------------------------
# evaluate_client — real evaluator + mock verifier, state set after lifespan
# ---------------------------------------------------------------------------


@pytest.fixture()
def evaluate_client(mock_verifier: MockVerifier):
    """TestClient with a working evaluator and mock verifier.

    State is injected AFTER the lifespan runs (so lifespan doesn't overwrite it).
    Access the app via ``evaluate_client.app``.
    """
    reset_readiness_state()
    a = create_app()
    with TestClient(a, raise_server_exceptions=False) as c:
        # Lifespan has already run. Override with test dependencies.
        a.state.evaluator = build_null_evaluator()
        a.state.verifier = mock_verifier
        get_readiness_state().mark_ready("oidc")
        yield c


# ---------------------------------------------------------------------------
# Audit capture fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def captured_events() -> list:
    return []


@pytest.fixture()
def capturing_evaluator(captured_events: list) -> GatewayEvaluator:
    """GatewayEvaluator that stores audit events in a list for assertions."""
    from basis_core.audit import AuditEvent
    from basis_core.domain import action as actions
    from basis_core.enforcement import EnforcementPoint
    from basis_core.policy import PolicyEngine, RolePolicyRule

    class _CapturingWriter:
        def write(self, event: AuditEvent) -> None:
            captured_events.append(event)

    engine = PolicyEngine(
        policies=[
            RolePolicyRule(
                role_table={
                    actions.READ_SENSOR_TELEMETRY: {"admin", "viewer"},
                    actions.WRITE_HVAC_SETPOINT: {"admin"},
                },
                rule_name="test-rbac",
            )
        ]
    )
    ep = EnforcementPoint(engine=engine, audit_writer=_CapturingWriter(), policy_version="test")
    return GatewayEvaluator(_enforcement_point=ep)


@pytest.fixture()
def capture_client(capturing_evaluator: GatewayEvaluator, mock_verifier: MockVerifier):
    """TestClient wired with the capturing evaluator. Use for audit tests."""
    reset_readiness_state()
    a = create_app()
    with TestClient(a, raise_server_exceptions=False) as c:
        a.state.evaluator = capturing_evaluator
        a.state.verifier = mock_verifier
        get_readiness_state().mark_ready("oidc")
        yield c
