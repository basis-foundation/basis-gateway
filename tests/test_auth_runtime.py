"""Tests for runtime auth-mode selection (basis_gateway.auth.runtime).

Covers: OIDC mode dispatches to the OIDC verifier + subject mapper,
basis_local_token mode dispatches to the BASIS-local verifier, neither mode
ever falls back to the other, unconfigured verifier/trust config fails
closed, and build_basis_local_token_trust_config's environment-parsing
behavior.
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
from helpers import MockVerifier

from basis_gateway.auth.basis_local_token import (
    BasisLocalTokenTrustConfig,
    BasisLocalTokenVerificationError,
)
from basis_gateway.auth.errors import AuthenticationError, JWTVerificationError
from basis_gateway.auth.runtime import (
    AuthNotConfiguredError,
    UnsupportedAuthModeError,
    authenticate,
    build_basis_local_token_trust_config,
)
from basis_gateway.auth.subject_mapper import IdentityContext, NormalizedSubject
from basis_gateway.config import AuthMode, EvaluationConfigError, GatewayConfig

ISSUER = "https://identity.basis.example.com"
AUDIENCE = "basis-gateway"
KID = "basis-local-key-1"


# ---------------------------------------------------------------------------
# Key / token fixtures
# ---------------------------------------------------------------------------


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


@pytest.fixture()
def trust_config(rsa_private_key: RSAPrivateKey) -> BasisLocalTokenTrustConfig:
    return BasisLocalTokenTrustConfig(
        issuer=ISSUER,
        audience=(AUDIENCE,),
        public_keys_by_id={KID: _public_pem(rsa_private_key)},
    )


def _basis_local_claims(subject_id: str = "user-123") -> dict[str, Any]:
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
                    "roles": ["admin"],
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


# ---------------------------------------------------------------------------
# OIDC mode dispatch
# ---------------------------------------------------------------------------


def test_oidc_mode_calls_oidc_verifier_and_subject_mapper():
    verifier = MockVerifier(claims={"sub": "user1", "iss": "https://test.example.com"})
    subject, identity_ctx = authenticate(
        auth_mode=AuthMode.OIDC,
        token="anything",
        oidc_verifier=verifier,
        basis_local_trust_config=None,
    )
    assert isinstance(subject, NormalizedSubject)
    assert subject.subject_id == "user1"
    assert isinstance(identity_ctx, IdentityContext)
    assert identity_ctx.issuer == "https://test.example.com"


def test_oidc_mode_without_verifier_fails_closed():
    with pytest.raises(AuthNotConfiguredError):
        authenticate(
            auth_mode=AuthMode.OIDC,
            token="anything",
            oidc_verifier=None,
            basis_local_trust_config=None,
        )


def test_oidc_mode_invalid_token_fails_closed():
    verifier = MockVerifier(claims={"sub": "user1"})
    verifier.set_raise(JWTVerificationError("bad token"))
    with pytest.raises(AuthenticationError):
        authenticate(
            auth_mode=AuthMode.OIDC,
            token="bad",
            oidc_verifier=verifier,
            basis_local_trust_config=None,
        )


def test_oidc_mode_never_attempts_basis_local_verification(trust_config):
    """A BASIS-local trust config being present must not matter in OIDC mode."""
    verifier = MockVerifier(claims={"sub": "user1", "iss": "https://test.example.com"})
    subject, _ = authenticate(
        auth_mode=AuthMode.OIDC,
        token="anything",
        oidc_verifier=verifier,
        basis_local_trust_config=trust_config,  # present but must be ignored
    )
    assert subject.subject_id == "user1"


# ---------------------------------------------------------------------------
# BASIS-local token mode dispatch
# ---------------------------------------------------------------------------


def test_basis_local_token_mode_calls_verifier(trust_config, rsa_private_key):
    token = _basis_local_token(rsa_private_key)
    subject, identity_ctx = authenticate(
        auth_mode=AuthMode.BASIS_LOCAL_TOKEN,
        token=token,
        oidc_verifier=None,
        basis_local_trust_config=trust_config,
    )
    assert isinstance(subject, NormalizedSubject)
    assert subject.subject_id == "user-123"
    assert isinstance(identity_ctx, IdentityContext)
    assert identity_ctx.issuer == ISSUER


def test_basis_local_token_mode_without_trust_config_fails_closed():
    with pytest.raises(AuthNotConfiguredError):
        authenticate(
            auth_mode=AuthMode.BASIS_LOCAL_TOKEN,
            token="anything",
            oidc_verifier=None,
            basis_local_trust_config=None,
        )


def test_basis_local_token_mode_invalid_token_fails_closed(trust_config):
    with pytest.raises(AuthenticationError):
        authenticate(
            auth_mode=AuthMode.BASIS_LOCAL_TOKEN,
            token="not-a-real-jwt",
            oidc_verifier=None,
            basis_local_trust_config=trust_config,
        )


def test_basis_local_token_mode_expired_token_fails_closed(trust_config, rsa_private_key):
    token = _basis_local_token(rsa_private_key, exp=int(time.time()) - 10)
    with pytest.raises(BasisLocalTokenVerificationError, match="expired"):
        authenticate(
            auth_mode=AuthMode.BASIS_LOCAL_TOKEN,
            token=token,
            oidc_verifier=None,
            basis_local_trust_config=trust_config,
        )


def test_basis_local_token_mode_wrong_issuer_fails_closed(trust_config, rsa_private_key):
    token = _basis_local_token(rsa_private_key, iss="https://someone-else.example.com")
    with pytest.raises(BasisLocalTokenVerificationError, match="issuer"):
        authenticate(
            auth_mode=AuthMode.BASIS_LOCAL_TOKEN,
            token=token,
            oidc_verifier=None,
            basis_local_trust_config=trust_config,
        )


def test_basis_local_token_mode_wrong_audience_fails_closed(trust_config, rsa_private_key):
    token = _basis_local_token(rsa_private_key, aud=["someone-else"])
    with pytest.raises(BasisLocalTokenVerificationError, match="audience"):
        authenticate(
            auth_mode=AuthMode.BASIS_LOCAL_TOKEN,
            token=token,
            oidc_verifier=None,
            basis_local_trust_config=trust_config,
        )


def test_basis_local_token_mode_wrong_key_fails_closed(trust_config):
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _basis_local_token(other_key)
    with pytest.raises(AuthenticationError):
        authenticate(
            auth_mode=AuthMode.BASIS_LOCAL_TOKEN,
            token=token,
            oidc_verifier=None,
            basis_local_trust_config=trust_config,
        )


def test_basis_local_token_mode_never_attempts_oidc_verification(trust_config, rsa_private_key):
    """An OIDC verifier being present must not matter in BASIS-local mode."""
    oidc_verifier = MockVerifier(claims={"sub": "should-not-be-used"})
    token = _basis_local_token(rsa_private_key)
    subject, _ = authenticate(
        auth_mode=AuthMode.BASIS_LOCAL_TOKEN,
        token=token,
        oidc_verifier=oidc_verifier,  # present but must be ignored
        basis_local_trust_config=trust_config,
    )
    assert subject.subject_id == "user-123"


# ---------------------------------------------------------------------------
# No fallback between modes
# ---------------------------------------------------------------------------


def test_oidc_token_not_attempted_as_basis_local_unless_mode_is_basis_local():
    """An OIDC-shaped mock verifier's presence must not leak into BASIS-local mode."""
    with pytest.raises(AuthNotConfiguredError):
        authenticate(
            auth_mode=AuthMode.BASIS_LOCAL_TOKEN,
            token="oidc-token",
            oidc_verifier=MockVerifier(claims={"sub": "user1"}),
            basis_local_trust_config=None,  # BASIS-local not configured
        )


def test_basis_local_token_not_attempted_as_oidc_unless_mode_is_oidc(trust_config):
    with pytest.raises(AuthNotConfiguredError):
        authenticate(
            auth_mode=AuthMode.OIDC,
            token="basis-local-token",
            oidc_verifier=None,  # OIDC not configured
            basis_local_trust_config=trust_config,
        )


def test_unsupported_auth_mode_fails_closed(trust_config):
    class _NotAnAuthMode:
        pass

    with pytest.raises(UnsupportedAuthModeError):
        authenticate(
            auth_mode=_NotAnAuthMode(),  # type: ignore[arg-type]
            token="anything",
            oidc_verifier=None,
            basis_local_trust_config=trust_config,
        )


# ---------------------------------------------------------------------------
# build_basis_local_token_trust_config
# ---------------------------------------------------------------------------


def test_build_trust_config_from_env(rsa_private_key: RSAPrivateKey):
    config = GatewayConfig(
        auth_mode=AuthMode.BASIS_LOCAL_TOKEN,
        basis_local_token_issuer=ISSUER,
        basis_local_token_audience=AUDIENCE,
        basis_local_token_public_keys_json=json.dumps({KID: _public_pem(rsa_private_key)}),
    )
    trust_config = build_basis_local_token_trust_config(config)
    assert trust_config.issuer == ISSUER
    assert trust_config.audience == (AUDIENCE,)
    assert KID in trust_config.public_keys_by_id


def test_build_trust_config_missing_issuer_raises():
    config = GatewayConfig(
        basis_local_token_audience=AUDIENCE,
        basis_local_token_public_keys_json="{}",
    )
    with pytest.raises(EvaluationConfigError, match="BASIS_LOCAL_TOKEN_ISSUER"):
        build_basis_local_token_trust_config(config)


def test_build_trust_config_missing_audience_raises():
    config = GatewayConfig(
        basis_local_token_issuer=ISSUER,
        basis_local_token_public_keys_json="{}",
    )
    with pytest.raises(EvaluationConfigError, match="BASIS_LOCAL_TOKEN_AUDIENCE"):
        build_basis_local_token_trust_config(config)


def test_build_trust_config_missing_public_keys_raises():
    config = GatewayConfig(
        basis_local_token_issuer=ISSUER,
        basis_local_token_audience=AUDIENCE,
    )
    with pytest.raises(EvaluationConfigError, match="BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON"):
        build_basis_local_token_trust_config(config)


def test_build_trust_config_invalid_json_raises():
    config = GatewayConfig(
        basis_local_token_issuer=ISSUER,
        basis_local_token_audience=AUDIENCE,
        basis_local_token_public_keys_json="not json",
    )
    with pytest.raises(EvaluationConfigError, match="not valid JSON"):
        build_basis_local_token_trust_config(config)


def test_build_trust_config_empty_object_raises():
    config = GatewayConfig(
        basis_local_token_issuer=ISSUER,
        basis_local_token_audience=AUDIENCE,
        basis_local_token_public_keys_json="{}",
    )
    with pytest.raises(EvaluationConfigError, match="non-empty JSON object"):
        build_basis_local_token_trust_config(config)


def test_build_trust_config_comma_separated_audience(rsa_private_key: RSAPrivateKey):
    config = GatewayConfig(
        basis_local_token_issuer=ISSUER,
        basis_local_token_audience="aud-1, aud-2",
        basis_local_token_public_keys_json=json.dumps({KID: _public_pem(rsa_private_key)}),
    )
    trust_config = build_basis_local_token_trust_config(config)
    assert trust_config.audience == ("aud-1", "aud-2")
