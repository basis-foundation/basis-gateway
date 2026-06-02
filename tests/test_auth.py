"""Tests for OIDC verifier: bearer extraction, discovery, JWKS, JWT verification.

All tests use locally generated RSA keys and a local mock HTTP server.
No live Keycloak or external network access is required.
"""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jwt.algorithms import RSAAlgorithm
from pytest_httpserver import HTTPServer

from basis_gateway.auth.errors import (
    JWKSFetchError,
    JWTVerificationError,
    OIDCDiscoveryError,
    TokenExtractionError,
)
from basis_gateway.auth.oidc import OIDCVerifier, extract_bearer_token

# ---------------------------------------------------------------------------
# Key fixtures
# ---------------------------------------------------------------------------

KID = "test-key-1"


@pytest.fixture(scope="session")
def rsa_private_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def jwks_payload(rsa_private_key: RSAPrivateKey) -> dict:
    """JWKS document exposing the test public key."""
    pub_jwk = json.loads(RSAAlgorithm.to_jwk(rsa_private_key.public_key()))
    pub_jwk["kid"] = KID
    pub_jwk["use"] = "sig"
    pub_jwk["alg"] = "RS256"
    return {"keys": [pub_jwk]}


def _make_token(
    private_key: RSAPrivateKey,
    *,
    sub: str = "user1",
    iss: str = "https://test.example.com",
    aud: str | None = None,
    exp_offset: int = 600,
    kid: str = KID,
    algorithm: str = "RS256",
    extra_claims: dict | None = None,
) -> str:
    payload: dict = {
        "sub": sub,
        "iss": iss,
        "exp": int(time.time()) + exp_offset,
        "iat": int(time.time()),
    }
    if aud:
        payload["aud"] = aud
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, private_key, algorithm=algorithm, headers={"kid": kid})


# ---------------------------------------------------------------------------
# Bearer token extraction
# ---------------------------------------------------------------------------


def test_extract_bearer_missing_header():
    with pytest.raises(TokenExtractionError, match="Missing"):
        extract_bearer_token(None)


def test_extract_bearer_wrong_scheme():
    with pytest.raises(TokenExtractionError, match="Bearer"):
        extract_bearer_token("Basic dXNlcjpwYXNz")


def test_extract_bearer_empty_scheme():
    with pytest.raises(TokenExtractionError, match="Bearer"):
        extract_bearer_token("")


def test_extract_bearer_empty_token():
    with pytest.raises(TokenExtractionError, match="empty"):
        extract_bearer_token("Bearer ")


def test_extract_bearer_whitespace_in_token():
    with pytest.raises(TokenExtractionError, match="whitespace"):
        extract_bearer_token("Bearer tok en")


def test_extract_bearer_valid():
    token = extract_bearer_token("Bearer mytoken123")
    assert token == "mytoken123"


def test_extract_bearer_valid_jwt_like():
    fake_jwt = "eyJ.eyJ.sig"
    token = extract_bearer_token(f"Bearer {fake_jwt}")
    assert token == fake_jwt


# ---------------------------------------------------------------------------
# OIDC discovery helpers
# ---------------------------------------------------------------------------


def test_oidc_discovery_success(httpserver: HTTPServer, jwks_payload: dict):
    issuer = f"http://{httpserver.host}:{httpserver.port}"
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_json(
        {"issuer": issuer, "jwks_uri": f"{issuer}/jwks"}
    )
    httpserver.expect_request("/jwks").respond_with_json(jwks_payload)

    verifier = OIDCVerifier.from_config(issuer=issuer)
    verifier.initialize()
    assert verifier._cache is not None


def test_oidc_discovery_issuer_mismatch(httpserver: HTTPServer):
    issuer = f"http://{httpserver.host}:{httpserver.port}"
    wrong_issuer = "https://wrong.example.com"
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_json(
        {"issuer": wrong_issuer, "jwks_uri": f"{issuer}/jwks"}
    )

    verifier = OIDCVerifier.from_config(issuer=issuer)
    with pytest.raises(OIDCDiscoveryError, match="mismatch"):
        verifier.initialize()


def test_oidc_discovery_missing_jwks_uri(httpserver: HTTPServer):
    issuer = f"http://{httpserver.host}:{httpserver.port}"
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_json(
        {"issuer": issuer}  # no jwks_uri
    )

    verifier = OIDCVerifier.from_config(issuer=issuer)
    with pytest.raises(OIDCDiscoveryError, match="jwks_uri"):
        verifier.initialize()


def test_oidc_discovery_network_failure():
    verifier = OIDCVerifier.from_config(issuer="http://localhost:19999")
    with pytest.raises(OIDCDiscoveryError):
        verifier.initialize(discovery_timeout=1.0)


def test_oidc_jwks_uri_override_skips_discovery(httpserver: HTTPServer, jwks_payload: dict):
    """OIDC_JWKS_URI override bypasses discovery entirely."""
    issuer = "https://example.com"  # would fail discovery if attempted
    jwks_uri = f"http://{httpserver.host}:{httpserver.port}/jwks"
    httpserver.expect_request("/jwks").respond_with_json(jwks_payload)

    verifier = OIDCVerifier.from_config(issuer=issuer, jwks_uri_override=jwks_uri)
    verifier.initialize()
    assert verifier._cache is not None


def test_jwks_fetch_failure_raises(httpserver: HTTPServer):
    issuer = f"http://{httpserver.host}:{httpserver.port}"
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_json(
        {"issuer": issuer, "jwks_uri": f"{issuer}/jwks"}
    )
    httpserver.expect_request("/jwks").respond_with_data("not json", status=500)

    verifier = OIDCVerifier.from_config(issuer=issuer)
    with pytest.raises((JWKSFetchError, OIDCDiscoveryError)):
        verifier.initialize()


# ---------------------------------------------------------------------------
# JWT verification
# ---------------------------------------------------------------------------


@pytest.fixture()
def initialized_verifier(
    httpserver: HTTPServer, rsa_private_key: RSAPrivateKey, jwks_payload: dict
):
    """An OIDCVerifier initialized against the local mock JWKS server."""
    issuer = f"http://{httpserver.host}:{httpserver.port}"
    httpserver.expect_request("/jwks").respond_with_json(jwks_payload)
    verifier = OIDCVerifier.from_config(issuer=issuer, jwks_uri_override=f"{issuer}/jwks")
    verifier.initialize()
    return verifier, issuer, rsa_private_key


def test_verify_valid_token(initialized_verifier):
    verifier, issuer, private_key = initialized_verifier
    token = _make_token(private_key, iss=issuer)
    claims = verifier.verify(token)
    assert claims["sub"] == "user1"
    assert claims["iss"] == issuer


def test_verify_expired_token(initialized_verifier):
    verifier, issuer, private_key = initialized_verifier
    token = _make_token(private_key, iss=issuer, exp_offset=-10)
    with pytest.raises(JWTVerificationError, match="expired"):
        verifier.verify(token)


def test_verify_wrong_issuer(initialized_verifier):
    verifier, issuer, private_key = initialized_verifier
    token = _make_token(private_key, iss="https://wrong-issuer.example.com")
    with pytest.raises(JWTVerificationError, match="issuer"):
        verifier.verify(token)


def test_verify_invalid_signature(initialized_verifier):
    verifier, issuer, private_key = initialized_verifier
    # Sign with a different key.
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _make_token(other_key, iss=issuer)
    with pytest.raises((JWTVerificationError, JWKSFetchError)):
        verifier.verify(token)


def test_verify_audience_valid(initialized_verifier):
    verifier, issuer, private_key = initialized_verifier
    verifier.audience = "my-api"
    token = _make_token(private_key, iss=issuer, aud="my-api")
    claims = verifier.verify(token)
    assert claims["sub"] == "user1"


def test_verify_audience_wrong(initialized_verifier):
    verifier, issuer, private_key = initialized_verifier
    verifier.audience = "my-api"
    token = _make_token(private_key, iss=issuer, aud="wrong-api")
    with pytest.raises(JWTVerificationError, match="audience"):
        verifier.verify(token)


def test_verify_audience_not_checked_when_not_configured(initialized_verifier):
    verifier, issuer, private_key = initialized_verifier
    verifier.audience = None
    # Token without aud claim — should be accepted when audience is not configured.
    token = _make_token(private_key, iss=issuer)
    claims = verifier.verify(token)
    assert claims["sub"] == "user1"


def test_verify_unsupported_algorithm_rejected(initialized_verifier):
    verifier, issuer, private_key = initialized_verifier
    # Build a token with HS256 (symmetric — not in allowed list).
    token = jwt.encode(
        {"sub": "user1", "iss": issuer, "exp": int(time.time()) + 600},
        "secret",
        algorithm="HS256",
    )
    with pytest.raises(JWTVerificationError, match="algorithm"):
        verifier.verify(token)


def test_verify_none_algorithm_rejected(initialized_verifier):
    verifier, issuer, _ = initialized_verifier
    # Craft a token with alg=none (unsigned).
    header = jwt.utils.base64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode()
    payload_b64 = jwt.utils.base64url_encode(
        json.dumps({"sub": "x", "iss": issuer, "exp": int(time.time()) + 600}).encode()
    ).decode()
    token = f"{header}.{payload_b64}."
    with pytest.raises(JWTVerificationError, match="algorithm"):
        verifier.verify(token)


def test_verify_not_initialized_raises():
    verifier = OIDCVerifier.from_config(issuer="https://example.com")
    with pytest.raises(JWTVerificationError, match="not initialized"):
        verifier.verify("some.token.here")


def test_no_raw_token_in_exception_message(initialized_verifier):
    verifier, issuer, private_key = initialized_verifier
    token = _make_token(private_key, iss=issuer, exp_offset=-10)
    try:
        verifier.verify(token)
    except JWTVerificationError as exc:
        # Raw token must not appear in the exception message.
        assert token not in str(exc)
    else:
        pytest.fail("Expected JWTVerificationError")


def test_jwks_cache_reused(
    httpserver: HTTPServer, rsa_private_key: RSAPrivateKey, jwks_payload: dict
):
    """JWKS endpoint is only hit once on initialization; not on every verify call."""
    issuer = f"http://{httpserver.host}:{httpserver.port}"
    # Allow exactly one JWKS request at initialization; no subsequent calls expected.
    httpserver.expect_oneshot_request("/jwks").respond_with_json(jwks_payload)

    verifier = OIDCVerifier.from_config(issuer=issuer, jwks_uri_override=f"{issuer}/jwks")
    verifier.initialize()

    # Make multiple verification calls — JWKS should be served from cache.
    for _ in range(3):
        token = _make_token(rsa_private_key, iss=issuer)
        claims = verifier.verify(token)
        assert claims["sub"] == "user1"
