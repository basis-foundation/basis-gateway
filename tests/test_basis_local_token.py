"""Tests for the BASIS-local token trust verifier.

Covers: trust config validation, successful verification (against a
token shaped like a real BASIS-local identity token from
``basis-identity``'s Phase 24/25 signing boundary), verification failure
modes, redaction/safety, the authorization boundary, and import
boundaries. All tokens are signed locally with a test RSA key pair; no
``basis_identity`` import and no live network access are required.
"""

from __future__ import annotations

import ast
import inspect
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from basis_gateway.auth import basis_local_token as blt
from basis_gateway.auth.basis_local_token import (
    DEFAULT_REQUIRED_BASIS_TOKEN_CLAIMS,
    BasisLocalTokenClaimsError,
    BasisLocalTokenConfigError,
    BasisLocalTokenHeaderError,
    BasisLocalTokenSignatureError,
    BasisLocalTokenTrustConfig,
    BasisLocalTokenVerificationError,
    BasisLocalTokenVerificationResult,
    basis_local_verification_result_to_gateway_identity,
    verify_basis_local_identity_token,
)
from basis_gateway.auth.errors import AuthenticationError
from basis_gateway.auth.subject_mapper import IdentityContext, NormalizedSubject

ISSUER = "https://identity.basis.example.com"
AUDIENCE = "basis-gateway"
KID = "basis-local-key-1"


# ---------------------------------------------------------------------------
# Key fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def rsa_private_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_rsa_private_key() -> RSAPrivateKey:
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


def _private_pem(key: RSAPrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


@pytest.fixture()
def trust_config(rsa_private_key: RSAPrivateKey) -> BasisLocalTokenTrustConfig:
    return BasisLocalTokenTrustConfig(
        issuer=ISSUER,
        audience=(AUDIENCE,),
        public_keys_by_id={KID: _public_pem(rsa_private_key)},
    )


# ---------------------------------------------------------------------------
# Claim payload builder — shaped like BASISLocalTokenClaims.to_dict() (Phase 24)
# ---------------------------------------------------------------------------


def _canonical_identity(subject_id: str = "user-123") -> dict[str, Any]:
    return {
        "subject": {
            "subject_id": subject_id,
            "subject_type": "user",
            "display_name": "Alice Example",
            "email": "alice@example.com",
            "roles": ["admin", "viewer"],
            "groups": [],
            "attributes": {},
        },
        "provider": {
            "provider_id": "keycloak-primary",
            "protocol": "oidc",
            "issuer": "https://idp.example.com/realms/basis",
            "realm": "basis",
            "tenant": None,
            "display_name": None,
        },
        "evidence": {
            "source_protocol": "oidc",
            "provider_subject": subject_id,
            "raw_claim_keys": ["sub", "email"],
            "mapped_fields": {},
            "evidence_reference": None,
            "issued_at": None,
            "authenticated_at": None,
        },
        "authentication_protocol": "oidc",
        "authenticated_at": None,
        "session_id": "sess-abc-1",
        "token_id": None,
        "context": {},
    }


def _claims_payload(
    *,
    issuer: str = ISSUER,
    audience: str | list[str] = AUDIENCE,
    subject_id: str = "user-123",
    token_id: str = "tok-1",
    token_type: str = "basis-local-identity",
    session_id: str = "sess-abc-1",
    provider_id: str = "keycloak-primary",
    authority_mode: str = "federated",
    authentication_protocol: str = "oidc",
    iat_offset: int = 0,
    exp_offset: int = 600,
    canonical_identity: dict[str, Any] | None = None,
    basis_overrides: dict[str, Any] | None = None,
    top_level_overrides: dict[str, Any] | None = None,
    omit_basis_keys: tuple[str, ...] = (),
) -> dict[str, Any]:
    now = int(time.time())
    basis: dict[str, Any] = {
        "session_id": session_id,
        "provider_id": provider_id,
        "authority_mode": authority_mode,
        "authentication_protocol": authentication_protocol,
        "canonical_identity": canonical_identity or _canonical_identity(subject_id),
        "source": "identity_session",
        "session_created_at": None,
        "session_authenticated_at": None,
        "identity_evidence_count": 1,
    }
    for key in omit_basis_keys:
        basis.pop(key, None)
    if basis_overrides:
        basis.update(basis_overrides)

    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": subject_id,
        "aud": audience if isinstance(audience, list) else [audience],
        "iat": now + iat_offset,
        "exp": now + exp_offset,
        "jti": token_id,
        "typ": token_type,
        "basis": basis,
    }
    if top_level_overrides:
        payload.update(top_level_overrides)
    return payload


def _sign(
    payload: dict[str, Any],
    private_key: RSAPrivateKey,
    *,
    kid: str | None = KID,
    algorithm: str = "RS256",
) -> str:
    headers = {"kid": kid} if kid is not None else {}
    return jwt.encode(payload, private_key, algorithm=algorithm, headers=headers)


def _valid_token(rsa_private_key: RSAPrivateKey, **payload_kwargs: Any) -> str:
    return _sign(_claims_payload(**payload_kwargs), rsa_private_key)


# ---------------------------------------------------------------------------
# Trust config validation
# ---------------------------------------------------------------------------


class TestTrustConfigValidation:
    def _kwargs(self, rsa_private_key: RSAPrivateKey, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "issuer": ISSUER,
            "audience": (AUDIENCE,),
            "public_keys_by_id": {KID: _public_pem(rsa_private_key)},
        }
        base.update(overrides)
        return base

    def test_blank_issuer_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="issuer"):
            BasisLocalTokenTrustConfig(**self._kwargs(rsa_private_key, issuer=""))

    def test_whitespace_padded_issuer_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="whitespace"):
            BasisLocalTokenTrustConfig(**self._kwargs(rsa_private_key, issuer=f" {ISSUER} "))

    def test_empty_audience_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="audience"):
            BasisLocalTokenTrustConfig(**self._kwargs(rsa_private_key, audience=()))

    def test_blank_audience_value_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="audience"):
            BasisLocalTokenTrustConfig(**self._kwargs(rsa_private_key, audience=("",)))

    def test_empty_public_key_map_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="public_keys_by_id"):
            BasisLocalTokenTrustConfig(**self._kwargs(rsa_private_key, public_keys_by_id={}))

    def test_blank_key_id_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="key id"):
            BasisLocalTokenTrustConfig(
                **self._kwargs(
                    rsa_private_key, public_keys_by_id={" ": _public_pem(rsa_private_key)}
                )
            )

    def test_blank_public_key_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="public key material"):
            BasisLocalTokenTrustConfig(
                **self._kwargs(rsa_private_key, public_keys_by_id={KID: "  "})
            )

    def test_private_key_material_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        """A private key supplied where a public key is expected must be rejected."""
        with pytest.raises(BasisLocalTokenConfigError, match="private key"):
            BasisLocalTokenTrustConfig(
                **self._kwargs(
                    rsa_private_key, public_keys_by_id={KID: _private_pem(rsa_private_key)}
                )
            )

    def test_empty_allowed_algorithms_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="allowed_algorithms"):
            BasisLocalTokenTrustConfig(**self._kwargs(rsa_private_key, allowed_algorithms=()))

    def test_none_algorithm_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="none"):
            BasisLocalTokenTrustConfig(
                **self._kwargs(rsa_private_key, allowed_algorithms=("none",))
            )

    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_symmetric_algorithm_rejected(self, rsa_private_key: RSAPrivateKey, alg: str) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="symmetric"):
            BasisLocalTokenTrustConfig(**self._kwargs(rsa_private_key, allowed_algorithms=(alg,)))

    def test_rs256_allowed(self, rsa_private_key: RSAPrivateKey) -> None:
        config = BasisLocalTokenTrustConfig(
            **self._kwargs(rsa_private_key, allowed_algorithms=("RS256",))
        )
        assert config.allowed_algorithms == ("RS256",)

    def test_negative_leeway_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="leeway"):
            BasisLocalTokenTrustConfig(**self._kwargs(rsa_private_key, leeway_seconds=-1))

    def test_empty_required_claims_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="required_claims"):
            BasisLocalTokenTrustConfig(**self._kwargs(rsa_private_key, required_claims=()))

    def test_blank_required_claim_path_rejected(self, rsa_private_key: RSAPrivateKey) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="required_claims"):
            BasisLocalTokenTrustConfig(**self._kwargs(rsa_private_key, required_claims=("",)))

    @pytest.mark.parametrize(
        "claim_path",
        ["basis.decision", "policy_id", "matched_rule", "grant", "obligation", "enforce_result"],
    )
    def test_authorization_shaped_required_claim_rejected(
        self, rsa_private_key: RSAPrivateKey, claim_path: str
    ) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="authorization"):
            BasisLocalTokenTrustConfig(
                **self._kwargs(rsa_private_key, required_claims=("iss", claim_path))
            )

    def test_default_required_claims_match_gateway_contract_shape(self) -> None:
        assert DEFAULT_REQUIRED_BASIS_TOKEN_CLAIMS == (
            "iss",
            "sub",
            "aud",
            "iat",
            "exp",
            "jti",
            "typ",
            "basis.session_id",
            "basis.provider_id",
            "basis.authority_mode",
            "basis.authentication_protocol",
            "basis.canonical_identity",
        )

    def test_config_is_a_basis_local_token_error_subclass(self) -> None:
        assert issubclass(BasisLocalTokenConfigError, AuthenticationError)


# ---------------------------------------------------------------------------
# Verification success
# ---------------------------------------------------------------------------


class TestVerificationSuccess:
    def test_valid_token_verifies(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key)
        result = verify_basis_local_identity_token(token, trust_config=trust_config)

        assert isinstance(result, BasisLocalTokenVerificationResult)
        assert result.subject_id == "user-123"
        assert result.issuer == ISSUER
        assert result.audience == (AUDIENCE,)
        assert result.token_id == "tok-1"
        assert result.token_type == "basis-local-identity"
        assert result.session_id == "sess-abc-1"
        assert result.provider_id == "keycloak-primary"
        assert result.authority_mode == "federated"
        assert result.authentication_protocol == "oidc"
        assert result.canonical_identity["subject"]["subject_id"] == "user-123"
        assert result.canonical_identity["subject"]["roles"] == ["admin", "viewer"]

    def test_multiple_audience_entries(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key, audience=[AUDIENCE, "other-aud"])
        result = verify_basis_local_identity_token(token, trust_config=trust_config)
        assert AUDIENCE in result.audience

    def test_leeway_permits_slightly_expired_token(self, rsa_private_key: RSAPrivateKey) -> None:
        config = BasisLocalTokenTrustConfig(
            issuer=ISSUER,
            audience=(AUDIENCE,),
            public_keys_by_id={KID: _public_pem(rsa_private_key)},
            leeway_seconds=30,
        )
        token = _valid_token(rsa_private_key, exp_offset=-10)
        result = verify_basis_local_identity_token(token, trust_config=config)
        assert result.subject_id == "user-123"


# ---------------------------------------------------------------------------
# Verification failure
# ---------------------------------------------------------------------------


class TestVerificationFailure:
    def test_blank_token_rejected(self, trust_config: BasisLocalTokenTrustConfig) -> None:
        with pytest.raises(BasisLocalTokenHeaderError, match="non-empty"):
            verify_basis_local_identity_token("", trust_config=trust_config)

    def test_malformed_token_rejected(self, trust_config: BasisLocalTokenTrustConfig) -> None:
        with pytest.raises(BasisLocalTokenHeaderError):
            verify_basis_local_identity_token("not-a-jwt", trust_config=trust_config)

    def test_missing_kid_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _sign(_claims_payload(), rsa_private_key, kid=None)
        with pytest.raises(BasisLocalTokenHeaderError, match="kid"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_unknown_kid_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _sign(_claims_payload(), rsa_private_key, kid="some-other-kid")
        with pytest.raises(BasisLocalTokenHeaderError, match="no public key configured"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_missing_alg_rejected(self, trust_config: BasisLocalTokenTrustConfig) -> None:
        # kid present, alg absent entirely (distinct from alg=none).
        header_b64 = jwt.utils.base64url_encode(b'{"kid":"basis-local-key-1","typ":"JWT"}').decode()
        payload_b64 = jwt.utils.base64url_encode(b'{"sub":"x"}').decode()
        token = f"{header_b64}.{payload_b64}."
        with pytest.raises(BasisLocalTokenHeaderError, match="alg"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_alg_none_rejected(self, trust_config: BasisLocalTokenTrustConfig) -> None:
        header_b64 = jwt.utils.base64url_encode(b'{"alg":"none","kid":"x","typ":"JWT"}').decode()
        payload_b64 = jwt.utils.base64url_encode(b'{"sub":"x"}').decode()
        token = f"{header_b64}.{payload_b64}."
        with pytest.raises(BasisLocalTokenHeaderError, match="none"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_hs256_algorithm_rejected(self, trust_config: BasisLocalTokenTrustConfig) -> None:
        token = jwt.encode(
            _claims_payload(), "some-shared-secret", algorithm="HS256", headers={"kid": KID}
        )
        with pytest.raises(BasisLocalTokenHeaderError, match="symmetric"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_wrong_public_key_rejected(
        self,
        rsa_private_key: RSAPrivateKey,
        other_rsa_private_key: RSAPrivateKey,
        trust_config: BasisLocalTokenTrustConfig,
    ) -> None:
        # Signed by a different key, but claims the trusted kid.
        token = _sign(_claims_payload(), other_rsa_private_key, kid=KID)
        with pytest.raises(BasisLocalTokenSignatureError):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_tampered_payload_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key)
        header, payload, sig = token.split(".")
        tampered_payload = jwt.utils.base64url_encode(b'{"sub":"attacker"}').decode()
        tampered = f"{header}.{tampered_payload}.{sig}"
        with pytest.raises(BasisLocalTokenSignatureError):
            verify_basis_local_identity_token(tampered, trust_config=trust_config)

    def test_tampered_signature_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key)
        header, payload, sig = token.split(".")
        tampered = f"{header}.{payload}.{sig[:-4]}abcd"
        with pytest.raises(BasisLocalTokenSignatureError):
            verify_basis_local_identity_token(tampered, trust_config=trust_config)

    def test_mismatched_issuer_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key, issuer="https://wrong-issuer.example.com")
        with pytest.raises(BasisLocalTokenVerificationError, match="issuer"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_mismatched_audience_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key, audience="wrong-audience")
        with pytest.raises(BasisLocalTokenVerificationError, match="audience"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_expired_token_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key, exp_offset=-10)
        with pytest.raises(BasisLocalTokenVerificationError, match="expired"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_not_yet_valid_token_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        payload = _claims_payload(top_level_overrides={"nbf": int(time.time()) + 300})
        token = _sign(payload, rsa_private_key)
        with pytest.raises(BasisLocalTokenVerificationError, match="not yet valid"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_missing_required_top_level_claim_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        payload = _claims_payload()
        del payload["jti"]
        token = _sign(payload, rsa_private_key)
        with pytest.raises((BasisLocalTokenClaimsError, BasisLocalTokenVerificationError)):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_missing_basis_namespace_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        payload = _claims_payload()
        del payload["basis"]
        token = _sign(payload, rsa_private_key)
        with pytest.raises(BasisLocalTokenClaimsError, match="basis"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_missing_session_id_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _sign(_claims_payload(omit_basis_keys=("session_id",)), rsa_private_key)
        with pytest.raises(BasisLocalTokenClaimsError, match="session_id"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_missing_canonical_identity_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _sign(_claims_payload(omit_basis_keys=("canonical_identity",)), rsa_private_key)
        with pytest.raises(BasisLocalTokenClaimsError, match="canonical_identity"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_wrong_token_type_rejected(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key, token_type="access-token")
        with pytest.raises(BasisLocalTokenClaimsError, match="token type"):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_config_type_checked(self) -> None:
        with pytest.raises(BasisLocalTokenConfigError, match="BasisLocalTokenTrustConfig"):
            verify_basis_local_identity_token("token", trust_config=cast_any_object())


def cast_any_object() -> Any:
    return object()


# ---------------------------------------------------------------------------
# Redaction / safety
# ---------------------------------------------------------------------------


class TestRedactionSafety:
    def test_raw_token_not_in_safe_dict(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key)
        result = verify_basis_local_identity_token(token, trust_config=trust_config)
        assert token not in str(result.to_dict())

    def test_raw_token_not_in_repr(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key)
        result = verify_basis_local_identity_token(token, trust_config=trust_config)
        assert token not in repr(result)

    def test_raw_token_not_in_errors(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key, exp_offset=-10)
        with pytest.raises(BasisLocalTokenVerificationError) as excinfo:
            verify_basis_local_identity_token(token, trust_config=trust_config)
        assert token not in str(excinfo.value)

    def test_public_key_pem_not_in_config_repr(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        assert _public_pem(rsa_private_key) not in repr(trust_config)

    def test_public_key_pem_not_in_config_to_dict(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        assert _public_pem(rsa_private_key) not in str(trust_config.to_dict())

    def test_private_key_pem_not_in_config_error(self, rsa_private_key: RSAPrivateKey) -> None:
        private_pem = _private_pem(rsa_private_key)
        with pytest.raises(BasisLocalTokenConfigError) as excinfo:
            BasisLocalTokenTrustConfig(
                issuer=ISSUER,
                audience=(AUDIENCE,),
                public_keys_by_id={KID: private_pem},
            )
        assert private_pem not in str(excinfo.value)

    def test_no_cookie_or_upstream_material_in_result(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key)
        result = verify_basis_local_identity_token(token, trust_config=trust_config)
        forbidden_terms = ("cookie", "nonce", "state", "code_verifier", "authorization_code")
        serialized = str(result.to_dict()).lower()
        for term in forbidden_terms:
            assert term not in serialized


# ---------------------------------------------------------------------------
# Authorization boundary
# ---------------------------------------------------------------------------


class TestAuthorizationBoundary:
    FORBIDDEN_TERMS = (
        "allow",
        "deny",
        "decision",
        "policy",
        "permission",
        "grant",
        "matched_rule",
        "enforce",
        "obligation",
    )

    def _find_forbidden_keys(self, data: Any) -> list[str]:
        found: list[str] = []
        if isinstance(data, dict):
            for key, value in data.items():
                lowered = str(key).lower()
                if any(term in lowered for term in self.FORBIDDEN_TERMS):
                    found.append(str(key))
                found.extend(self._find_forbidden_keys(value))
        elif isinstance(data, (list, tuple)):
            for item in data:
                found.extend(self._find_forbidden_keys(item))
        return found

    def test_verification_result_has_no_authorization_shaped_keys(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key)
        result = verify_basis_local_identity_token(token, trust_config=trust_config)
        assert self._find_forbidden_keys(result.to_dict()) == []

    @pytest.mark.parametrize(
        "poison_key", ["decision", "matched_rule", "granted_permission", "policy_id", "allow_all"]
    )
    def test_forbidden_key_in_canonical_identity_is_rejected(
        self,
        rsa_private_key: RSAPrivateKey,
        trust_config: BasisLocalTokenTrustConfig,
        poison_key: str,
    ) -> None:
        canonical_identity = _canonical_identity()
        canonical_identity[poison_key] = "should-not-be-here"
        token = _sign(_claims_payload(canonical_identity=canonical_identity), rsa_private_key)
        with pytest.raises(BasisLocalTokenClaimsError):
            verify_basis_local_identity_token(token, trust_config=trust_config)

    def test_allowed_algorithms_config_key_is_not_a_false_positive(
        self, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        """``allowed_algorithms`` contains 'allow' but is not an authorization decision.

        A naive recursive scan (like the test-local one above) *would* flag
        it — demonstrating the false-positive risk — but the module's own
        ``_assert_no_authorization_shaped_keys`` must not raise on it.
        """
        config_dict = trust_config.to_dict()
        naive_hits = self._find_forbidden_keys(config_dict)
        assert naive_hits == ["allowed_algorithms"]

        # The production scanner must not raise for this key.
        blt._assert_no_authorization_shaped_keys(config_dict)

    def test_result_construction_still_rejects_real_allow_key(self) -> None:
        with pytest.raises(BasisLocalTokenClaimsError):
            blt._assert_no_authorization_shaped_keys({"allow_decision": True})


# ---------------------------------------------------------------------------
# Import boundary
# ---------------------------------------------------------------------------


def _top_level_imported_modules() -> set[str]:
    source = inspect.getsource(blt)
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


class TestImportBoundary:
    def test_does_not_import_basis_identity(self) -> None:
        assert "basis_identity" not in _top_level_imported_modules()

    def test_does_not_import_basis_core(self) -> None:
        assert "basis_core" not in _top_level_imported_modules()

    def test_does_not_import_web_frameworks(self) -> None:
        imported = _top_level_imported_modules()
        assert "fastapi" not in imported
        assert "starlette" not in imported

    def test_only_expected_top_level_modules_imported(self) -> None:
        allowed = {
            "__future__",
            "collections",
            "dataclasses",
            "datetime",
            "types",
            "typing",
            "jwt",
            "basis_gateway",
        }
        assert _top_level_imported_modules() <= allowed

    def test_no_key_generation_in_source(self) -> None:
        source = inspect.getsource(blt)
        assert "generate_private_key(" not in source
        assert "rsa.generate" not in source

    def test_no_key_loading_from_file_or_env_in_source(self) -> None:
        source = inspect.getsource(blt)
        assert "os.environ" not in source
        assert "getenv" not in source
        assert "open(" not in source

    def test_no_signing_primitive_in_source(self) -> None:
        source = inspect.getsource(blt)
        assert "jwt.encode" not in source

    def test_no_policy_evaluation_call_in_source(self) -> None:
        source = inspect.getsource(blt)
        assert "EnforcementPoint" not in source
        assert "PolicyEngine" not in source


# ---------------------------------------------------------------------------
# Optional adapter into the existing gateway subject model
# ---------------------------------------------------------------------------


class TestGatewayIdentityAdapter:
    def test_converts_to_normalized_subject_and_identity_context(
        self, rsa_private_key: RSAPrivateKey, trust_config: BasisLocalTokenTrustConfig
    ) -> None:
        token = _valid_token(rsa_private_key)
        result = verify_basis_local_identity_token(token, trust_config=trust_config)

        subject, context = basis_local_verification_result_to_gateway_identity(result)

        assert isinstance(subject, NormalizedSubject)
        assert isinstance(context, IdentityContext)
        assert subject.subject_id == "user-123"
        assert subject.name == "Alice Example"
        assert subject.roles == ("admin", "viewer")
        assert subject.attributes["email"] == "alice@example.com"
        assert context.issuer == ISSUER
        assert context.subject_id == "user-123"

    def test_rejects_non_result_argument(self) -> None:
        with pytest.raises(BasisLocalTokenClaimsError):
            basis_local_verification_result_to_gateway_identity(cast_any_object())


# ---------------------------------------------------------------------------
# Existing gateway suite untouched (sanity import check)
# ---------------------------------------------------------------------------


def test_module_is_independently_importable() -> None:
    """This module must not require any gateway runtime wiring to import."""
    import importlib

    reloaded = importlib.reload(blt)
    assert reloaded.verify_basis_local_identity_token is not None
