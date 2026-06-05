"""OIDC verifier for basis-gateway.

Responsibilities:
- Bearer token extraction from the Authorization header
- OIDC discovery via ``{issuer}/.well-known/openid-configuration``
- JWKS fetching and in-memory caching (TTL + kid-miss refresh)
- JWT signature, expiry, issuer, audience, and algorithm verification

Security invariants:
- ``alg=none`` is never accepted.
- Only RS256/RS384/RS512/ES256/ES384/ES512 are accepted by default.
- Raw JWT strings never appear in exception messages or log output.
- Unverified claims are never used for authorization decisions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient, PyJWKClientError
from jwt.types import Options as JWTOptions

from basis_gateway.auth.errors import (
    JWKSFetchError,
    JWTVerificationError,
    OIDCDiscoveryError,
    TokenExtractionError,
)

log = logging.getLogger(__name__)

# Algorithms explicitly permitted. ``alg=none`` is never in this list.
_ALLOWED_ALGORITHMS: list[str] = [
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
]

_BEARER_PREFIX = "Bearer "


def extract_bearer_token(authorization: str | None) -> str:
    """Extract the Bearer token from an Authorization header value.

    Args:
        authorization: The raw value of the ``Authorization`` header,
            or ``None`` if the header is absent.

    Returns:
        The token string (not validated or decoded).

    Raises:
        TokenExtractionError: If the header is absent, malformed, uses a
            non-Bearer scheme, or contains an empty token.
    """
    if authorization is None:
        raise TokenExtractionError("Missing Authorization header")

    if not authorization.startswith(_BEARER_PREFIX):
        # Catches empty string, wrong scheme (Basic, Digest, etc.), missing space.
        raise TokenExtractionError(
            "Authorization header must use Bearer scheme: 'Authorization: Bearer <token>'"
        )

    token = authorization[len(_BEARER_PREFIX) :]
    if not token:
        raise TokenExtractionError("Bearer token is empty")

    # Sanity check: tokens must not contain whitespace (malformed split).
    if " " in token or "\t" in token:
        raise TokenExtractionError("Bearer token contains invalid whitespace")

    return token


@dataclass
class _JWKSCache:
    """Simple in-memory JWKS cache wrapping PyJWKClient.

    PyJWKClient already handles TTL-based cache refresh and kid-based
    key lookup. This wrapper holds the client and exposes a clean interface
    for the verifier.
    """

    client: PyJWKClient
    jwks_uri: str

    def get_signing_key(self, token: str) -> jwt.PyJWK:
        """Resolve the signing key for *token* by matching its ``kid`` header.

        Re-fetches JWKS on unknown ``kid`` (PyJWKClient behaviour).

        Raises:
            JWKSFetchError: If the JWKS endpoint is unreachable.
            JWTVerificationError: If no matching key is found.
        """
        try:
            return self.client.get_signing_key_from_jwt(token)
        except PyJWKClientError as exc:
            # Distinguish network errors from key-not-found errors.
            msg = str(exc)
            if "Unable to find" in msg or "Keyset is empty" in msg:
                raise JWTVerificationError(f"No matching key found in JWKS: {msg}") from exc
            raise JWKSFetchError(f"JWKS fetch failed: {msg}") from exc
        except Exception as exc:
            raise JWKSFetchError(f"JWKS fetch failed: {exc}") from exc


def _discover_jwks_uri(
    issuer: str,
    override_jwks_uri: str | None,
    timeout: float = 10.0,
) -> str:
    """Discover the JWKS URI for *issuer* via OIDC discovery.

    Args:
        issuer: The configured OIDC issuer URL.
        override_jwks_uri: If set, skip discovery and use this URI directly.
        timeout: HTTP request timeout in seconds.

    Returns:
        The JWKS URI to use for key fetching.

    Raises:
        OIDCDiscoveryError: If discovery fails or the discovered issuer
            does not match the configured issuer.
    """
    if override_jwks_uri:
        log.debug("Using configured OIDC_JWKS_URI override, skipping discovery")
        return override_jwks_uri

    discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    log.debug("Fetching OIDC discovery document from %s", discovery_url)

    try:
        with httpx.Client(trust_env=False) as client:
            response = client.get(discovery_url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise OIDCDiscoveryError(
            f"OIDC discovery request failed for issuer {issuer!r}: {exc}"
        ) from exc

    try:
        metadata = response.json()
    except Exception as exc:
        raise OIDCDiscoveryError(
            f"OIDC discovery response is not valid JSON for issuer {issuer!r}"
        ) from exc

    discovered_issuer = metadata.get("issuer")
    if discovered_issuer != issuer:
        raise OIDCDiscoveryError(
            f"OIDC issuer mismatch: configured {issuer!r}, discovered {discovered_issuer!r}"
        )

    jwks_uri = metadata.get("jwks_uri")
    if not jwks_uri:
        raise OIDCDiscoveryError(f"OIDC discovery document for {issuer!r} is missing 'jwks_uri'")

    log.debug("Discovered JWKS URI: %s", jwks_uri)
    return str(jwks_uri)


@dataclass
class OIDCVerifier:
    """Stateful OIDC verifier for basis-gateway.

    Lifecycle::

        verifier = OIDCVerifier.from_config(config)
        verifier.initialize()          # at application startup
        claims = verifier.verify(token)  # per request

    The verifier is not safe for concurrent initialization calls.
    After ``initialize()`` completes, ``verify()`` is thread-safe.
    """

    issuer: str
    audience: str | None
    jwks_uri_override: str | None
    cache_ttl_seconds: float

    _cache: _JWKSCache | None = field(default=None, init=False, repr=False)

    @classmethod
    def from_config(
        cls,
        issuer: str,
        audience: str | None = None,
        jwks_uri_override: str | None = None,
        cache_ttl_seconds: float = 300.0,
    ) -> OIDCVerifier:
        return cls(
            issuer=issuer,
            audience=audience,
            jwks_uri_override=jwks_uri_override,
            cache_ttl_seconds=cache_ttl_seconds,
        )

    def initialize(self, discovery_timeout: float = 10.0) -> None:
        """Run OIDC discovery and build the JWKS cache.

        Should be called once during application startup before any requests
        are served. Raises on failure so the readiness state is not set.

        Raises:
            OIDCDiscoveryError: Discovery failed or issuer mismatch.
            JWKSFetchError: Initial JWKS fetch failed.
        """
        jwks_uri = _discover_jwks_uri(
            self.issuer,
            self.jwks_uri_override,
            timeout=discovery_timeout,
        )

        # PyJWKClient handles in-memory key caching with TTL.
        # cache_jwk_set=True + lifespan=TTL gives us the caching behaviour we need.
        # On unknown kid it re-fetches automatically.
        # cache_jwk_set and lifespan were added in PyJWT 2.8; older stub versions do
        # not list them even though the runtime accepts them.
        try:
            client = PyJWKClient(  # type: ignore[call-arg]
                jwks_uri,
                cache_keys=True,
                cache_jwk_set=True,
                lifespan=int(self.cache_ttl_seconds),
            )
            # Eagerly fetch JWKS to validate connectivity at startup.
            client.fetch_data()
        except PyJWKClientError as exc:
            raise JWKSFetchError(f"Initial JWKS fetch failed: {exc}") from exc
        except Exception as exc:
            raise JWKSFetchError(f"Initial JWKS fetch failed: {exc}") from exc

        self._cache = _JWKSCache(client=client, jwks_uri=jwks_uri)
        log.info("OIDC verifier initialized; JWKS URI: %s", jwks_uri)

    def verify(self, token: str) -> dict[str, Any]:
        """Verify *token* and return verified claims.

        Args:
            token: Raw JWT string extracted from the Authorization header.
                   Must not be logged or included in exception messages.

        Returns:
            Verified claims dictionary. All returned claims are verified.

        Raises:
            JWTVerificationError: Verification failed for any reason.
            JWKSFetchError: JWKS was unavailable during verification.
        """
        if self._cache is None:
            raise JWTVerificationError(
                "OIDCVerifier not initialized; call initialize() before verifying tokens"
            )

        # Reject alg=none and other unsupported algorithms before key lookup.
        # jwt.get_unverified_header lacks type annotations in older PyJWT stub versions;
        # the return type is Dict[str, Any] at runtime.
        try:
            header: dict[str, Any] = jwt.get_unverified_header(token)  # type: ignore[no-untyped-call]
        except jwt.exceptions.DecodeError as exc:
            raise JWTVerificationError("Malformed JWT header") from exc

        alg = header.get("alg", "")
        if alg not in _ALLOWED_ALGORITHMS:
            raise JWTVerificationError(
                f"Unsupported JWT algorithm {alg!r}. Allowed: {', '.join(_ALLOWED_ALGORITHMS)}"
            )

        signing_key = self._cache.get_signing_key(token)

        decode_options: JWTOptions = {
            "verify_exp": True,
            "verify_iss": True,
        }

        audience = self.audience if self.audience else None

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=_ALLOWED_ALGORITHMS,
                issuer=self.issuer,
                audience=audience,
                options=decode_options,
            )
        except jwt.ExpiredSignatureError as exc:
            raise JWTVerificationError("Token has expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise JWTVerificationError("Token issuer is invalid") from exc
        except jwt.InvalidAudienceError as exc:
            raise JWTVerificationError("Token audience is invalid") from exc
        except jwt.InvalidSignatureError as exc:
            raise JWTVerificationError("Token signature is invalid") from exc
        except jwt.DecodeError as exc:
            raise JWTVerificationError(f"Token decode error: {exc}") from exc
        except jwt.PyJWTError as exc:
            raise JWTVerificationError(f"Token verification failed: {exc}") from exc

        return claims


def make_verifier_from_env(
    issuer: str,
    audience: str | None = None,
    jwks_uri_override: str | None = None,
    cache_ttl_seconds: float = 300.0,
) -> OIDCVerifier:
    """Factory used by the application lifespan to build a verifier from config."""
    return OIDCVerifier.from_config(
        issuer=issuer,
        audience=audience,
        jwks_uri_override=jwks_uri_override,
        cache_ttl_seconds=cache_ttl_seconds,
    )
