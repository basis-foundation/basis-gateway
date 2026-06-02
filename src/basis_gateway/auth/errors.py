"""Typed authentication error hierarchy for basis-gateway.

All errors are safe to log at a high level.
Raw JWT material must never appear in exception messages or tracebacks.
"""

from __future__ import annotations


class AuthenticationError(Exception):
    """Base class for all authentication failures.

    Callers should catch this to produce a 401 response.
    Subclasses provide more specific context for internal logging.
    Do not expose subclass names or messages directly to HTTP callers.
    """


class TokenExtractionError(AuthenticationError):
    """Raised when the Authorization header is missing, malformed, or uses
    an unsupported scheme.

    Safe message: does not contain token material.
    """


class OIDCDiscoveryError(AuthenticationError):
    """Raised when OIDC discovery fails: network error, unexpected response
    shape, or issuer mismatch between configuration and discovered metadata.
    """


class JWKSFetchError(AuthenticationError):
    """Raised when the JWKS endpoint cannot be reached or returns an
    unexpected response. Authentication fails closed when JWKS is unavailable.
    """


class JWTVerificationError(AuthenticationError):
    """Raised when JWT verification fails for any reason: expired token,
    invalid signature, wrong issuer, wrong audience, unsupported algorithm,
    missing required claims, or unknown key ID.

    Message must not include the raw token string.
    """


class SubjectMappingError(AuthenticationError):
    """Raised when verified claims cannot be mapped to a NormalizedSubject,
    e.g. a missing required ``sub`` claim or an unrecoverable claim structure.
    """
