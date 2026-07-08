"""Runtime authentication-mode selection for basis-gateway.

Chooses which verifier authenticates an incoming Bearer token — OIDC or
BASIS-local token — based on the gateway's configured ``AuthMode``, and
normalizes either verifier's result into the same
``(NormalizedSubject, IdentityContext)`` pair so the rest of the request
path (``/v1/evaluate``'s ``DecisionRequest`` construction and evaluation)
never needs to know which mode authenticated the caller::

    Authorization: Bearer <token>
            |
            v
    configured auth mode
            +-- oidc              -> OIDCVerifier.verify() + map_claims()
            +-- basis_local_token -> verify_basis_local_identity_token()
            |                        + basis_local_verification_result_to_gateway_identity()
            v
    (NormalizedSubject, IdentityContext)

Rules, enforced by construction rather than by convention:

- The auth mode is explicit configuration (``GatewayConfig.auth_mode``). It
  is never inferred from the token's shape, header, or claims.
- There is no fallback between modes. If the configured mode's verifier
  fails, the request fails closed — the other mode's verifier is never
  attempted, and an OIDC token is never attempted as a BASIS-local token
  (or vice versa) unless that mode is actually configured.
- Bearer token *extraction* is unchanged and still lives in
  ``basis_gateway.auth.oidc.extract_bearer_token``; this module only covers
  what happens after a token string has already been extracted.
- This module does not evaluate authorization. It answers only "who is this
  caller?" — the existing ``/v1/evaluate`` evaluation path (basis-core via
  ``GatewayEvaluator``) is unchanged and untouched by this module.
- This module does not import ``basis_identity`` or ``basis_core``, issue
  or sign tokens, or handle private key material — see
  ``basis_gateway.auth.basis_local_token`` for those boundaries, which this
  module composes but does not alter.
"""

from __future__ import annotations

import json
from typing import Any

from basis_gateway.auth.basis_local_token import (
    BasisLocalTokenTrustConfig,
    basis_local_verification_result_to_gateway_identity,
    verify_basis_local_identity_token,
)
from basis_gateway.auth.errors import AuthenticationError
from basis_gateway.auth.oidc import OIDCVerifier
from basis_gateway.auth.subject_mapper import IdentityContext, NormalizedSubject, map_claims
from basis_gateway.config import AuthMode, EvaluationConfigError, GatewayConfig

__all__ = [
    "AuthNotConfiguredError",
    "UnsupportedAuthModeError",
    "authenticate",
    "build_basis_local_token_trust_config",
]


class AuthNotConfiguredError(AuthenticationError):
    """The configured auth mode's verifier/trust config is not initialized.

    Distinct from a bad token: this fires when ``app.state`` never received
    a verifier (or trust config) for the currently configured mode — the
    same startup-incomplete condition the pre-existing OIDC path already
    reported as "Authentication not configured", generalized across modes.
    """


class UnsupportedAuthModeError(AuthenticationError):
    """``auth_mode`` did not match a known ``AuthMode`` value.

    Should be unreachable in practice: ``GatewayConfig.auth_mode`` is a
    pydantic ``AuthMode`` enum field, so an unrecognized value is already
    rejected at configuration load time, before this module ever runs.
    Exists so runtime dispatch fails closed rather than silently choosing a
    default mode if that invariant is ever violated.
    """


def authenticate(
    *,
    auth_mode: AuthMode,
    token: str,
    oidc_verifier: OIDCVerifier | None,
    basis_local_trust_config: BasisLocalTokenTrustConfig | None,
) -> tuple[NormalizedSubject, IdentityContext]:
    """Verify *token* using the configured *auth_mode* and normalize identity.

    Args:
        auth_mode: The gateway's configured authentication mode.
        token: The raw Bearer token, already extracted from the
            ``Authorization`` header by ``extract_bearer_token``. Never
            logged or included in any exception message raised here.
        oidc_verifier: The initialized ``OIDCVerifier``, or ``None`` if
            OIDC was never initialized (e.g. a different mode is active).
        basis_local_trust_config: The initialized
            ``BasisLocalTokenTrustConfig``, or ``None`` if BASIS-local trust
            was never initialized (e.g. a different mode is active).

    Returns:
        A ``(NormalizedSubject, IdentityContext)`` pair, regardless of which
        mode authenticated the caller.

    Raises:
        AuthNotConfiguredError: the configured mode's verifier/trust config
            is ``None`` (not initialized).
        AuthenticationError: verification or identity normalization failed.
            See ``basis_gateway.auth.oidc`` and
            ``basis_gateway.auth.basis_local_token`` for the full subclass
            hierarchy raised by each mode's verifier.
        UnsupportedAuthModeError: *auth_mode* is not a recognized value.
    """
    if auth_mode == AuthMode.OIDC:
        if oidc_verifier is None:
            raise AuthNotConfiguredError("OIDC verifier not initialized")
        claims: dict[str, Any] = oidc_verifier.verify(token)
        return map_claims(claims)

    if auth_mode == AuthMode.BASIS_LOCAL_TOKEN:
        if basis_local_trust_config is None:
            raise AuthNotConfiguredError("BASIS-local token trust config not initialized")
        result = verify_basis_local_identity_token(token, trust_config=basis_local_trust_config)
        return basis_local_verification_result_to_gateway_identity(result)

    raise UnsupportedAuthModeError(f"Unsupported auth mode: {auth_mode!r}")


def _split_csv(value: str) -> tuple[str, ...]:
    """Split a comma-separated environment value into a trimmed tuple."""
    return tuple(part.strip() for part in value.split(",") if part.strip())


def build_basis_local_token_trust_config(config: GatewayConfig) -> BasisLocalTokenTrustConfig:
    """Build a ``BasisLocalTokenTrustConfig`` from environment-sourced config.

    Presence of ``BASIS_LOCAL_TOKEN_ISSUER``, ``BASIS_LOCAL_TOKEN_AUDIENCE``,
    and ``BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON`` is already checked by
    ``basis_gateway.config.validate_evaluation_config`` during startup, but
    this function re-checks so it is safe to call standalone (e.g. from a
    test). ``BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON`` must decode to a
    non-empty JSON object mapping key id to PEM public key. Deeper semantic
    validation — rejecting ``alg=none``, symmetric ``HS*`` algorithms, blank
    fields, private-key-shaped PEM values, and so on — is delegated to
    ``BasisLocalTokenTrustConfig`` itself, which raises
    ``BasisLocalTokenConfigError``.

    This function performs no I/O: no key generation, no file load, no
    JWKS fetch. It only parses already-loaded environment-sourced strings.

    Raises:
        EvaluationConfigError: a required environment variable is missing,
            or ``BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON`` is not valid JSON or
            does not decode to a non-empty object.
        BasisLocalTokenConfigError: the decoded values fail
            ``BasisLocalTokenTrustConfig``'s own validation (see
            ``basis_gateway.auth.basis_local_token``).
    """
    if not config.basis_local_token_issuer:
        raise EvaluationConfigError(
            "BASIS_LOCAL_TOKEN_ISSUER is required when AUTH_MODE=basis_local_token."
        )
    if not config.basis_local_token_audience:
        raise EvaluationConfigError(
            "BASIS_LOCAL_TOKEN_AUDIENCE is required when AUTH_MODE=basis_local_token."
        )
    if not config.basis_local_token_public_keys_json:
        raise EvaluationConfigError(
            "BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON is required when AUTH_MODE=basis_local_token."
        )

    try:
        public_keys = json.loads(config.basis_local_token_public_keys_json)
    except (TypeError, ValueError) as exc:
        raise EvaluationConfigError(
            f"BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON is not valid JSON: {exc}"
        ) from exc
    if not isinstance(public_keys, dict) or not public_keys:
        raise EvaluationConfigError(
            "BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON must decode to a non-empty JSON object "
            "mapping key id to PEM public key, e.g. "
            '{"basis-identity-key-1": "-----BEGIN PUBLIC KEY-----..."}'
        )

    return BasisLocalTokenTrustConfig(
        issuer=config.basis_local_token_issuer,
        audience=_split_csv(config.basis_local_token_audience),
        public_keys_by_id=public_keys,
        allowed_algorithms=_split_csv(config.basis_local_token_allowed_algorithms),
        leeway_seconds=config.basis_local_token_leeway_seconds,
    )
