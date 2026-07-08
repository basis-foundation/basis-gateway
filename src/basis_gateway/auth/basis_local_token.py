"""BASIS-local token trust verifier for basis-gateway.

``basis-identity`` can issue signed BASIS-local identity tokens (its own
Phase 24 claims model + Phase 25 signing boundary + Phase 26 gateway trust
contract). This module is the ``basis-gateway`` side of that boundary: a
small, explicit trust configuration and a verifier function that establish
*identity trust only*::

    BASIS-local signed token
        |
        v
    gateway trust configuration (BasisLocalTokenTrustConfig)
        |
        v
    signature / issuer / audience / time verification (PyJWT)
        |
        v
    required identity claim validation
        |
        v
    gateway trusted identity context (BasisLocalTokenVerificationResult)

What this module is, and is not:

- It is a **verifier and a configuration model**, mirroring the shape of the
  OIDC verifier (:mod:`basis_gateway.auth.oidc`) already in this package. It
  performs no I/O beyond the cryptographic verification itself: no key
  fetch, no file load, no environment parsing, no network call.
- It does **not** import ``basis_identity``. The BASIS-local token shape
  (claim names, the ``basis`` namespace, the default required claim paths)
  is mirrored from ``basis-identity``'s own published trust contract
  (``basis_identity.tokens.gateway_contract``) as plain strings and dicts —
  never as a shared type. The two repositories stay independently
  deployable.
- It does **not** import ``basis_core`` and does **not** evaluate
  authorization. It answers "who is this subject, and did basis-identity
  issue this token for this gateway?" — never "may this subject perform
  this operation?". A verification result never carries a permission, a
  role-as-authorization, a policy id, a matched rule, an allow/deny result,
  an obligation, or an enforcement result; construction actively rejects a
  ``required_claims`` entry or a verified-claim key that looks
  authorization/enforcement-shaped (see ``_FORBIDDEN_CLAIM_TERMS`` below).
- It does **not** sign, issue, generate, load from a file/environment
  variable, rotate, or publish a JWKS for any key. ``public_keys_by_id`` is
  an ordinary, caller-constructed, in-memory mapping of verification
  material only; a value that looks like a private key is rejected at
  configuration time.
- It does **not** wire itself into request authentication or change
  ``/v1/evaluate``'s existing OIDC-based behavior. This is a verifier and an
  optional conversion helper into the existing gateway subject model
  (:func:`basis_local_verification_result_to_gateway_identity`); runtime
  auth-mode wiring is left to a later, separate change.

Security invariants, mirrored from :mod:`basis_gateway.auth.oidc`:

- ``alg=none`` is never accepted.
- Symmetric (``HS*``) algorithms are never accepted.
- Only algorithms in the caller-configured allow-list are accepted.
- Decoded claims are never used before signature verification succeeds.
- Raw JWT strings, private key material, and public key PEM bodies never
  appear in exception messages, ``repr()``, or ``to_dict()`` output.

See ``docs/basis-local-token-trust.md`` for the full rationale.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, cast

import jwt

from basis_gateway.auth.errors import AuthenticationError
from basis_gateway.auth.subject_mapper import IdentityContext, NormalizedSubject

__all__ = [
    "DEFAULT_REQUIRED_BASIS_TOKEN_CLAIMS",
    "BasisLocalTokenClaims",
    "BasisLocalTokenClaimsError",
    "BasisLocalTokenConfigError",
    "BasisLocalTokenError",
    "BasisLocalTokenHeaderError",
    "BasisLocalTokenSignatureError",
    "BasisLocalTokenTrustConfig",
    "BasisLocalTokenVerificationError",
    "BasisLocalTokenVerificationResult",
    "basis_local_verification_result_to_gateway_identity",
    "verify_basis_local_identity_token",
]

# The BASIS-local identity token type this verifier accepts. Mirrors
# ``basis_identity.tokens.local.BASISLocalTokenType.BASIS_LOCAL_IDENTITY``'s
# value verbatim, without importing the enum itself.
_BASIS_LOCAL_IDENTITY_TOKEN_TYPE = "basis-local-identity"

# The unsigned "algorithm". A token presenting ``alg=none`` carries no
# verifiable signature and is rejected outright, before any key selection.
_UNSIGNED_ALGORITHM = "none"

# Symmetric algorithm family prefix. Rejected outright: a shared secret is
# not public key material, and BASIS-local tokens are only ever signed with
# an asymmetric algorithm (RS256 today).
_SYMMETRIC_ALGORITHM_PREFIX = "HS"

# The minimum claim paths this gateway requires before trusting a
# BASIS-local token, expressed against the token's own JWT payload shape
# (``iss``/``sub``/``aud``/``iat``/``exp``/``jti``/``typ`` plus the
# ``basis.*`` namespace). Mirrors
# ``basis_identity.tokens.gateway_contract.DEFAULT_GATEWAY_REQUIRED_CLAIM_PATHS``
# without importing it. Deliberately identity-only: no permission,
# role-as-authorization, policy, or enforcement-result path appears here,
# and constructing a trust config with such a path is rejected (see
# ``_reject_authorization_shaped_claim_paths``).
DEFAULT_REQUIRED_BASIS_TOKEN_CLAIMS: tuple[str, ...] = (
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

# Substrings that mark a required-claim path or a verified-claim key as
# authorization/enforcement-shaped rather than identity-shaped. Matched
# case-insensitively as a substring, not an exact key match. Note:
# ``allowed_algorithms`` (a *config* field name, never a claim path or a
# verification-result key) is deliberately excluded from this scan wherever
# it could otherwise collide with the "allow" substring — see
# ``_assert_no_authorization_shaped_keys``.
_FORBIDDEN_CLAIM_TERMS: tuple[str, ...] = (
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

# Verification-result/config field names that are exempt from the
# authorization-shaped-key scan even though they contain a forbidden
# substring. ``allowed_algorithms`` contains "allow" but is a trust
# configuration setting, never an authorization decision.
_AUTHORIZATION_SCAN_EXEMPT_KEYS: frozenset[str] = frozenset({"allowed_algorithms"})


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class BasisLocalTokenError(AuthenticationError):
    """Base class for every error raised while trusting a BASIS-local token.

    Subclasses :class:`~basis_gateway.auth.errors.AuthenticationError` so
    existing gateway error handling (which produces a 401 response for any
    ``AuthenticationError``) already covers this module without a code
    change. No subclass ever includes a raw signed token, a private key, a
    public key PEM body, a signing secret, or any other secret material —
    none of those values exist anywhere on this module's models in the
    first place. Messages may safely name an issuer, an audience entry, a
    ``kid``, a claim path, or a field name.
    """


class BasisLocalTokenConfigError(BasisLocalTokenError):
    """A :class:`BasisLocalTokenTrustConfig` field could not be validated.

    Raised for a blank or whitespace-padded ``issuer``, a missing/empty/
    blank/whitespace-padded ``audience`` entry, an empty
    ``public_keys_by_id`` mapping, a blank/whitespace-padded key id, a blank
    public key PEM value, a PEM value that looks like a private key, an
    empty ``allowed_algorithms`` tuple, an ``allowed_algorithms`` entry that
    is ``none`` or a symmetric ``HS*`` algorithm, a negative
    ``leeway_seconds``, an empty ``required_claims`` tuple, a blank/
    whitespace-padded claim path, or a ``required_claims`` entry that looks
    authorization/enforcement-shaped. The message never includes public key
    PEM material.
    """


class BasisLocalTokenHeaderError(BasisLocalTokenError):
    """The token's JOSE header is missing or not usable for verification.

    Raised before any signature check when the header cannot be parsed,
    declares no ``kid``, declares no ``alg``, declares ``alg=none``,
    declares a symmetric ``HS*`` algorithm, declares an algorithm excluded
    by the trust config's ``allowed_algorithms``, or declares a ``kid``
    unknown to the trust config's ``public_keys_by_id``. The raw token and
    any key material are never included.
    """


class BasisLocalTokenSignatureError(BasisLocalTokenError):
    """The token's signature did not verify, or the token is undecodable.

    Raised when the cryptographic signature check fails against the
    selected public key, or when the token is so malformed that decoding
    cannot proceed. The raw token, the signature, and the key material are
    never included.
    """


class BasisLocalTokenVerificationError(BasisLocalTokenError):
    """A standard claim (issuer/audience/expiration/timing) failed verification.

    Raised for an expired token, a not-yet-valid token, a mismatched
    issuer, or a mismatched audience — PyJWT-detected standard-claim
    failures, distinct from a missing/malformed BASIS-local claim. The raw
    token and any key material are never included.
    """


class BasisLocalTokenClaimsError(BasisLocalTokenError):
    """Verified token claims do not satisfy the BASIS-local trust contract.

    Raised only **after** cryptographic verification has already succeeded,
    when the verified payload is missing a required claim path, carries a
    malformed ``basis`` namespace, carries the wrong ``typ``, or carries a
    key that looks authorization/enforcement-shaped. Messages may name the
    offending claim path or key, never its value, and never the raw token.
    """


# --------------------------------------------------------------------------- #
# Shared validation helpers
# --------------------------------------------------------------------------- #


def _require_no_surrounding_whitespace(value: object, field_name: str) -> str:
    """Validate a required string field, rejecting (never trimming) whitespace."""

    if not isinstance(value, str) or not value:
        raise BasisLocalTokenConfigError(f"{field_name} must be a non-empty string")
    if not value.strip():
        raise BasisLocalTokenConfigError(f"{field_name} must be a non-empty string")
    if value != value.strip():
        raise BasisLocalTokenConfigError(
            f"{field_name} must not have leading or trailing whitespace"
        )
    return value


def _normalize_audience(value: object) -> tuple[str, ...]:
    """Validate and normalize ``audience`` into a deterministic tuple.

    Requires at least one entry; rejects a blank or whitespace-padded
    entry. Insertion order is preserved.
    """

    candidates: Sequence[object]
    if isinstance(value, str):
        candidates = (value,)
    elif isinstance(value, Sequence):
        candidates = value
    else:
        raise BasisLocalTokenConfigError("audience must be a string or a sequence of strings")

    if len(candidates) == 0:
        raise BasisLocalTokenConfigError("audience must contain at least one entry")

    cleaned: list[str] = []
    for entry in candidates:
        if not isinstance(entry, str) or not entry or not entry.strip():
            raise BasisLocalTokenConfigError("audience entries must be non-empty strings")
        if entry != entry.strip():
            raise BasisLocalTokenConfigError(
                "audience entries must not have leading or trailing whitespace"
            )
        cleaned.append(entry)
    return tuple(cleaned)


def _validate_algorithm_string(value: object, field_name: str) -> str:
    """Validate a single algorithm string, rejecting ``none`` and ``HS*``.

    Does not restrict the value to a closed enum — RS256 is the only
    algorithm ``basis-identity`` signs with today, but a future asymmetric
    algorithm (e.g. RS384, ES256) should not require a code change here.
    """

    if not isinstance(value, str) or not value.strip():
        raise BasisLocalTokenConfigError(f"{field_name} must be a non-empty string")
    if value != value.strip():
        raise BasisLocalTokenConfigError(
            f"{field_name} must not have leading or trailing whitespace"
        )
    if value.lower() == _UNSIGNED_ALGORITHM:
        raise BasisLocalTokenConfigError(
            f"{field_name} must not be {_UNSIGNED_ALGORITHM!r} (unsigned tokens are not accepted)"
        )
    if value.upper().startswith(_SYMMETRIC_ALGORITHM_PREFIX):
        raise BasisLocalTokenConfigError(
            f"{field_name} must not be a symmetric algorithm: {value!r}"
        )
    return value


def _validate_allowed_algorithms(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise BasisLocalTokenConfigError("allowed_algorithms must be a sequence of strings")
    if len(value) == 0:
        raise BasisLocalTokenConfigError("allowed_algorithms must not be empty")
    return tuple(_validate_algorithm_string(entry, "allowed_algorithms entry") for entry in value)


def _validate_public_keys_by_id(value: object) -> Mapping[str, str]:
    """Validate and defensively copy ``public_keys_by_id`` into a read-only mapping.

    Requires a non-empty mapping whose keys are non-blank, non-whitespace-
    padded key ids and whose values are non-blank public key PEM strings.
    Rejects a value that looks like a private key outright — this config
    exists to hand *verification* material to the gateway, never signing
    material.
    """

    if not isinstance(value, Mapping) or len(value) == 0:
        raise BasisLocalTokenConfigError(
            "public_keys_by_id must be a non-empty mapping of key id to public key PEM"
        )

    cleaned: dict[str, str] = {}
    for kid, pem in value.items():
        if not isinstance(kid, str) or not kid.strip():
            raise BasisLocalTokenConfigError("public key id must be a non-empty string")
        if kid != kid.strip():
            raise BasisLocalTokenConfigError(
                "public key id must not have leading or trailing whitespace"
            )
        if not isinstance(pem, str) or not pem.strip():
            raise BasisLocalTokenConfigError(
                f"public key material for kid {kid!r} must be a non-empty string"
            )
        if "PRIVATE KEY" in pem.upper():
            raise BasisLocalTokenConfigError(
                f"public_keys_by_id entry for kid {kid!r} looks like a private key; "
                "only public verification keys are accepted"
            )
        cleaned[kid] = pem
    return MappingProxyType(cleaned)


def _reject_authorization_shaped_claim_paths(paths: Sequence[str]) -> None:
    """Reject a ``required_claims`` entry that looks authorization-shaped.

    This trust config is identity trust only: it must never require a
    permission, a role-as-authorization, a policy id, a matched rule, an
    allow/deny result, an obligation, or an enforcement result.
    """

    for path in paths:
        lowered = path.lower()
        for term in _FORBIDDEN_CLAIM_TERMS:
            if term in lowered:
                raise BasisLocalTokenConfigError(
                    f"required_claims entry {path!r} looks like an authorization/enforcement "
                    "claim, which is not permitted in an identity-only trust config"
                )


def _validate_required_claims(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise BasisLocalTokenConfigError("required_claims must be a sequence of claim path strings")
    if len(value) == 0:
        raise BasisLocalTokenConfigError("required_claims must not be empty")

    cleaned: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not entry or not entry.strip():
            raise BasisLocalTokenConfigError("required_claims entries must be non-empty strings")
        if entry != entry.strip():
            raise BasisLocalTokenConfigError(
                "required_claims entries must not have leading or trailing whitespace"
            )
        cleaned.append(entry)

    _reject_authorization_shaped_claim_paths(cleaned)
    return tuple(cleaned)


def _claim_path_present(payload: Mapping[str, Any], path: str) -> bool:
    """Check whether a dotted claim path (e.g. ``"basis.session_id"``) resolves.

    Walks nested mappings one path segment at a time. A path that resolves
    to an explicit ``None`` is treated as absent.
    """

    node: Any = payload
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return False
        node = node[part]
    return node is not None


def _assert_no_authorization_shaped_keys(data: object) -> None:
    """Recursively scan a serialized mapping for authorization-shaped keys.

    Applied to a verified token's claim payload after signature
    verification has already succeeded, so a token that somehow carries a
    key like ``"decision"`` or ``"matched_rule"`` is rejected rather than
    silently trusted as identity context. ``_AUTHORIZATION_SCAN_EXEMPT_KEYS``
    (currently just ``"allowed_algorithms"``) is excluded so a legitimate
    trust-configuration field is never mistaken for an authorization
    decision because it contains the substring "allow".
    """

    if isinstance(data, Mapping):
        for key, value in data.items():
            lowered = str(key).lower()
            if key not in _AUTHORIZATION_SCAN_EXEMPT_KEYS:
                for term in _FORBIDDEN_CLAIM_TERMS:
                    if term in lowered:
                        raise BasisLocalTokenClaimsError(
                            f"claim key {key!r} is not permitted in an identity-only "
                            "BASIS-local token trust boundary"
                        )
            _assert_no_authorization_shaped_keys(value)
    elif isinstance(data, (list, tuple)):
        for item in data:
            _assert_no_authorization_shaped_keys(item)


def _timestamp_to_datetime(value: object, *, field_name: str) -> datetime:
    """Convert a verified numeric JWT timestamp claim into an aware ``datetime``."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BasisLocalTokenClaimsError(f"{field_name} must be a numeric timestamp")
    return datetime.fromtimestamp(value, tz=timezone.utc)


def _to_json_safe(value: object) -> object:
    """Recursively convert mappings/sequences into plain, JSON-serializable values."""

    if isinstance(value, Mapping):
        return {str(key): _to_json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_json_safe(item) for item in value]
    return value


# --------------------------------------------------------------------------- #
# Trust configuration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BasisLocalTokenTrustConfig:
    """Gateway-local trust configuration for verifying BASIS-local tokens.

    Captures exactly what :func:`verify_basis_local_identity_token` needs:
    the expected ``issuer``/``audience``, the public verification keys by
    ``kid``, the allowlisted signing algorithms, the minimum identity claim
    paths that must be present, and a clock-skew ``leeway_seconds``.
    Constructing one performs no I/O, no key generation, and no key
    loading — every field is an ordinary, caller-constructed, in-memory
    value, exactly like :class:`~basis_gateway.auth.oidc.OIDCVerifier`'s own
    configuration fields.

    Only **public** verification keys are ever accepted in
    ``public_keys_by_id``: construction rejects a value that looks like a
    private key (``"PRIVATE KEY"`` anywhere in the PEM body), and this
    model has no field for private key material or signing configuration
    at all.
    """

    issuer: str
    audience: tuple[str, ...]
    public_keys_by_id: Mapping[str, str]
    allowed_algorithms: tuple[str, ...] = ("RS256",)
    required_claims: tuple[str, ...] = DEFAULT_REQUIRED_BASIS_TOKEN_CLAIMS
    leeway_seconds: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "issuer", _require_no_surrounding_whitespace(self.issuer, "issuer")
        )
        object.__setattr__(self, "audience", _normalize_audience(self.audience))
        object.__setattr__(
            self, "public_keys_by_id", _validate_public_keys_by_id(self.public_keys_by_id)
        )
        object.__setattr__(
            self, "allowed_algorithms", _validate_allowed_algorithms(self.allowed_algorithms)
        )
        object.__setattr__(self, "required_claims", _validate_required_claims(self.required_claims))
        if not isinstance(self.leeway_seconds, int) or isinstance(self.leeway_seconds, bool):
            raise BasisLocalTokenConfigError("leeway_seconds must be an int")
        if self.leeway_seconds < 0:
            raise BasisLocalTokenConfigError("leeway_seconds must be non-negative")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(issuer={self.issuer!r}, audience={list(self.audience)!r}, "
            f"public_key_ids={sorted(self.public_keys_by_id)!r}, "
            f"public_key_count={len(self.public_keys_by_id)}, "
            f"allowed_algorithms={list(self.allowed_algorithms)!r}, "
            f"required_claims={list(self.required_claims)!r}, "
            f"leeway_seconds={self.leeway_seconds!r})"
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize to a safe, deterministic dictionary — never a PEM body.

        Exposes ``public_key_ids``/``public_key_count`` instead of the
        actual key material, matching :class:`BasisLocalTokenVerificationResult`'s
        own redaction style.
        """

        return {
            "issuer": self.issuer,
            "audience": list(self.audience),
            "public_key_ids": sorted(self.public_keys_by_id),
            "public_key_count": len(self.public_keys_by_id),
            "allowed_algorithms": list(self.allowed_algorithms),
            "required_claims": list(self.required_claims),
            "leeway_seconds": self.leeway_seconds,
        }


# --------------------------------------------------------------------------- #
# Verified claims (internal representation)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BasisLocalTokenClaims:
    """Typed view over an already-verified BASIS-local token payload.

    Built only from a payload PyJWT has already verified the signature and
    standard claims of — never from an unverified decode. This is an
    internal, gateway-local representation; it does not import or
    reconstruct ``basis_identity``'s own ``BASISLocalTokenClaims`` model.
    """

    issuer: str
    subject_id: str
    audience: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    token_id: str
    token_type: str
    session_id: str
    provider_id: str
    authority_mode: str
    authentication_protocol: str
    canonical_identity: Mapping[str, object]
    raw_claims: Mapping[str, object]

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(token_id={self.token_id!r}, issuer={self.issuer!r}, "
            f"subject_id={self.subject_id!r}, session_id={self.session_id!r}, "
            f"provider_id={self.provider_id!r}, token_type={self.token_type!r})"
        )


def _basis_local_claims_from_verified_payload(payload: Mapping[str, Any]) -> BasisLocalTokenClaims:
    """Reconstruct :class:`BasisLocalTokenClaims` from an already-verified JWT payload.

    Called only by :func:`verify_basis_local_identity_token`, after PyJWT
    has already verified the signature and the standard claims. Rejects a
    missing or malformed BASIS-local claim with
    :class:`BasisLocalTokenClaimsError` rather than silently defaulting it.
    """

    try:
        basis = payload["basis"]
        if not isinstance(basis, Mapping):
            raise BasisLocalTokenClaimsError("'basis' claim must be an object")

        issuer = payload["iss"]
        subject_id = payload["sub"]
        token_id = payload["jti"]
        token_type = payload["typ"]

        audience_raw = payload["aud"]
        audience: tuple[str, ...]
        if isinstance(audience_raw, str):
            audience = (audience_raw,)
        elif isinstance(audience_raw, (list, tuple)):
            audience = tuple(audience_raw)
        else:
            raise BasisLocalTokenClaimsError("'aud' claim must be a string or list of strings")

        issued_at = _timestamp_to_datetime(payload["iat"], field_name="iat")
        expires_at = _timestamp_to_datetime(payload["exp"], field_name="exp")

        session_id = basis["session_id"]
        provider_id = basis["provider_id"]
        authority_mode = basis["authority_mode"]
        authentication_protocol = basis["authentication_protocol"]
        canonical_identity = basis["canonical_identity"]
        if not isinstance(canonical_identity, Mapping):
            raise BasisLocalTokenClaimsError("'basis.canonical_identity' claim must be an object")

        for label, claim_value in (
            ("iss", issuer),
            ("sub", subject_id),
            ("jti", token_id),
            ("typ", token_type),
            ("basis.session_id", session_id),
            ("basis.provider_id", provider_id),
            ("basis.authority_mode", authority_mode),
            ("basis.authentication_protocol", authentication_protocol),
        ):
            if not isinstance(claim_value, str) or not claim_value.strip():
                raise BasisLocalTokenClaimsError(f"claim {label!r} must be a non-empty string")
    except BasisLocalTokenClaimsError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise BasisLocalTokenClaimsError(
            "verified token payload is missing a required BASIS-local claim "
            "or has a malformed value"
        ) from exc

    return BasisLocalTokenClaims(
        issuer=issuer,
        subject_id=subject_id,
        audience=audience,
        issued_at=issued_at,
        expires_at=expires_at,
        token_id=token_id,
        token_type=token_type,
        session_id=session_id,
        provider_id=provider_id,
        authority_mode=authority_mode,
        authentication_protocol=authentication_protocol,
        canonical_identity=MappingProxyType(dict(canonical_identity)),
        raw_claims=MappingProxyType(dict(payload)),
    )


# --------------------------------------------------------------------------- #
# Gateway-safe verification result
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BasisLocalTokenVerificationResult:
    """The gateway-trusted identity established by a verified BASIS-local token.

    Deterministic and JSON-safe. Never includes the raw signed token, a
    public or private key value, or any authorization/enforcement-shaped
    field (permission, policy id, matched rule, allow/deny decision,
    obligation, or grant) — construction actively rejects a
    ``canonical_identity``/``claims`` payload that carries one.

    This is identity trust only: *who* the subject is, established by a
    signature basis-identity produced. It never says whether that subject
    may perform any particular operation — that remains basis-core's
    responsibility via the normal ``/v1/evaluate`` path.
    """

    subject_id: str
    issuer: str
    audience: tuple[str, ...]
    token_id: str
    token_type: str
    session_id: str
    provider_id: str
    authority_mode: str
    authentication_protocol: str
    canonical_identity: Mapping[str, object]
    claims: Mapping[str, object]

    def __post_init__(self) -> None:
        for field_name in (
            "subject_id",
            "issuer",
            "token_id",
            "token_type",
            "session_id",
            "provider_id",
            "authority_mode",
            "authentication_protocol",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise BasisLocalTokenClaimsError(f"{field_name} must be a non-empty string")

        if not isinstance(self.audience, tuple) or len(self.audience) == 0:
            raise BasisLocalTokenClaimsError("audience must be a non-empty tuple of strings")

        if not isinstance(self.canonical_identity, Mapping):
            raise BasisLocalTokenClaimsError("canonical_identity must be a mapping")
        if not isinstance(self.claims, Mapping):
            raise BasisLocalTokenClaimsError("claims must be a mapping")

        _assert_no_authorization_shaped_keys(self.canonical_identity)
        _assert_no_authorization_shaped_keys(self.claims)

        object.__setattr__(
            self, "canonical_identity", MappingProxyType(dict(self.canonical_identity))
        )
        object.__setattr__(self, "claims", MappingProxyType(dict(self.claims)))

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(subject_id={self.subject_id!r}, issuer={self.issuer!r}, "
            f"audience={list(self.audience)!r}, token_id={self.token_id!r}, "
            f"token_type={self.token_type!r}, session_id={self.session_id!r}, "
            f"provider_id={self.provider_id!r}, authority_mode={self.authority_mode!r}, "
            f"authentication_protocol={self.authentication_protocol!r})"
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize to a deterministic, JSON-serializable dictionary.

        Never includes the raw signed token or any key material — neither
        field exists anywhere on this model in the first place.
        """

        return {
            "subject_id": self.subject_id,
            "issuer": self.issuer,
            "audience": list(self.audience),
            "token_id": self.token_id,
            "token_type": self.token_type,
            "session_id": self.session_id,
            "provider_id": self.provider_id,
            "authority_mode": self.authority_mode,
            "authentication_protocol": self.authentication_protocol,
            "canonical_identity": _to_json_safe(self.canonical_identity),
            "claims": _to_json_safe(self.claims),
        }


def _result_from_claims(claims: BasisLocalTokenClaims) -> BasisLocalTokenVerificationResult:
    return BasisLocalTokenVerificationResult(
        subject_id=claims.subject_id,
        issuer=claims.issuer,
        audience=claims.audience,
        token_id=claims.token_id,
        token_type=claims.token_type,
        session_id=claims.session_id,
        provider_id=claims.provider_id,
        authority_mode=claims.authority_mode,
        authentication_protocol=claims.authentication_protocol,
        canonical_identity=claims.canonical_identity,
        claims=claims.raw_claims,
    )


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


def verify_basis_local_identity_token(
    token: str,
    *,
    trust_config: BasisLocalTokenTrustConfig,
) -> BasisLocalTokenVerificationResult:
    """Verify a signed BASIS-local identity token and return trusted identity.

    Steps, in order: validate ``token`` is non-blank; parse the JOSE header
    (requiring ``kid`` and ``alg``, rejecting ``alg=none`` and symmetric
    ``HS*`` algorithms, requiring the algorithm be in
    ``trust_config.allowed_algorithms``); select the public key by ``kid``;
    verify the signature and standard claims (issuer/audience/expiration/
    not-before/issued-at) via PyJWT; validate every path in
    ``trust_config.required_claims`` is present; validate the token type is
    the expected BASIS-local identity type; and return a gateway-safe
    :class:`BasisLocalTokenVerificationResult`.

    Decoded claims are never used before signature verification succeeds.

    Args:
        token: The raw, compact BASIS-local signed JWT string.
        trust_config: The gateway's :class:`BasisLocalTokenTrustConfig`.

    Raises:
        BasisLocalTokenConfigError: ``trust_config`` is not a
            :class:`BasisLocalTokenTrustConfig` instance.
        BasisLocalTokenHeaderError: the header/algorithm/``kid`` is missing
            or not acceptable.
        BasisLocalTokenSignatureError: the signature did not verify, or the
            token is undecodable.
        BasisLocalTokenVerificationError: a standard claim (issuer/
            audience/expiration/timing) failed validation.
        BasisLocalTokenClaimsError: the verified payload's BASIS-local
            claims are missing, malformed, of the wrong token type, or
            contain an authorization-shaped key.
    """

    if not isinstance(trust_config, BasisLocalTokenTrustConfig):
        raise BasisLocalTokenConfigError(
            "trust_config must be a BasisLocalTokenTrustConfig instance"
        )
    if not isinstance(token, str) or not token.strip():
        raise BasisLocalTokenHeaderError("token must be a non-empty string")

    try:
        header = jwt.get_unverified_header(token)  # type: ignore[no-untyped-call]
    except jwt.InvalidTokenError as exc:
        raise BasisLocalTokenHeaderError("token JOSE header could not be parsed") from exc

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise BasisLocalTokenHeaderError("token header is missing a non-empty 'kid'")
    kid = kid.strip()

    alg = header.get("alg")
    if not isinstance(alg, str) or not alg.strip():
        raise BasisLocalTokenHeaderError("token header is missing the 'alg' parameter")
    alg = alg.strip()

    if alg.lower() == _UNSIGNED_ALGORITHM:
        raise BasisLocalTokenHeaderError("unsigned tokens (alg=none) are not accepted")
    if alg.upper().startswith(_SYMMETRIC_ALGORITHM_PREFIX):
        raise BasisLocalTokenHeaderError(f"symmetric algorithm {alg!r} is not accepted")
    if alg not in trust_config.allowed_algorithms:
        raise BasisLocalTokenHeaderError(f"algorithm {alg!r} is not in the configured allow-list")

    public_key_pem = trust_config.public_keys_by_id.get(kid)
    if public_key_pem is None:
        raise BasisLocalTokenHeaderError(f"no public key configured for kid {kid!r}")

    options = {
        "require": ["exp", "iss", "aud", "sub", "iat", "jti"],
        "verify_signature": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iat": True,
        "verify_aud": True,
        "verify_iss": True,
    }
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            key=public_key_pem,
            algorithms=[alg],
            audience=list(trust_config.audience),
            issuer=trust_config.issuer,
            leeway=trust_config.leeway_seconds,
            # PyJWT's ``options`` TypedDict is not a stable, importable name
            # across PyJWT versions (see the identical rationale in
            # auth/oidc.py), so the dict is built plainly and cast here.
            options=cast(Any, options),
        )
    except jwt.ExpiredSignatureError as exc:
        raise BasisLocalTokenVerificationError("token is expired") from exc
    except jwt.ImmatureSignatureError as exc:
        raise BasisLocalTokenVerificationError(
            "token is not yet valid ('nbf' is in the future)"
        ) from exc
    except jwt.InvalidAudienceError as exc:
        raise BasisLocalTokenVerificationError(
            "token audience does not match the configured audience"
        ) from exc
    except jwt.InvalidIssuerError as exc:
        raise BasisLocalTokenVerificationError(
            "token issuer does not match the configured issuer"
        ) from exc
    except jwt.MissingRequiredClaimError as exc:
        raise BasisLocalTokenClaimsError(f"token is missing required claim {exc.claim!r}") from exc
    except jwt.InvalidSignatureError as exc:
        raise BasisLocalTokenSignatureError("token signature failed verification") from exc
    except jwt.DecodeError as exc:
        raise BasisLocalTokenSignatureError(
            "token could not be decoded or its signature is invalid"
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise BasisLocalTokenVerificationError("token failed standard claim validation") from exc

    missing = [
        path for path in trust_config.required_claims if not _claim_path_present(payload, path)
    ]
    if missing:
        raise BasisLocalTokenClaimsError(
            f"verified token payload is missing required claim path(s): {missing!r}"
        )

    token_type = payload.get("typ")
    if token_type != _BASIS_LOCAL_IDENTITY_TOKEN_TYPE:
        raise BasisLocalTokenClaimsError(f"unexpected token type {token_type!r}")

    claims = _basis_local_claims_from_verified_payload(payload)
    return _result_from_claims(claims)


# --------------------------------------------------------------------------- #
# Optional adapter into the existing gateway subject model
# --------------------------------------------------------------------------- #


def basis_local_verification_result_to_gateway_identity(
    result: BasisLocalTokenVerificationResult,
) -> tuple[NormalizedSubject, IdentityContext]:
    """Convert a verified BASIS-local identity into the existing gateway subject model.

    Mirrors :func:`basis_gateway.auth.subject_mapper.map_claims`'s output
    shape so a caller can treat a BASIS-local-verified identity exactly
    like an OIDC-verified one downstream. Subject identity is derived only
    from the verified result — never from caller-supplied fields.

    Args:
        result: An already-verified :class:`BasisLocalTokenVerificationResult`.

    Returns:
        A ``(NormalizedSubject, IdentityContext)`` pair.

    Raises:
        BasisLocalTokenClaimsError: ``result`` is not a
            :class:`BasisLocalTokenVerificationResult` instance.
    """

    if not isinstance(result, BasisLocalTokenVerificationResult):
        raise BasisLocalTokenClaimsError(
            "result must be a BasisLocalTokenVerificationResult instance"
        )

    subject_data = result.canonical_identity.get("subject")

    roles: tuple[str, ...] = ()
    display_name = result.subject_id
    attributes: dict[str, Any] = {}

    if isinstance(subject_data, Mapping):
        raw_roles = subject_data.get("roles")
        if isinstance(raw_roles, (list, tuple)):
            roles = tuple(sorted({role for role in raw_roles if isinstance(role, str)}))

        raw_display_name = subject_data.get("display_name")
        if isinstance(raw_display_name, str) and raw_display_name.strip():
            display_name = raw_display_name

        email = subject_data.get("email")
        if isinstance(email, str) and email:
            attributes["email"] = email

    subject = NormalizedSubject(
        subject_id=result.subject_id,
        name=display_name,
        roles=roles,
        attributes=attributes,
    )
    context = IdentityContext(
        issuer=result.issuer,
        subject_id=result.subject_id,
        claims=dict(result.claims),
    )
    return subject, context
