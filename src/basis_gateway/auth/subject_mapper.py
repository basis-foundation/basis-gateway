"""Subject mapper for basis-gateway.

Maps verified JWT claims into gateway-local normalized identity structures.
These structures will be used to construct ``basis-core`` domain types
(``Subject``, ``IdentityContext``) in Phase 3 when basis-core is integrated.

Design decisions documented here:

- ``sub`` is required. A missing ``sub`` raises ``SubjectMappingError``.
- Roles are sourced from (in priority order):
    1. ``realm_access.roles`` (Keycloak-style)
    2. ``roles`` (flat list claim)
  Malformed role structures (non-list values) normalize to an empty tuple;
  individual non-string role entries are silently dropped.
  This fail-open choice for roles means a broken claim structure does not
  hard-block authentication, but produces a subject with no roles, which will
  DENY in policy evaluation. Document this choice explicitly.
- Roles are deduplicated and sorted for deterministic output.
- ``preferred_username`` is used as the display name; falls back to ``sub``.
- ``email``, ``given_name``, ``family_name`` are collected into attributes.
- No deprecated ``subject_from_jwt`` from basis-core is called here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from basis_gateway.auth.errors import SubjectMappingError

# Claims included in ``NormalizedSubject.attributes`` when present.
_ATTRIBUTE_CLAIMS: tuple[str, ...] = (
    "email",
    "given_name",
    "family_name",
    "name",
)


@dataclass(frozen=True)
class NormalizedSubject:
    """Gateway-local normalized representation of an authenticated principal.

    Produced from verified JWT claims only. Never constructed from unverified
    input.

    Attributes:
        subject_id: The ``sub`` claim value. Always present.
        name: Display name. ``preferred_username`` if available, else ``sub``.
        roles: Sorted, deduplicated tuple of role strings.
        attributes: Dict of additional safe claims (email, given_name, etc.).
    """

    subject_id: str
    name: str
    roles: tuple[str, ...]
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IdentityContext:
    """Cross-boundary identity context derived from verified token claims.

    Carries the issuer and the full verified claims dict for use in
    constructing ``basis-core`` ``IdentityContext`` in Phase 3.

    Attributes:
        issuer: The ``iss`` claim value.
        subject_id: The ``sub`` claim value.
        claims: Full verified claims dictionary. Read-only snapshot.
    """

    issuer: str
    subject_id: str
    claims: dict[str, Any] = field(default_factory=dict)


def _extract_roles(claims: dict[str, Any]) -> tuple[str, ...]:
    """Extract and normalize roles from verified claims.

    Sources checked in order:
    1. ``realm_access.roles`` (Keycloak-style nested claim)
    2. ``roles`` (flat list claim)

    Malformed structures (non-list, non-string entries) are silently
    normalized away. Result is sorted and deduplicated.
    """
    raw: Any = None

    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict):
        raw = realm_access.get("roles")

    if not isinstance(raw, list):
        # Fall back to flat ``roles`` claim.
        raw = claims.get("roles")

    if not isinstance(raw, list):
        return ()

    # Drop non-string entries silently; deduplicate and sort.
    return tuple(sorted({r for r in raw if isinstance(r, str)}))


def map_claims(verified_claims: dict[str, Any]) -> tuple[NormalizedSubject, IdentityContext]:
    """Map *verified_claims* from a verified JWT into normalized identity structures.

    Args:
        verified_claims: The claim dictionary returned by the OIDC verifier.
            Must come from a fully verified token — never from an unverified
            decode call.

    Returns:
        A ``(NormalizedSubject, IdentityContext)`` pair.

    Raises:
        SubjectMappingError: If ``sub`` is absent or not a non-empty string.
    """
    subject_id = verified_claims.get("sub")
    if not isinstance(subject_id, str) or not subject_id:
        raise SubjectMappingError("Verified token is missing required 'sub' claim")

    name: str = verified_claims.get("preferred_username") or subject_id
    if not isinstance(name, str):
        name = subject_id

    roles = _extract_roles(verified_claims)

    attributes: dict[str, Any] = {}
    for claim_key in _ATTRIBUTE_CLAIMS:
        value = verified_claims.get(claim_key)
        if value is not None:
            attributes[claim_key] = value

    issuer = verified_claims.get("iss", "")
    if not isinstance(issuer, str):
        issuer = ""

    subject = NormalizedSubject(
        subject_id=subject_id,
        name=name,
        roles=roles,
        attributes=attributes,
    )
    context = IdentityContext(
        issuer=issuer,
        subject_id=subject_id,
        claims=dict(verified_claims),
    )
    return subject, context
