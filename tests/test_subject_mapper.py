"""Tests for the subject mapper.

All tests use plain claim dictionaries — no real JWTs required.
The mapper only accepts already-verified claims.
"""

from __future__ import annotations

import pytest

from basis_gateway.auth.errors import SubjectMappingError
from basis_gateway.auth.subject_mapper import map_claims

# ---------------------------------------------------------------------------
# Basic mapping
# ---------------------------------------------------------------------------


def test_standard_oidc_claims_map_correctly():
    claims = {
        "sub": "user-123",
        "preferred_username": "alice",
        "iss": "https://example.com",
        "email": "alice@example.com",
    }
    subject, context = map_claims(claims)
    assert subject.subject_id == "user-123"
    assert subject.name == "alice"
    assert context.issuer == "https://example.com"
    assert context.subject_id == "user-123"


def test_name_falls_back_to_sub_when_preferred_username_absent():
    claims = {"sub": "user-456", "iss": "https://example.com"}
    subject, _ = map_claims(claims)
    assert subject.name == "user-456"


def test_name_falls_back_to_sub_when_preferred_username_not_string():
    claims = {"sub": "user-789", "preferred_username": 42, "iss": "https://example.com"}
    subject, _ = map_claims(claims)
    assert subject.name == "user-789"


# ---------------------------------------------------------------------------
# Role extraction — Keycloak-style realm_access.roles
# ---------------------------------------------------------------------------


def test_keycloak_realm_access_roles_mapped():
    claims = {
        "sub": "u1",
        "iss": "https://example.com",
        "realm_access": {"roles": ["admin", "viewer"]},
    }
    subject, _ = map_claims(claims)
    assert "admin" in subject.roles
    assert "viewer" in subject.roles


def test_flat_roles_claim_mapped():
    claims = {"sub": "u1", "iss": "https://example.com", "roles": ["operator"]}
    subject, _ = map_claims(claims)
    assert subject.roles == ("operator",)


def test_realm_access_roles_takes_priority_over_flat_roles():
    claims = {
        "sub": "u1",
        "iss": "https://example.com",
        "realm_access": {"roles": ["admin"]},
        "roles": ["operator"],
    }
    subject, _ = map_claims(claims)
    # realm_access.roles wins when present.
    assert subject.roles == ("admin",)


def test_duplicate_roles_removed():
    claims = {
        "sub": "u1",
        "iss": "https://example.com",
        "roles": ["admin", "admin", "viewer"],
    }
    subject, _ = map_claims(claims)
    assert subject.roles.count("admin") == 1


def test_roles_sorted_deterministically():
    claims = {
        "sub": "u1",
        "iss": "https://example.com",
        "roles": ["zebra", "alpha", "middle"],
    }
    subject, _ = map_claims(claims)
    assert subject.roles == ("alpha", "middle", "zebra")


def test_roles_immutable_tuple():
    claims = {"sub": "u1", "iss": "https://example.com", "roles": ["admin"]}
    subject, _ = map_claims(claims)
    assert isinstance(subject.roles, tuple)


# ---------------------------------------------------------------------------
# Malformed roles — fail-open to empty tuple (documented choice)
# ---------------------------------------------------------------------------


def test_malformed_roles_non_list_produces_empty_tuple():
    claims = {"sub": "u1", "iss": "https://example.com", "roles": "not-a-list"}
    subject, _ = map_claims(claims)
    assert subject.roles == ()


def test_malformed_realm_access_non_dict_produces_empty_tuple():
    claims = {"sub": "u1", "iss": "https://example.com", "realm_access": "bad"}
    subject, _ = map_claims(claims)
    assert subject.roles == ()


def test_non_string_role_entries_dropped():
    claims = {"sub": "u1", "iss": "https://example.com", "roles": ["valid", 42, None, "also-valid"]}
    subject, _ = map_claims(claims)
    assert subject.roles == ("also-valid", "valid")


def test_empty_roles_list_produces_empty_tuple():
    claims = {"sub": "u1", "iss": "https://example.com", "roles": []}
    subject, _ = map_claims(claims)
    assert subject.roles == ()


# ---------------------------------------------------------------------------
# Attributes
# ---------------------------------------------------------------------------


def test_attributes_include_email():
    claims = {"sub": "u1", "iss": "https://example.com", "email": "u1@example.com"}
    subject, _ = map_claims(claims)
    assert subject.attributes["email"] == "u1@example.com"


def test_attributes_include_given_name():
    claims = {"sub": "u1", "iss": "https://example.com", "given_name": "Alice"}
    subject, _ = map_claims(claims)
    assert subject.attributes["given_name"] == "Alice"


def test_attributes_include_family_name():
    claims = {"sub": "u1", "iss": "https://example.com", "family_name": "Smith"}
    subject, _ = map_claims(claims)
    assert subject.attributes["family_name"] == "Smith"


def test_missing_optional_attribute_claims_absent_from_attributes():
    claims = {"sub": "u1", "iss": "https://example.com"}
    subject, _ = map_claims(claims)
    # No email / given_name / family_name in output.
    assert "email" not in subject.attributes
    assert "given_name" not in subject.attributes


# ---------------------------------------------------------------------------
# Required fields
# ---------------------------------------------------------------------------


def test_missing_sub_raises():
    claims = {"iss": "https://example.com"}
    with pytest.raises(SubjectMappingError, match="sub"):
        map_claims(claims)


def test_empty_sub_raises():
    claims = {"sub": "", "iss": "https://example.com"}
    with pytest.raises(SubjectMappingError, match="sub"):
        map_claims(claims)


def test_non_string_sub_raises():
    claims = {"sub": 123, "iss": "https://example.com"}
    with pytest.raises(SubjectMappingError, match="sub"):
        map_claims(claims)


# ---------------------------------------------------------------------------
# IdentityContext
# ---------------------------------------------------------------------------


def test_identity_context_carries_full_claims():
    claims = {"sub": "u1", "iss": "https://example.com", "custom": "value"}
    _, context = map_claims(claims)
    assert context.claims["custom"] == "value"


def test_identity_context_issuer_defaults_to_empty_when_absent():
    claims = {"sub": "u1"}
    _, context = map_claims(claims)
    assert context.issuer == ""


def test_identity_context_is_frozen():
    claims = {"sub": "u1", "iss": "https://example.com"}
    _, context = map_claims(claims)
    with pytest.raises((AttributeError, TypeError)):
        context.issuer = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Deprecation guard — subject_from_jwt must not be called
# ---------------------------------------------------------------------------


def test_mapper_does_not_call_deprecated_subject_from_jwt(monkeypatch):
    """Verify subject_mapper.py never calls the deprecated basis-core helper."""
    called = []

    def _spy(*args, **kwargs):  # type: ignore[no-untyped-def]
        called.append(True)
        raise AssertionError("subject_from_jwt must not be called from basis-gateway")

    # Patch it in the domain module if importable; otherwise the test is vacuously true.
    try:
        import basis_core.domain.subject as _subject_mod

        monkeypatch.setattr(_subject_mod, "subject_from_jwt", _spy)
    except ImportError:
        pass  # basis-core not installed; constraint trivially satisfied

    claims = {
        "sub": "u1",
        "iss": "https://example.com",
        "realm_access": {"roles": ["admin"]},
    }
    map_claims(claims)
    assert not called, "subject_from_jwt was called — this is a boundary violation"
