"""Tests for ``GatewayConfig.operation_producer_mtls_admitted_uris`` parsing
(Phase 1B.3 — ``OPERATION_PRODUCER_MTLS_ADMITTED_URIS``).

Scope: configuration parsing only. See
``tests/test_operation_producer_mtls.py`` for the live mTLS producer-trust
orchestration this configuration feeds, and
``tests/test_operation_aware_endpoint_producer_mtls.py`` for route-level
integration.

This is a deliberately distinct trust mechanism from
``OPERATION_PRODUCER_SUBJECT_IDS`` — its parser is not made to resemble that
allowlist's comma-separated/whitespace-trimming leniency merely for
consistency (ADR-0008 treats mTLS certificate identity and legacy bearer
subject identity as two different trust facts).
"""

from __future__ import annotations

import pytest

from basis_gateway.config import GatewayConfig

# ---------------------------------------------------------------------------
# Default / absence
# ---------------------------------------------------------------------------


def test_default_admitted_uris_is_empty() -> None:
    config = GatewayConfig()
    assert config.operation_producer_mtls_admitted_uris == frozenset()


def test_absent_env_var_yields_empty_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPERATION_PRODUCER_MTLS_ADMITTED_URIS", raising=False)
    config = GatewayConfig()
    assert config.operation_producer_mtls_admitted_uris == frozenset()


def test_existing_configuration_without_the_new_variable_remains_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deployment that only sets the legacy variable is unaffected."""
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", "adapter-1")
    monkeypatch.delenv("OPERATION_PRODUCER_MTLS_ADMITTED_URIS", raising=False)
    config = GatewayConfig()
    assert config.operation_producer_subject_ids == frozenset({"adapter-1"})
    assert config.operation_producer_mtls_admitted_uris == frozenset()


# ---------------------------------------------------------------------------
# Exact JSON-array loading
# ---------------------------------------------------------------------------


def test_json_array_with_one_uri_loads_exactly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        '["spiffe://example.test/basis/reference-producer-01"]',
    )
    config = GatewayConfig()
    assert config.operation_producer_mtls_admitted_uris == frozenset(
        {"spiffe://example.test/basis/reference-producer-01"}
    )


def test_json_array_with_multiple_exact_uris_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        '["spiffe://example.test/basis/producer-01", "spiffe://example.test/basis/producer-02"]',
    )
    config = GatewayConfig()
    assert config.operation_producer_mtls_admitted_uris == frozenset(
        {
            "spiffe://example.test/basis/producer-01",
            "spiffe://example.test/basis/producer-02",
        }
    )


def test_empty_json_array_yields_empty_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_MTLS_ADMITTED_URIS", "[]")
    config = GatewayConfig()
    assert config.operation_producer_mtls_admitted_uris == frozenset()


def test_duplicate_uris_collapse_via_frozenset_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        '["spiffe://example.test/basis/producer-01", "spiffe://example.test/basis/producer-01"]',
    )
    config = GatewayConfig()
    assert config.operation_producer_mtls_admitted_uris == frozenset(
        {"spiffe://example.test/basis/producer-01"}
    )


def test_case_is_preserved_not_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        '["spiffe://Example.Test/Basis/Producer-01", "spiffe://example.test/basis/producer-01"]',
    )
    config = GatewayConfig()
    # Two distinct entries -- case is preserved, never folded.
    assert config.operation_producer_mtls_admitted_uris == frozenset(
        {
            "spiffe://Example.Test/Basis/Producer-01",
            "spiffe://example.test/basis/producer-01",
        }
    )


def test_wildcard_shaped_values_remain_literal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        '["spiffe://example.test/basis/*", "*"]',
    )
    config = GatewayConfig()
    assert config.operation_producer_mtls_admitted_uris == frozenset(
        {"spiffe://example.test/basis/*", "*"}
    )


def test_no_whitespace_trimming(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unlike OPERATION_PRODUCER_SUBJECT_IDS, entries are never trimmed --
    a URI with meaningful leading/trailing whitespace (however unusual)
    would be silently altered by trimming, which this parser never does."""
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        '[" spiffe://example.test/basis/producer-01 "]',
    )
    config = GatewayConfig()
    assert config.operation_producer_mtls_admitted_uris == frozenset(
        {" spiffe://example.test/basis/producer-01 "}
    )


# ---------------------------------------------------------------------------
# Rejected shapes
# ---------------------------------------------------------------------------


def test_scalar_string_configuration_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        "spiffe://example.test/basis/reference-producer-01",
    )
    with pytest.raises(Exception, match="JSON array"):
        GatewayConfig()


def test_json_string_literal_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A value that IS valid JSON, but decodes to a scalar string rather
    than an array, is still rejected -- not merely malformed-JSON is
    rejected, but any non-array JSON shape."""
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        '"spiffe://example.test/basis/reference-producer-01"',
    )
    with pytest.raises(Exception, match="JSON array"):
        GatewayConfig()


def test_malformed_json_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_MTLS_ADMITTED_URIS", "[not valid json")
    with pytest.raises(Exception, match="valid JSON"):
        GatewayConfig()


def test_object_shaped_json_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        '{"spiffe://example.test/basis/producer-01": true}',
    )
    with pytest.raises(Exception, match="JSON array"):
        GatewayConfig()


def test_number_shaped_json_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_MTLS_ADMITTED_URIS", "42")
    with pytest.raises(Exception, match="JSON array"):
        GatewayConfig()


def test_empty_string_member_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        '["spiffe://example.test/basis/producer-01", ""]',
    )
    with pytest.raises(Exception, match="empty"):
        GatewayConfig()


def test_non_string_member_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        '["spiffe://example.test/basis/producer-01", 42]',
    )
    with pytest.raises(Exception, match="string"):
        GatewayConfig()


def test_array_of_arrays_member_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_MTLS_ADMITTED_URIS", "[[]]")
    with pytest.raises(Exception, match="string"):
        GatewayConfig()


# ---------------------------------------------------------------------------
# Programmatic (non-string) construction -- same per-entry rules
# ---------------------------------------------------------------------------


def test_programmatic_frozenset_construction_is_accepted() -> None:
    config = GatewayConfig(
        operation_producer_mtls_admitted_uris=frozenset({"spiffe://example.test/basis/producer-01"})
    )
    assert config.operation_producer_mtls_admitted_uris == frozenset(
        {"spiffe://example.test/basis/producer-01"}
    )


def test_programmatic_construction_rejects_empty_string_entry() -> None:
    with pytest.raises(Exception, match="empty"):
        GatewayConfig(operation_producer_mtls_admitted_uris=["spiffe://example.test/basis/x", ""])


def test_programmatic_construction_rejects_non_string_entry() -> None:
    with pytest.raises(Exception, match="string"):
        GatewayConfig(operation_producer_mtls_admitted_uris=["spiffe://example.test/basis/x", 1])


# ---------------------------------------------------------------------------
# Trusted-proxy mode / admission-set independence
# ---------------------------------------------------------------------------


def test_trusted_proxy_mode_can_be_enabled_with_empty_admission_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicitly empty admission set is a legitimate, fail-closed
    configuration -- trusted-proxy mode does not require a non-empty
    admission set to be enabled."""
    monkeypatch.setenv("OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED", "true")
    monkeypatch.delenv("OPERATION_PRODUCER_MTLS_ADMITTED_URIS", raising=False)
    config = GatewayConfig()
    assert config.operation_producer_mtls_trusted_proxy_enabled is True
    assert config.operation_producer_mtls_admitted_uris == frozenset()


def test_admitted_uris_do_not_require_trusted_proxy_mode_to_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two settings are independently parsed/valid -- an admission set
    configured while trusted-proxy mode is off still loads without error
    (it simply has no live effect while the mode is disabled)."""
    monkeypatch.delenv("OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED", raising=False)
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        '["spiffe://example.test/basis/producer-01"]',
    )
    config = GatewayConfig()
    assert config.operation_producer_mtls_trusted_proxy_enabled is False
    assert config.operation_producer_mtls_admitted_uris == frozenset(
        {"spiffe://example.test/basis/producer-01"}
    )
