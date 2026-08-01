"""Tests for operation-producer trust configuration and classification.

Covers ``GatewayConfig.operation_producer_subject_ids`` parsing
(``src/basis_gateway/config.py``) and
``basis_gateway.auth.operation_producer.classify_operation_producer()`` —
PR 4 of
``docs/implementation/operation-aware-gateway-integration-plan.md`` (§5a,
§16, §17 "Operation-producer trust").

Scope: configuration parsing and the trust classifier in isolation. No
composition, no HTTP, no kernel involvement — see
``tests/test_operation_aware_composition.py`` for the composition-boundary
tests that consume this classifier's output.
"""

from __future__ import annotations

import copy

import pytest

from basis_gateway.auth.operation_producer import (
    OperationProducerTrust,
    OperationProducerTrustSource,
    OperationProducerTrustStatus,
    classify_operation_producer,
)
from basis_gateway.auth.subject_mapper import NormalizedSubject
from basis_gateway.config import GatewayConfig

# ---------------------------------------------------------------------------
# Configuration parsing
# ---------------------------------------------------------------------------


def test_default_allowlist_is_empty() -> None:
    config = GatewayConfig()
    assert config.operation_producer_subject_ids == frozenset()


def test_empty_env_var_produces_empty_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", "")
    config = GatewayConfig()
    assert config.operation_producer_subject_ids == frozenset()


def test_whitespace_only_env_var_produces_empty_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", "   ")
    config = GatewayConfig()
    assert config.operation_producer_subject_ids == frozenset()


def test_whitespace_is_trimmed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", "  adapter-1 ,  adapter-2  ")
    config = GatewayConfig()
    assert config.operation_producer_subject_ids == frozenset({"adapter-1", "adapter-2"})


def test_empty_entries_are_discarded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", "adapter-1,,adapter-2,")
    config = GatewayConfig()
    assert config.operation_producer_subject_ids == frozenset({"adapter-1", "adapter-2"})


def test_duplicate_subject_ids_are_deduplicated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", "adapter-1,adapter-2,adapter-1")
    config = GatewayConfig()
    assert config.operation_producer_subject_ids == frozenset({"adapter-1", "adapter-2"})


def test_matching_is_case_sensitive_at_parse_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", "Adapter-1,adapter-1")
    config = GatewayConfig()
    # Two distinct entries — case is preserved, not normalized.
    assert config.operation_producer_subject_ids == frozenset({"Adapter-1", "adapter-1"})


def test_wildcard_looking_values_are_treated_literally(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", "adapter-*,*")
    config = GatewayConfig()
    assert config.operation_producer_subject_ids == frozenset({"adapter-*", "*"})
    # No wildcard expansion — an unrelated subject id is not matched by "*".
    subject = NormalizedSubject(subject_id="adapter-1", name="adapter-1", roles=(), attributes={})
    result = classify_operation_producer(subject, config.operation_producer_subject_ids)
    assert result.status is OperationProducerTrustStatus.UNTRUSTED


def test_single_subject_id_no_trailing_comma(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", "adapter-1")
    config = GatewayConfig()
    assert config.operation_producer_subject_ids == frozenset({"adapter-1"})


# ---------------------------------------------------------------------------
# Trust classification
# ---------------------------------------------------------------------------


def _subject(
    subject_id: str = "adapter-1",
    roles: tuple[str, ...] = (),
    attributes: dict | None = None,
) -> NormalizedSubject:
    return NormalizedSubject(
        subject_id=subject_id,
        name=subject_id,
        roles=roles,
        attributes=attributes or {},
    )


def test_empty_allowlist_produces_untrusted_not_configured() -> None:
    result = classify_operation_producer(_subject("adapter-1"), frozenset())
    assert result.status is OperationProducerTrustStatus.UNTRUSTED
    assert result.source is OperationProducerTrustSource.NOT_CONFIGURED
    assert result.operation_producer_subject_id is None
    assert result.authorization_subject_id == "adapter-1"


def test_allowed_exact_subject_id_produces_trusted() -> None:
    result = classify_operation_producer(_subject("adapter-1"), frozenset({"adapter-1"}))
    assert result.status is OperationProducerTrustStatus.TRUSTED
    assert result.source is OperationProducerTrustSource.CONFIGURED_SUBJECT_ID_ALLOWLIST
    assert result.operation_producer_subject_id == "adapter-1"
    assert result.authorization_subject_id == "adapter-1"


def test_non_allowed_subject_produces_untrusted_subject_id_not_allowed() -> None:
    result = classify_operation_producer(_subject("human-1"), frozenset({"adapter-1"}))
    assert result.status is OperationProducerTrustStatus.UNTRUSTED
    assert result.source is OperationProducerTrustSource.SUBJECT_ID_NOT_ALLOWED
    assert result.operation_producer_subject_id is None
    assert result.authorization_subject_id == "human-1"


def test_case_mismatch_remains_untrusted() -> None:
    result = classify_operation_producer(_subject("Adapter-1"), frozenset({"adapter-1"}))
    assert result.status is OperationProducerTrustStatus.UNTRUSTED
    assert result.source is OperationProducerTrustSource.SUBJECT_ID_NOT_ALLOWED


def test_subject_roles_do_not_grant_trust() -> None:
    subject = _subject("human-1", roles=("operation-producer", "admin"))
    result = classify_operation_producer(subject, frozenset())
    assert result.status is OperationProducerTrustStatus.UNTRUSTED

    # Even with a non-empty allowlist that does not contain this subject id.
    result2 = classify_operation_producer(subject, frozenset({"adapter-1"}))
    assert result2.status is OperationProducerTrustStatus.UNTRUSTED


def test_subject_attributes_do_not_grant_trust() -> None:
    subject = _subject("human-1", attributes={"is_trusted_operation_producer": True})
    result = classify_operation_producer(subject, frozenset())
    assert result.status is OperationProducerTrustStatus.UNTRUSTED

    result2 = classify_operation_producer(subject, frozenset({"adapter-1"}))
    assert result2.status is OperationProducerTrustStatus.UNTRUSTED


def test_classification_signature_has_no_request_parameter() -> None:
    """Operation-aware request contents cannot influence classification.

    Structural guarantee: the classifier's signature accepts only a
    ``NormalizedSubject`` and a configured allowlist — there is no parameter
    through which request body content could be threaded in, so this is
    enforced by the function's shape, not just by convention.
    """
    import inspect

    params = list(inspect.signature(classify_operation_producer).parameters)
    assert params == ["subject", "trusted_subject_ids"]


def test_trusted_result_exposes_separate_operation_producer_subject_id() -> None:
    result = classify_operation_producer(_subject("adapter-1"), frozenset({"adapter-1"}))
    assert result.authorization_subject_id == "adapter-1"
    assert result.operation_producer_subject_id == "adapter-1"
    # Equal values, but tracked as two independently named fields.
    assert hasattr(result, "authorization_subject_id")
    assert hasattr(result, "operation_producer_subject_id")


def test_untrusted_result_exposes_no_operation_producer_subject_id() -> None:
    result = classify_operation_producer(_subject("human-1"), frozenset({"adapter-1"}))
    assert result.operation_producer_subject_id is None
    assert result.authorization_subject_id == "human-1"


def test_input_subject_is_not_mutated() -> None:
    subject = _subject("adapter-1", roles=("viewer",), attributes={"email": "a@example.com"})
    original_roles = subject.roles
    original_attributes = copy.deepcopy(subject.attributes)

    classify_operation_producer(subject, frozenset({"adapter-1"}))

    assert subject.roles == original_roles
    assert subject.attributes == original_attributes


def test_input_configuration_is_not_mutated() -> None:
    allowlist = frozenset({"adapter-1", "adapter-2"})
    original = frozenset(allowlist)

    classify_operation_producer(_subject("adapter-1"), allowlist)
    classify_operation_producer(_subject("human-1"), allowlist)

    assert allowlist == original


def test_operation_producer_trust_is_frozen() -> None:
    result = classify_operation_producer(_subject("adapter-1"), frozenset({"adapter-1"}))
    with pytest.raises(AttributeError):
        result.status = OperationProducerTrustStatus.UNTRUSTED  # type: ignore[misc]


def test_default_trusted_subject_ids_config_yields_no_trusted_caller() -> None:
    """No caller is a trusted operation producer with default configuration."""
    config = GatewayConfig()
    result = classify_operation_producer(
        _subject("any-subject"), config.operation_producer_subject_ids
    )
    assert result.status is OperationProducerTrustStatus.UNTRUSTED
    assert result.source is OperationProducerTrustSource.NOT_CONFIGURED


def test_operation_producer_trust_result_type_matches_dataclass() -> None:
    result = classify_operation_producer(_subject("adapter-1"), frozenset({"adapter-1"}))
    assert isinstance(result, OperationProducerTrust)
