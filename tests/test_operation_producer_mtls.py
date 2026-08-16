"""Unit tests for ``basis_gateway.auth.operation_producer_mtls`` (Phase 1B.3).

Covers the live mTLS producer-trust orchestration in isolation, using
directly constructed Starlette ``Request`` objects (mirroring
``tests/test_producer_mtls_trusted_proxy.py``'s own pattern) and the
retained Phase 1A/1B.2 PKI fixtures (``tests/integration/mtls_certs.py``) --
no real NGINX or TLS is involved here; that is the separate real-process
integration suite (``tests/integration/test_producer_mtls_live_gateway.py``).

Scope: proves the live orchestration composes Phase 1B.1/1B.2 correctly and
implements the mode-selection / no-fallback rule. Does not re-derive every
Phase 1B.1 certificate-identity edge case (already covered by
``tests/test_producer_mtls_certificate_identity.py``) or every Phase 1B.2
header-retrieval edge case (already covered by
``tests/test_producer_mtls_trusted_proxy.py``).
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import quote

import pytest
from starlette.requests import Request

from basis_gateway.auth.operation_producer import (
    OperationProducerTrustSource,
    OperationProducerTrustStatus,
)
from basis_gateway.auth.operation_producer_mtls import (
    MissingProducerCertificateAssertionError,
    resolve_mtls_operation_producer_trust,
    resolve_operation_producer_trust,
)
from basis_gateway.auth.producer_mtls import (
    CertificateAssertionDecodingError,
    CertificateParsingError,
    MultipleEligibleUriSansError,
    NoEligibleUriSanError,
)
from basis_gateway.auth.producer_mtls_trusted_proxy import (
    PRODUCER_CLIENT_CERT_HEADER_NAME,
    DuplicateProducerCertificateAssertionError,
    OversizedProducerCertificateAssertionError,
)
from basis_gateway.auth.subject_mapper import NormalizedSubject
from basis_gateway.config import GatewayConfig

_INTEGRATION_DIR = Path(__file__).parent / "integration"
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from mtls_certs import (  # noqa: E402  (path shim above must run first)
    MULTI_URI_SAN_A,
    ONE_URI_SAN,
    MTLSFixtureSet,
    build_fixture_set,
)

BEARER_SUBJECT = "service-maintenance-operator-01"


@pytest.fixture(scope="module")
def mtls_fixtures(tmp_path_factory: pytest.TempPathFactory) -> MTLSFixtureSet:
    return build_fixture_set(tmp_path_factory.mktemp("oa-producer-mtls-pki"))


def _subject(subject_id: str = BEARER_SUBJECT) -> NormalizedSubject:
    return NormalizedSubject(subject_id=subject_id, name=subject_id, roles=(), attributes={})


def _escape_pem(pem_bytes: bytes) -> str:
    """Simulate nginx's ``$ssl_client_escaped_cert``."""
    return quote(pem_bytes, safe="")


def _request(headers: list[tuple[bytes, bytes]]) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/evaluate/operation-aware",
        "headers": headers,
    }
    return Request(scope)


def _request_with_assertion(pem_bytes: bytes) -> Request:
    value = _escape_pem(pem_bytes).encode()
    return _request([(PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), value)])


# ---------------------------------------------------------------------------
# resolve_mtls_operation_producer_trust: admission outcomes
# ---------------------------------------------------------------------------


def test_admitted_uri_yields_trusted(mtls_fixtures: MTLSFixtureSet) -> None:
    request = _request_with_assertion(mtls_fixtures.client_one_uri_san.cert_pem)
    result = resolve_mtls_operation_producer_trust(
        request, subject=_subject(), admitted_producer_uris=frozenset({ONE_URI_SAN})
    )
    assert result.status is OperationProducerTrustStatus.TRUSTED
    assert result.source is OperationProducerTrustSource.MTLS_ADMITTED_URI_SAN
    assert result.producer_workload_identity == ONE_URI_SAN
    assert result.operation_producer_subject_id is None
    assert result.authorization_subject_id == BEARER_SUBJECT


def test_unadmitted_uri_yields_untrusted_not_admitted(mtls_fixtures: MTLSFixtureSet) -> None:
    request = _request_with_assertion(mtls_fixtures.client_one_uri_san.cert_pem)
    result = resolve_mtls_operation_producer_trust(
        request, subject=_subject(), admitted_producer_uris=frozenset()
    )
    assert result.status is OperationProducerTrustStatus.UNTRUSTED
    assert result.source is OperationProducerTrustSource.MTLS_URI_SAN_NOT_ADMITTED
    # The derived (non-secret) URI SAN is still recorded for diagnostics,
    # even though this producer is not admitted.
    assert result.producer_workload_identity == ONE_URI_SAN
    assert result.operation_producer_subject_id is None


def test_case_mismatched_admission_is_not_admitted(mtls_fixtures: MTLSFixtureSet) -> None:
    request = _request_with_assertion(mtls_fixtures.client_one_uri_san.cert_pem)
    mismatched = ONE_URI_SAN.upper()
    assert mismatched != ONE_URI_SAN
    result = resolve_mtls_operation_producer_trust(
        request, subject=_subject(), admitted_producer_uris=frozenset({mismatched})
    )
    assert result.status is OperationProducerTrustStatus.UNTRUSTED
    assert result.source is OperationProducerTrustSource.MTLS_URI_SAN_NOT_ADMITTED


def test_prefix_shaped_admitted_value_does_not_match(mtls_fixtures: MTLSFixtureSet) -> None:
    request = _request_with_assertion(mtls_fixtures.client_one_uri_san.cert_pem)
    result = resolve_mtls_operation_producer_trust(
        request,
        subject=_subject(),
        admitted_producer_uris=frozenset({ONE_URI_SAN[:-2]}),
    )
    assert result.status is OperationProducerTrustStatus.UNTRUSTED


def test_suffix_shaped_admitted_value_does_not_match(mtls_fixtures: MTLSFixtureSet) -> None:
    request = _request_with_assertion(mtls_fixtures.client_one_uri_san.cert_pem)
    result = resolve_mtls_operation_producer_trust(
        request,
        subject=_subject(),
        admitted_producer_uris=frozenset({ONE_URI_SAN[2:]}),
    )
    assert result.status is OperationProducerTrustStatus.UNTRUSTED


def test_wildcard_looking_admitted_value_is_literal_only(mtls_fixtures: MTLSFixtureSet) -> None:
    request = _request_with_assertion(mtls_fixtures.client_one_uri_san.cert_pem)
    result = resolve_mtls_operation_producer_trust(
        request,
        subject=_subject(),
        admitted_producer_uris=frozenset({"spiffe://example.test/basis/*", "*"}),
    )
    assert result.status is OperationProducerTrustStatus.UNTRUSTED


def test_empty_admission_set_trusts_no_mtls_producer(mtls_fixtures: MTLSFixtureSet) -> None:
    request = _request_with_assertion(mtls_fixtures.client_one_uri_san.cert_pem)
    result = resolve_mtls_operation_producer_trust(
        request, subject=_subject(), admitted_producer_uris=frozenset()
    )
    assert result.status is OperationProducerTrustStatus.UNTRUSTED


# ---------------------------------------------------------------------------
# Missing assertion: dedicated fail-closed exception, no OperationProducerTrust
# ---------------------------------------------------------------------------
# Per the merged producer-mtls-proxy-trust-boundary.md §11/§18: a missing
# internal certificate assertion on a request that reached basis-gateway
# while trusted-proxy mode is enabled is a Layer-2 proxy/backend
# trust-boundary failure, not an ordinary producer-trust outcome. It is
# architecturally impossible to interpret this absence as an
# OperationProducerTrust(status=UNTRUSTED) result -- resolve_mtls_operation_
# producer_trust() raises before constructing one.


def test_missing_assertion_raises_dedicated_exception_and_constructs_no_trust() -> None:
    request = _request([])
    with pytest.raises(MissingProducerCertificateAssertionError) as exc_info:
        resolve_mtls_operation_producer_trust(
            request, subject=_subject(), admitted_producer_uris=frozenset({ONE_URI_SAN})
        )
    # The exception message must never contain certificate data, headers,
    # bearer tokens, or request bodies -- only a fixed, generic description.
    message = str(exc_info.value)
    assert "Bearer" not in message
    assert "BEGIN CERTIFICATE" not in message
    assert PRODUCER_CLIENT_CERT_HEADER_NAME not in message


def test_missing_assertion_exception_shares_layer2_base_class() -> None:
    from basis_gateway.auth.producer_mtls_trusted_proxy import TrustedProxyAssertionError

    request = _request([])
    with pytest.raises(TrustedProxyAssertionError):
        resolve_mtls_operation_producer_trust(
            request, subject=_subject(), admitted_producer_uris=frozenset({ONE_URI_SAN})
        )


# ---------------------------------------------------------------------------
# Certificate boundary failures: exceptions, fail closed
# ---------------------------------------------------------------------------


def test_duplicate_assertion_raises(mtls_fixtures: MTLSFixtureSet) -> None:
    value = _escape_pem(mtls_fixtures.client_one_uri_san.cert_pem).encode()
    header_name = PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode()
    request = _request([(header_name, value), (header_name, value)])
    with pytest.raises(DuplicateProducerCertificateAssertionError):
        resolve_mtls_operation_producer_trust(
            request, subject=_subject(), admitted_producer_uris=frozenset({ONE_URI_SAN})
        )


def test_oversized_assertion_raises() -> None:
    header_name = PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode()
    oversized_value = b"%41" * 20_000  # far beyond MAX_ASSERTION_SIZE_BYTES
    request = _request([(header_name, oversized_value)])
    with pytest.raises(OversizedProducerCertificateAssertionError):
        resolve_mtls_operation_producer_trust(
            request, subject=_subject(), admitted_producer_uris=frozenset({ONE_URI_SAN})
        )


def test_malformed_percent_encoding_raises() -> None:
    header_name = PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode()
    request = _request([(header_name, b"%zz-not-valid-percent-encoding")])
    with pytest.raises(CertificateAssertionDecodingError):
        resolve_mtls_operation_producer_trust(
            request, subject=_subject(), admitted_producer_uris=frozenset({ONE_URI_SAN})
        )


def test_malformed_certificate_raises() -> None:
    header_name = PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode()
    bogus_pem = b"-----BEGIN CERTIFICATE-----\nnot-real-der-bytes\n-----END CERTIFICATE-----"
    value = quote(bogus_pem).encode()
    request = _request([(header_name, value)])
    with pytest.raises(CertificateParsingError):
        resolve_mtls_operation_producer_trust(
            request, subject=_subject(), admitted_producer_uris=frozenset({ONE_URI_SAN})
        )


def test_zero_uri_san_raises(mtls_fixtures: MTLSFixtureSet) -> None:
    request = _request_with_assertion(mtls_fixtures.client_zero_uri_san.cert_pem)
    with pytest.raises(NoEligibleUriSanError):
        resolve_mtls_operation_producer_trust(
            request, subject=_subject(), admitted_producer_uris=frozenset({ONE_URI_SAN})
        )


def test_multiple_uri_san_raises(mtls_fixtures: MTLSFixtureSet) -> None:
    request = _request_with_assertion(mtls_fixtures.client_multi_uri_san.cert_pem)
    with pytest.raises(MultipleEligibleUriSansError):
        resolve_mtls_operation_producer_trust(
            request,
            subject=_subject(),
            admitted_producer_uris=frozenset({MULTI_URI_SAN_A}),
        )


# ---------------------------------------------------------------------------
# resolve_operation_producer_trust: mode selection / no fallback
# ---------------------------------------------------------------------------


def test_mode_disabled_delegates_to_legacy_classifier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED", raising=False)
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", BEARER_SUBJECT)
    config = GatewayConfig()
    assert config.operation_producer_mtls_trusted_proxy_enabled is False

    request = _request([])  # no certificate header at all
    result = resolve_operation_producer_trust(request, subject=_subject(), config=config)
    assert result.status is OperationProducerTrustStatus.TRUSTED
    assert result.source is OperationProducerTrustSource.CONFIGURED_SUBJECT_ID_ALLOWLIST
    assert result.operation_producer_subject_id == BEARER_SUBJECT
    assert result.producer_workload_identity is None


def test_mode_disabled_ignores_certificate_looking_header(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    """A caller-supplied header shaped like the internal certificate
    assertion is completely ignored when trusted-proxy mode is disabled --
    no certificate parsing is triggered merely because the header exists."""
    monkeypatch.delenv("OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED", raising=False)
    monkeypatch.delenv("OPERATION_PRODUCER_SUBJECT_IDS", raising=False)
    config = GatewayConfig()

    request = _request_with_assertion(mtls_fixtures.client_one_uri_san.cert_pem)
    result = resolve_operation_producer_trust(request, subject=_subject(), config=config)
    # No exception raised (would be, if certificate parsing were triggered
    # by a malformed/attacker-shaped value) and the legacy NOT_CONFIGURED
    # result is returned untouched.
    assert result.status is OperationProducerTrustStatus.UNTRUSTED
    assert result.source is OperationProducerTrustSource.NOT_CONFIGURED


def test_mode_enabled_never_consults_legacy_allowlist_when_admitted(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    """Dual-identity proof: the bearer subject is deliberately NOT in the
    legacy allowlist, yet the mTLS path still establishes trust."""
    monkeypatch.setenv("OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED", "true")
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS",
        f'["{ONE_URI_SAN}"]',
    )
    monkeypatch.delenv("OPERATION_PRODUCER_SUBJECT_IDS", raising=False)
    config = GatewayConfig()
    assert BEARER_SUBJECT not in config.operation_producer_subject_ids

    request = _request_with_assertion(mtls_fixtures.client_one_uri_san.cert_pem)
    result = resolve_operation_producer_trust(request, subject=_subject(), config=config)
    assert result.status is OperationProducerTrustStatus.TRUSTED
    assert result.source is OperationProducerTrustSource.MTLS_ADMITTED_URI_SAN
    assert result.producer_workload_identity == ONE_URI_SAN


def test_mode_enabled_unadmitted_producer_cannot_be_rescued_by_legacy_allowlist(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    """No-fallback proof: even though the bearer subject IS in the legacy
    allowlist, an unadmitted mTLS producer certificate does not become
    trusted while trusted-proxy mode is enabled."""
    monkeypatch.setenv("OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED", "true")
    monkeypatch.delenv("OPERATION_PRODUCER_MTLS_ADMITTED_URIS", raising=False)  # empty
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", BEARER_SUBJECT)
    config = GatewayConfig()
    assert BEARER_SUBJECT in config.operation_producer_subject_ids

    request = _request_with_assertion(mtls_fixtures.client_one_uri_san.cert_pem)
    result = resolve_operation_producer_trust(request, subject=_subject(), config=config)
    assert result.status is OperationProducerTrustStatus.UNTRUSTED
    assert result.source is OperationProducerTrustSource.MTLS_URI_SAN_NOT_ADMITTED


def test_mode_enabled_malformed_assertion_cannot_be_rescued_by_legacy_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED", "true")
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", BEARER_SUBJECT)
    config = GatewayConfig()

    header_name = PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode()
    request = _request([(header_name, b"%zz-malformed")])
    with pytest.raises(CertificateAssertionDecodingError):
        resolve_operation_producer_trust(request, subject=_subject(), config=config)


def test_mode_enabled_missing_assertion_fails_closed_even_with_legacy_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mandatory no-fallback regression test: missing assertion + a bearer
    subject that IS present in the legacy allowlist still fails closed at
    the Layer-2 trust boundary -- legacy allowlist membership authenticates
    a bearer subject, not the trusted-proxy boundary, and cannot rescue a
    missing assertion. No OperationProducerTrust is returned or
    constructed."""
    monkeypatch.setenv("OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED", "true")
    monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", BEARER_SUBJECT)
    config = GatewayConfig()
    assert BEARER_SUBJECT in config.operation_producer_subject_ids

    request = _request([])
    with pytest.raises(MissingProducerCertificateAssertionError):
        resolve_operation_producer_trust(request, subject=_subject(), config=config)
