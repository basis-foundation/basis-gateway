"""Unit tests for ``basis_gateway.auth.producer_mtls_trusted_proxy``
(Phase 1B.2).

Covers the internal certificate-assertion retrieval boundary in isolation,
using directly constructed Starlette ``Request`` objects (minimal ASGI
scopes) rather than a running server — no real NGINX or TLS is involved
here; that is the separate, real-process integration suite
(tests/integration/test_producer_mtls_trusted_proxy_boundary.py).
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import quote

import pytest
from starlette.requests import Request

from basis_gateway.auth.producer_mtls import (
    CertificateAssertionDecodingError,
    CertificateParsingError,
    decode_producer_certificate_assertion,
    derive_producer_identity,
    parse_producer_leaf_certificate,
)
from basis_gateway.auth.producer_mtls_trusted_proxy import (
    MAX_ASSERTION_SIZE_BYTES,
    PRODUCER_CLIENT_CERT_HEADER_NAME,
    DuplicateProducerCertificateAssertionError,
    OversizedProducerCertificateAssertionError,
    retrieve_trusted_producer_certificate_assertion,
)

_INTEGRATION_DIR = Path(__file__).parent / "integration"
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from mtls_certs import (  # noqa: E402  (path shim above must run first)
    ONE_URI_SAN,
    build_fixture_set,
)


def _request(headers: list[tuple[bytes, bytes]]) -> Request:
    """Build a minimal Starlette ``Request`` exposing exactly *headers* —
    enough to exercise ``request.headers`` without a running ASGI server."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/evaluate/operation-aware",
        "headers": headers,
    }
    return Request(scope)


def _escape_pem(pem_bytes: bytes) -> str:
    """Simulate nginx's ``$ssl_client_escaped_cert``: RFC 3986
    percent-encoding of a PEM block, escaping every non-unreserved byte
    (including ``+``, ``/``, and newlines). Mirrors
    tests/test_producer_mtls_certificate_identity.py's identical helper.
    """
    return quote(pem_bytes, safe="")


# ---------------------------------------------------------------------------
# Trusted-proxy mode disabled
# ---------------------------------------------------------------------------


def test_disabled_mode_with_no_header_returns_none():
    request = _request([])
    assert (
        retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=False)
        is None
    )


def test_disabled_mode_with_attacker_supplied_header_still_returns_none():
    """The header name alone never creates trust: when trusted-proxy mode
    is disabled, its presence must not trigger certificate parsing or any
    other new behavior."""
    request = _request(
        [(PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), b"attacker-controlled-value")]
    )
    assert (
        retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=False)
        is None
    )


# ---------------------------------------------------------------------------
# Trusted-proxy mode enabled
# ---------------------------------------------------------------------------


def test_enabled_mode_with_no_header_returns_none():
    request = _request([])
    assert (
        retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True) is None
    )


def test_enabled_mode_with_exactly_one_valid_shaped_header_returns_its_value():
    request = _request([(PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), b"some-value")])
    assert (
        retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)
        == "some-value"
    )


@pytest.mark.parametrize(
    "header_name_bytes",
    [
        b"X-BASIS-Producer-Client-Cert",
        b"x-basis-producer-client-cert",
        b"X-Basis-Producer-Client-Cert",
    ],
)
def test_header_lookup_is_case_insensitive(header_name_bytes: bytes):
    request = _request([(header_name_bytes, b"some-value")])
    assert (
        retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)
        == "some-value"
    )


def test_two_identical_occurrences_fail_closed():
    request = _request(
        [
            (PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), b"value-a"),
            (PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), b"value-a"),
        ]
    )
    with pytest.raises(DuplicateProducerCertificateAssertionError):
        retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)


def test_two_differently_cased_occurrences_fail_closed():
    request = _request(
        [
            (b"X-BASIS-Producer-Client-Cert", b"value-a"),
            (b"x-basis-producer-client-cert", b"value-b"),
        ]
    )
    with pytest.raises(DuplicateProducerCertificateAssertionError):
        retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)


def test_duplicate_detection_ignores_unrelated_headers():
    request = _request(
        [
            (b"host", b"example.test"),
            (PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), b"value-a"),
            (b"authorization", b"Bearer xyz"),
        ]
    )
    assert (
        retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)
        == "value-a"
    )


def test_oversized_assertion_fails_closed():
    oversized_value = ("a" * (MAX_ASSERTION_SIZE_BYTES + 1)).encode()
    request = _request([(PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), oversized_value)])
    with pytest.raises(OversizedProducerCertificateAssertionError):
        retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)


def test_assertion_exactly_at_permitted_bound_is_accepted():
    boundary_value = ("a" * MAX_ASSERTION_SIZE_BYTES).encode()
    request = _request([(PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), boundary_value)])
    result = retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)
    assert result is not None
    assert len(result) == MAX_ASSERTION_SIZE_BYTES


def test_assertion_just_over_permitted_bound_fails_closed():
    over_value = ("a" * (MAX_ASSERTION_SIZE_BYTES + 1)).encode()
    request = _request([(PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), over_value)])
    with pytest.raises(OversizedProducerCertificateAssertionError):
        retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)


# ---------------------------------------------------------------------------
# Raw value never appears in exception messages
# ---------------------------------------------------------------------------


def test_duplicate_error_message_does_not_contain_raw_values():
    secret_marker = "SECRET-CERT-VALUE-MUST-NOT-LEAK"
    request = _request(
        [
            (PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), secret_marker.encode()),
            (PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), secret_marker.encode()),
        ]
    )
    with pytest.raises(DuplicateProducerCertificateAssertionError) as exc_info:
        retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)
    assert secret_marker not in str(exc_info.value)


def test_oversized_error_message_does_not_contain_raw_value():
    secret_marker = "SECRET-CERT-VALUE-MUST-NOT-LEAK-"
    oversized_value = (secret_marker + "a" * MAX_ASSERTION_SIZE_BYTES).encode()
    request = _request([(PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), oversized_value)])
    with pytest.raises(OversizedProducerCertificateAssertionError) as exc_info:
        retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)
    assert secret_marker not in str(exc_info.value)


# ---------------------------------------------------------------------------
# Composition with the already-released Phase 1B.1 pipeline
# ---------------------------------------------------------------------------


def test_composition_malformed_percent_encoding_fails_closed_through_phase_1b1():
    request = _request(
        [(PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), b"%zz-not-valid-percent-encoding")]
    )
    assertion = retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)
    assert assertion is not None
    with pytest.raises(CertificateAssertionDecodingError):
        decode_producer_certificate_assertion(assertion)


def test_composition_malformed_pem_fails_closed_through_phase_1b1():
    request = _request(
        [(PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), quote(b"not a pem block").encode())]
    )
    assertion = retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)
    assert assertion is not None
    pem_bytes = decode_producer_certificate_assertion(assertion)
    with pytest.raises(CertificateParsingError):
        parse_producer_leaf_certificate(pem_bytes)


def test_composition_valid_assertion_yields_expected_uri_san(tmp_path):
    fixtures = build_fixture_set(tmp_path)
    escaped = _escape_pem(fixtures.client_one_uri_san.cert_pem)
    request = _request([(PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode(), escaped.encode())])

    assertion = retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)
    assert assertion is not None
    pem_bytes = decode_producer_certificate_assertion(assertion)
    certificate = parse_producer_leaf_certificate(pem_bytes)
    uri_san = derive_producer_identity(certificate)

    assert uri_san == ONE_URI_SAN
