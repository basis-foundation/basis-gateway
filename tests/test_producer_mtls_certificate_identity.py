"""Unit tests for ``basis_gateway.auth.producer_mtls`` (Phase 1B.1).

Covers the three internal primitives Phase 1B.1 implements in isolation:
strict URL-escaped PEM decoding, X.509 leaf parsing, exactly-one-URI-SAN
identity derivation, and exact-match producer admission. No HTTP request,
no FastAPI/Starlette involvement, no live endpoint — see
``producer_mtls.py``'s own module docstring for why that wiring is
deliberately out of scope for this PR.

Certificate fixtures: the canonical zero/one/multi-URI-SAN shapes reuse
``tests/integration/mtls_certs.py``'s ``build_fixture_set()`` (the Phase 1A
spike's own PKI generator, which already documents itself as covering
"every URI SAN shape ADR-0008 cares about"). A small local helper,
``_self_signed_leaf_pem``, supplements it only for SAN-type-mixing shapes
(URI SAN alongside DNS/IP/email SANs, and a Common-Name-only certificate)
that the shared fixture set does not construct. Chain-of-trust is out of
scope for this module (see ``producer_mtls.py``'s docstring — certificate
authentication belongs to the trusted NGINX ingress, not this module), so
self-signed certificates are sufficient for every test here; no CA
signing is required.
"""

from __future__ import annotations

import datetime
import ipaddress
import sys
from pathlib import Path
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from basis_gateway.auth.producer_mtls import (
    CertificateAssertionDecodingError,
    CertificateParsingError,
    MultipleEligibleUriSansError,
    NoEligibleUriSanError,
    ProducerAdmissionConfigurationError,
    ProducerAdmissionStatus,
    admit_producer,
    decode_producer_certificate_assertion,
    derive_producer_identity,
    parse_producer_leaf_certificate,
)

_INTEGRATION_DIR = Path(__file__).parent / "integration"
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from mtls_certs import (  # noqa: E402  (path shim above must run first)
    ONE_URI_SAN,
    build_fixture_set,
)

# ---------------------------------------------------------------------------
# Local certificate helper (SAN shapes not covered by mtls_certs.py)
# ---------------------------------------------------------------------------


def _self_signed_leaf_pem(*, common_name: str, san_entries: list[x509.GeneralName] | None) -> bytes:
    """A minimal self-signed leaf certificate PEM for structural
    parsing/SAN-derivation tests. No CA signing — chain-of-trust is not
    this module's responsibility (see ``producer_mtls.py``)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    if san_entries is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


def _escape_pem(pem_bytes: bytes) -> str:
    """Simulate nginx's ``$ssl_client_escaped_cert``: RFC 3986
    percent-encoding of a PEM block, escaping every non-unreserved byte
    (including ``+``, ``/``, and newlines)."""
    return quote(pem_bytes, safe="")


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


def test_valid_url_escaped_pem_decodes_to_original_bytes(tmp_path: Path) -> None:
    fixtures = build_fixture_set(tmp_path)
    escaped = _escape_pem(fixtures.client_one_uri_san.cert_pem)

    decoded = decode_producer_certificate_assertion(escaped)

    assert decoded == fixtures.client_one_uri_san.cert_pem


def test_valid_decoded_pem_parses_and_yields_expected_uri_san(tmp_path: Path) -> None:
    fixtures = build_fixture_set(tmp_path)
    escaped = _escape_pem(fixtures.client_one_uri_san.cert_pem)

    decoded = decode_producer_certificate_assertion(escaped)
    certificate = parse_producer_leaf_certificate(decoded)

    assert derive_producer_identity(certificate) == ONE_URI_SAN


@pytest.mark.parametrize(
    "malformed",
    [
        "%zz",  # not hex
        "abc%4",  # truncated at end of string
        "abc%",  # bare trailing percent
        "%",  # bare percent, nothing else
        "%2",  # only one hex digit present
    ],
)
def test_malformed_percent_encoding_fails_closed(malformed: str) -> None:
    with pytest.raises(CertificateAssertionDecodingError):
        decode_producer_certificate_assertion(malformed)


def test_non_ascii_character_fails_closed() -> None:
    with pytest.raises(CertificateAssertionDecodingError):
        decode_producer_certificate_assertion("café")


def test_decoder_does_not_double_decode() -> None:
    # "%2541" single-decodes to the three literal bytes b"%41". If the
    # decoder mistakenly ran a second pass, b"%41" would further decode to
    # b"A" (0x41) -- the regression this test guards against.
    result = decode_producer_certificate_assertion("%2541")

    assert result == b"%41"


def test_plus_sign_is_never_reinterpreted_as_space() -> None:
    result = decode_producer_certificate_assertion("A+B")

    assert result == b"A+B"


def test_percent_encoded_plus_round_trips_to_literal_plus() -> None:
    result = decode_producer_certificate_assertion("%2B")

    assert result == b"+"


def test_malformed_decoded_pem_fails_closed_at_parse_time() -> None:
    escaped = _escape_pem(b"this is not a certificate")
    decoded = decode_producer_certificate_assertion(escaped)

    with pytest.raises(CertificateParsingError):
        parse_producer_leaf_certificate(decoded)


def test_empty_assertion_fails_closed_at_parse_time() -> None:
    decoded = decode_producer_certificate_assertion("")

    with pytest.raises(CertificateParsingError):
        parse_producer_leaf_certificate(decoded)


# ---------------------------------------------------------------------------
# Exactly-one-PEM-certificate-block enforcement
#
# cryptography.x509.load_pem_x509_certificate is structurally permissive: it
# parses the first CERTIFICATE block it finds and silently ignores a second
# concatenated certificate, leading junk, or trailing junk. This boundary
# must enforce exactly one block itself.
# ---------------------------------------------------------------------------


def test_single_pem_certificate_block_parses_successfully(tmp_path: Path) -> None:
    fixtures = build_fixture_set(tmp_path)

    certificate = parse_producer_leaf_certificate(fixtures.client_one_uri_san.cert_pem)

    assert derive_producer_identity(certificate) == ONE_URI_SAN


def test_two_concatenated_pem_certificates_fail_closed(tmp_path: Path) -> None:
    fixtures = build_fixture_set(tmp_path)
    concatenated = fixtures.client_one_uri_san.cert_pem + fixtures.client_multi_uri_san.cert_pem

    with pytest.raises(CertificateParsingError):
        parse_producer_leaf_certificate(concatenated)


def test_junk_preceding_valid_certificate_fails_closed(tmp_path: Path) -> None:
    fixtures = build_fixture_set(tmp_path)
    prefixed = b"JUNK-BEFORE\n" + fixtures.client_one_uri_san.cert_pem

    with pytest.raises(CertificateParsingError):
        parse_producer_leaf_certificate(prefixed)


def test_junk_following_valid_certificate_fails_closed(tmp_path: Path) -> None:
    fixtures = build_fixture_set(tmp_path)
    suffixed = fixtures.client_one_uri_san.cert_pem + b"JUNK-AFTER\n"

    with pytest.raises(CertificateParsingError):
        parse_producer_leaf_certificate(suffixed)


def test_surrounding_whitespace_only_still_parses(tmp_path: Path) -> None:
    # Whitespace-only padding around the single PEM block is not "data" and
    # must not be rejected -- only non-whitespace surrounding content is.
    fixtures = build_fixture_set(tmp_path)
    padded = b"\n  \n" + fixtures.client_one_uri_san.cert_pem + b"\n\n  \n"

    certificate = parse_producer_leaf_certificate(padded)

    assert derive_producer_identity(certificate) == ONE_URI_SAN


# ---------------------------------------------------------------------------
# URI SAN identity derivation
# ---------------------------------------------------------------------------


def test_one_uri_san_returns_verbatim_identity(tmp_path: Path) -> None:
    fixtures = build_fixture_set(tmp_path)
    certificate = parse_producer_leaf_certificate(fixtures.client_one_uri_san.cert_pem)

    assert derive_producer_identity(certificate) == ONE_URI_SAN


def test_zero_uri_san_fails_closed(tmp_path: Path) -> None:
    fixtures = build_fixture_set(tmp_path)
    certificate = parse_producer_leaf_certificate(fixtures.client_zero_uri_san.cert_pem)

    with pytest.raises(NoEligibleUriSanError):
        derive_producer_identity(certificate)


def test_multiple_uri_san_fails_closed(tmp_path: Path) -> None:
    fixtures = build_fixture_set(tmp_path)
    certificate = parse_producer_leaf_certificate(fixtures.client_multi_uri_san.cert_pem)

    with pytest.raises(MultipleEligibleUriSansError):
        derive_producer_identity(certificate)


def test_common_name_only_fails_closed_no_san_extension() -> None:
    pem = _self_signed_leaf_pem(common_name="no-san-producer", san_entries=None)
    certificate = parse_producer_leaf_certificate(pem)

    with pytest.raises(NoEligibleUriSanError):
        derive_producer_identity(certificate)


def test_common_name_plus_non_uri_san_fails_closed() -> None:
    pem = _self_signed_leaf_pem(
        common_name="dns-only-producer",
        san_entries=[x509.DNSName("example.test")],
    )
    certificate = parse_producer_leaf_certificate(pem)

    with pytest.raises(NoEligibleUriSanError):
        derive_producer_identity(certificate)


def test_one_uri_san_plus_dns_san_still_succeeds() -> None:
    pem = _self_signed_leaf_pem(
        common_name="mixed-san-producer",
        san_entries=[
            x509.UniformResourceIdentifier(ONE_URI_SAN),
            x509.DNSName("example.test"),
        ],
    )
    certificate = parse_producer_leaf_certificate(pem)

    assert derive_producer_identity(certificate) == ONE_URI_SAN


def test_one_uri_san_plus_other_non_uri_san_types_still_succeeds() -> None:
    pem = _self_signed_leaf_pem(
        common_name="mixed-san-producer-2",
        san_entries=[
            x509.UniformResourceIdentifier(ONE_URI_SAN),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.RFC822Name("producer@example.test"),
        ],
    )
    certificate = parse_producer_leaf_certificate(pem)

    assert derive_producer_identity(certificate) == ONE_URI_SAN


def test_producer_identity_never_derived_from_common_name() -> None:
    """Security regression test: even when the Common Name is itself
    SAN-shaped text that could plausibly be mistaken for an identity, the
    derived producer identity must come only from the URI SAN, never from
    Common Name."""
    impersonating_common_name = "spiffe://impersonator.test/basis/fake-producer"
    pem = _self_signed_leaf_pem(
        common_name=impersonating_common_name,
        san_entries=[x509.UniformResourceIdentifier(ONE_URI_SAN)],
    )
    certificate = parse_producer_leaf_certificate(pem)

    identity = derive_producer_identity(certificate)

    assert identity == ONE_URI_SAN
    assert identity != impersonating_common_name


# ---------------------------------------------------------------------------
# Exact producer admission
# ---------------------------------------------------------------------------


def test_exact_admitted_uri_is_admitted() -> None:
    result = admit_producer(ONE_URI_SAN, {ONE_URI_SAN})

    assert result.status == ProducerAdmissionStatus.ADMITTED
    assert result.producer_uri == ONE_URI_SAN


def test_exact_unadmitted_uri_is_rejected() -> None:
    result = admit_producer(ONE_URI_SAN, {"spiffe://example.test/basis/reference-producer-02"})

    assert result.status == ProducerAdmissionStatus.NOT_ADMITTED


def test_empty_admission_set_admits_nothing() -> None:
    result = admit_producer(ONE_URI_SAN, frozenset())

    assert result.status == ProducerAdmissionStatus.NOT_ADMITTED


def test_case_mismatch_is_rejected() -> None:
    admitted = {"SPIFFE://example.test/basis/reference-producer-01"}

    result = admit_producer(ONE_URI_SAN, admitted)

    assert result.status == ProducerAdmissionStatus.NOT_ADMITTED


def test_prefix_match_attempt_is_rejected() -> None:
    # admitted set contains a value ONE_URI_SAN is a strict prefix of
    admitted = {ONE_URI_SAN + "/child"}

    result = admit_producer(ONE_URI_SAN, admitted)

    assert result.status == ProducerAdmissionStatus.NOT_ADMITTED


def test_suffix_match_attempt_is_rejected() -> None:
    admitted = {"prefix-" + ONE_URI_SAN}

    result = admit_producer(ONE_URI_SAN, admitted)

    assert result.status == ProducerAdmissionStatus.NOT_ADMITTED


def test_substring_match_attempt_is_rejected() -> None:
    admitted = {ONE_URI_SAN[:-1]}  # admitted value is a strict substring

    result = admit_producer(ONE_URI_SAN, admitted)

    assert result.status == ProducerAdmissionStatus.NOT_ADMITTED


def test_longer_suffix_variant_is_rejected() -> None:
    # ADR-0008's own example: "...reference-producer-010" must not match
    # an admitted "...reference-producer-01".
    admitted = {ONE_URI_SAN}
    presented = ONE_URI_SAN + "0"

    result = admit_producer(presented, admitted)

    assert result.status == ProducerAdmissionStatus.NOT_ADMITTED


def test_wildcard_shaped_admission_entry_is_treated_as_a_literal_string() -> None:
    admitted = {"spiffe://example.test/basis/*"}

    result = admit_producer(ONE_URI_SAN, admitted)

    assert result.status == ProducerAdmissionStatus.NOT_ADMITTED


def test_admission_does_not_mutate_inputs() -> None:
    admitted = frozenset({ONE_URI_SAN})

    admit_producer(ONE_URI_SAN, admitted)

    assert admitted == frozenset({ONE_URI_SAN})


# ---------------------------------------------------------------------------
# Scalar-string admission hardening
#
# A bare `str` is itself an iterable of characters and supports Python's
# `in` operator with *substring* semantics. Without a runtime guard, an
# accidentally scalar-string `admitted_producer_uris` argument would
# silently turn exact set-membership matching into substring matching --
# exactly the fuzzy admission behavior ADR-0008 forbids. See
# test_exact_admitted_uri_is_admitted above for proof that a normal,
# correctly-typed exact identity set still admits an exact value.
# ---------------------------------------------------------------------------


def test_scalar_string_admission_argument_fails_closed() -> None:
    with pytest.raises(ProducerAdmissionConfigurationError):
        admit_producer(ONE_URI_SAN, ONE_URI_SAN)  # type: ignore[arg-type]


def test_scalar_string_containing_producer_uri_as_substring_cannot_admit() -> None:
    # If the runtime guard were absent, `ONE_URI_SAN in admitted_as_scalar`
    # would evaluate True via substring containment, silently admitting a
    # producer that was never exactly configured. It must instead fail
    # closed, exactly like any other scalar-string misuse.
    admitted_as_scalar = "prefix-" + ONE_URI_SAN + "-suffix"
    assert ONE_URI_SAN in admitted_as_scalar  # sanity: the substring is present

    with pytest.raises(ProducerAdmissionConfigurationError):
        admit_producer(ONE_URI_SAN, admitted_as_scalar)  # type: ignore[arg-type]
