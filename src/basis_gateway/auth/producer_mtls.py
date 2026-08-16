"""Producer mTLS certificate identity and exact admission primitives.

Phase 1B.1 of the bounded operation-producer reference implementation
(``basis-architecture`` ADR-0008 "Producer Workload Authentication and
Gateway Admission" and ADR-0009 "Trusted Producer mTLS Ingress and Gateway
Certificate Handoff"). This module implements only the reusable,
gateway-owned half of the certificate-identity pipeline those ADRs
authorize:

    trusted authenticated leaf-certificate assertion
        -> strict URL-escaped PEM decoding
        -> X.509 parsing
        -> exactly one URI SAN
        -> exact case-sensitive producer admission

What this module is not
------------------------
This module does **not** accept a FastAPI/Starlette ``Request``, does not
read HTTP headers, and does not decide whether a certificate assertion is
trustworthy. It operates entirely on an already-supplied certificate
assertion *value* (the accepted ADR-0009 internal transport representation:
a URL-escaped PEM leaf certificate, corresponding to what a trusted NGINX
ingress would derive from ``$ssl_client_escaped_cert``). Establishing that a
given assertion value actually originated from a trusted ingress is Phase
1B.2's responsibility (``auth/producer_mtls_trusted_proxy.py``); composing
that with this module's pipeline into a live ``OperationProducerTrust`` is
Phase 1B.3's responsibility (``auth/operation_producer_mtls.py``, see
``docs/implementation/producer-mtls-phase-1b3.md``). As of Phase 1B.3, this
module's functions ARE reachable from the live
``POST /v1/evaluate/operation-aware`` route, indirectly, through that
orchestration module — never directly from ``api/routes.py``, and never by
accepting a ``Request`` themselves.

Producer workload identity vs. authorization subject
------------------------------------------------------
The **producer workload identity** this module derives (a URI SAN on an
authenticated leaf certificate) answers *which admitted workload submitted
this operation?* It is never the same fact as the **authorization
subject** (``auth/subject_mapper.py``'s ``NormalizedSubject``, established
by the gateway's existing Bearer-token dispatch), which answers *whose
authority is basis-core evaluating?* This module never constructs, reads,
or mutates a ``NormalizedSubject``, and nothing in this module's output may
be assigned to ``subject_id`` or any authorization-subject field — see
ADR-0008's "Producer vs. authorization subject".

Security invariants this module enforces
-----------------------------------------
- Producer identity is derived only from a successfully parsed leaf
  certificate's URI SAN — never from Common Name, DNS SAN, IP SAN, email
  SAN, subject string, issuer, or serial number.
- Exactly one eligible URI SAN is required. Zero or multiple eligible URI
  SANs fail closed (``NoEligibleUriSanError`` /
  ``MultipleEligibleUriSansError``).
- The URI SAN value is returned verbatim — never normalized, lowercased,
  rewritten, or canonicalized.
- Producer admission is exact, case-sensitive string equality only. No
  wildcard, prefix, suffix, substring, regex, or case-insensitive matching
  exists anywhere in this module.
- Malformed percent-encoding or a certificate that fails to parse fails
  closed rather than being heuristically repaired.
- Raw PEM/certificate bytes are never included in an exception message.

See also
--------
- ``basis-architecture`` ``docs/adr/0008-producer-workload-authentication-and-admission.md``
- ``basis-architecture``
  ``docs/adr/0009-trusted-producer-mtls-ingress-and-gateway-certificate-handoff.md``
- ``basis-architecture`` ``docs/architecture/producer-mtls-proxy-trust-boundary.md``
- ``src/basis_gateway/auth/operation_producer.py`` — the analogous,
  already-released legacy bearer-subject producer classification this
  module's mTLS path is additive to, never a replacement for.
"""

from __future__ import annotations

from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from enum import Enum

from cryptography import x509

__all__ = [
    "CertificateAssertionDecodingError",
    "CertificateParsingError",
    "MultipleEligibleUriSansError",
    "NoEligibleUriSanError",
    "ProducerAdmissionConfigurationError",
    "ProducerAdmissionResult",
    "ProducerAdmissionStatus",
    "ProducerCertificateError",
    "ProducerIdentityError",
    "admit_producer",
    "decode_producer_certificate_assertion",
    "derive_producer_identity",
    "parse_producer_leaf_certificate",
]

_HEX_DIGITS = frozenset("0123456789ABCDEFabcdef")

_PEM_CERTIFICATE_BEGIN_MARKER = b"-----BEGIN CERTIFICATE-----"
_PEM_CERTIFICATE_END_MARKER = b"-----END CERTIFICATE-----"
_PEM_SURROUNDING_WHITESPACE = b" \t\r\n"


class ProducerCertificateError(Exception):
    """Base class for producer-certificate identity failures.

    Callers should catch this to reject a producer certificate assertion
    outright (fail closed). Subclasses distinguish the specific failure
    category for logging/diagnostics; messages never contain raw
    certificate bytes, PEM content, or private key material.
    """


class CertificateAssertionDecodingError(ProducerCertificateError):
    """The certificate assertion value could not be strictly percent-decoded.

    Raised for malformed percent-encoding (a bare ``%`` not followed by two
    hex digits) or a non-ASCII byte in the asserted value. This is a
    transport/encoding-shape failure, distinct from a certificate that
    decodes but fails X.509 parsing (``CertificateParsingError``).
    """


class CertificateParsingError(ProducerCertificateError):
    """The decoded assertion could not be parsed as a well-formed X.509
    leaf certificate (malformed PEM structure, or PEM that decodes but does
    not parse as a valid certificate)."""


class ProducerIdentityError(ProducerCertificateError):
    """Base class for producer-identity derivation failures (SAN
    cardinality). Callers should generally catch the specific subclass
    (``NoEligibleUriSanError`` / ``MultipleEligibleUriSansError``) rather
    than this base class, since the two failure modes have different
    operational meaning."""


class NoEligibleUriSanError(ProducerIdentityError):
    """The certificate has zero eligible URI SANs.

    This includes certificates with no Subject Alternative Name extension
    at all, and certificates whose SAN extension contains only non-URI
    entries (DNS, IP, email, etc.). Common Name is never consulted as a
    fallback — a certificate with a Common Name but no URI SAN fails
    exactly the same way as a certificate with no usable identity at all.
    """


class MultipleEligibleUriSansError(ProducerIdentityError):
    """The certificate has more than one eligible URI SAN.

    ADR-0008 requires exactly one eligible URI SAN for the first mTLS
    profile; a certificate carrying more than one fails closed rather than
    guessing which URI SAN represents the producer.
    """


class ProducerAdmissionConfigurationError(ProducerCertificateError):
    """``admit_producer``'s *admitted_producer_uris* argument is not a
    proper set of exact identity strings.

    Raised, in particular, when a bare ``str`` is passed instead of a
    ``set``/``frozenset`` of strings. A ``str`` is itself an
    ``Iterable[str]`` in Python, so without this guard
    ``producer_uri in admitted_producer_uris`` would silently apply
    substring/containment semantics rather than exact-match set membership
    -- exactly the fuzzy-matching behavior ADR-0008 forbids. This is a
    fail-closed runtime check, not merely a static-typing convention: a
    caller that ignores type hints (for example, a misconfigured
    single-string environment variable passed directly) must still be
    rejected rather than silently misinterpreted.
    """


def decode_producer_certificate_assertion(assertion: str) -> bytes:
    """Strictly percent-decode a URL-escaped PEM certificate assertion.

    *assertion* is the accepted ADR-0009 internal transport representation
    of a producer leaf certificate: URL-escaped PEM, corresponding to the
    value a trusted NGINX ingress would derive from
    ``$ssl_client_escaped_cert`` (RFC 3986 percent-encoding of a standard
    PEM block). This function performs exactly one percent-decoding pass
    and returns the resulting bytes unchanged — it does not parse, inspect,
    or validate PEM/X.509 structure (that is
    ``parse_producer_leaf_certificate``'s responsibility).

    Decoding is intentionally strict, not permissive:

    - ``+`` is never reinterpreted as a space (that is
      ``application/x-www-form-urlencoded`` behavior, not RFC 3986
      percent-encoding, and nginx's ``$ssl_client_escaped_cert`` does not
      use it). ``+`` characters (common in base64 PEM bodies) pass through
      literally when not themselves percent-encoded.
    - A ``%`` not immediately followed by exactly two hex digits is
      rejected as malformed, rather than passed through or repaired.
    - A non-ASCII character anywhere in *assertion* is rejected — a
      correctly percent-encoded PEM/base64 assertion is pure ASCII.
    - No second decoding pass is performed on the result (no accidental
      double decoding).

    Raises:
        CertificateAssertionDecodingError: *assertion* contains malformed
            percent-encoding or a non-ASCII character.
    """
    decoded = bytearray()
    length = len(assertion)
    index = 0
    while index < length:
        char = assertion[index]
        if char == "%":
            if (
                index + 2 >= length
                or assertion[index + 1] not in _HEX_DIGITS
                or assertion[index + 2] not in _HEX_DIGITS
            ):
                raise CertificateAssertionDecodingError(
                    "producer certificate assertion contains malformed percent-encoding"
                )
            decoded.append(int(assertion[index + 1 : index + 3], 16))
            index += 3
            continue
        code_point = ord(char)
        if code_point > 0x7F:
            raise CertificateAssertionDecodingError(
                "producer certificate assertion contains a non-ASCII character"
            )
        decoded.append(code_point)
        index += 1
    return bytes(decoded)


def _require_single_pem_certificate_block(pem_bytes: bytes) -> None:
    """Fail closed unless *pem_bytes* contains exactly one PEM ``CERTIFICATE``
    block with no other data before or after it.

    ``cryptography.x509.load_pem_x509_certificate`` is structurally
    permissive: it happily parses the *first* certificate block it finds
    and silently ignores a second concatenated certificate, leading junk,
    or trailing junk. ADR-0009's certificate-handoff contract is exactly one
    leaf-certificate PEM assertion, so this repository's own boundary must
    enforce that shape itself rather than relying on the underlying
    library's leniency. Only structural marker/whitespace checks are
    performed here -- no ASN.1 parsing, no PEM repair.
    """
    begin_count = pem_bytes.count(_PEM_CERTIFICATE_BEGIN_MARKER)
    end_count = pem_bytes.count(_PEM_CERTIFICATE_END_MARKER)
    if begin_count != 1 or end_count != 1:
        raise CertificateParsingError(
            "producer certificate assertion must contain exactly one PEM CERTIFICATE block"
        )

    begin_index = pem_bytes.index(_PEM_CERTIFICATE_BEGIN_MARKER)
    end_index = pem_bytes.index(_PEM_CERTIFICATE_END_MARKER) + len(_PEM_CERTIFICATE_END_MARKER)
    leading = pem_bytes[:begin_index]
    trailing = pem_bytes[end_index:]
    if leading.strip(_PEM_SURROUNDING_WHITESPACE) or trailing.strip(_PEM_SURROUNDING_WHITESPACE):
        raise CertificateParsingError(
            "producer certificate assertion must not contain data before or "
            "after the single PEM CERTIFICATE block"
        )


def parse_producer_leaf_certificate(pem_bytes: bytes) -> x509.Certificate:
    """Parse decoded PEM bytes as exactly one X.509 leaf certificate.

    Structural parsing only. This function does not perform, and must
    never be extended to perform: CA-chain verification, trust-anchor
    evaluation, expiration validation, CRL processing, OCSP, or certificate
    path building. Under ADR-0009, those TLS-authentication responsibilities
    belong to the trusted NGINX ingress; the gateway receives an already
    (TLS-layer) authenticated leaf certificate and owns only identity
    derivation from it (this module's ``derive_producer_identity``).

    Before invoking ``cryptography``'s parser, this function requires
    *pem_bytes* to contain exactly one PEM ``CERTIFICATE`` block with no
    non-whitespace data before or after it -- ``load_pem_x509_certificate``
    on its own would otherwise silently accept a second concatenated
    certificate, leading junk, or trailing junk by parsing only the first
    block it finds.

    Raises:
        CertificateParsingError: *pem_bytes* does not contain exactly one
            PEM ``CERTIFICATE`` block bounded only by whitespace, or the
            single block is not a well-formed, parseable X.509 leaf
            certificate. The original ``cryptography``/``ValueError``
            message is not included, since it may echo fragments of the
            malformed input.
    """
    _require_single_pem_certificate_block(pem_bytes)
    try:
        return x509.load_pem_x509_certificate(pem_bytes)
    except (ValueError, TypeError) as exc:
        raise CertificateParsingError(
            "producer certificate assertion could not be parsed as a valid X.509 leaf certificate"
        ) from exc


def derive_producer_identity(certificate: x509.Certificate) -> str:
    """Derive the producer workload identity from *certificate*'s URI SAN.

    Per ADR-0008's "Certificate identity profile": the producer workload
    identity is the certificate's URI Subject Alternative Name, taken
    verbatim, and only when exactly one eligible URI SAN is present.
    Common Name is never consulted, not even as a diagnostic substitute.
    Non-URI SAN entries (DNS, IP, email) are ignored for cardinality
    purposes — a certificate with one URI SAN plus any number of other SAN
    types still satisfies the exactly-one rule.

    Raises:
        NoEligibleUriSanError: *certificate* has no Subject Alternative
            Name extension, or its SAN extension contains zero URI entries.
        MultipleEligibleUriSansError: *certificate* has more than one URI
            SAN entry.
    """
    try:
        san_extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound as exc:
        raise NoEligibleUriSanError(
            "producer certificate has no Subject Alternative Name extension"
        ) from exc

    uri_sans: list[str] = san_extension.value.get_values_for_type(x509.UniformResourceIdentifier)

    if len(uri_sans) == 0:
        raise NoEligibleUriSanError("producer certificate has zero eligible URI SAN entries")
    if len(uri_sans) > 1:
        raise MultipleEligibleUriSansError(
            "producer certificate has more than one eligible URI SAN entry"
        )
    return uri_sans[0]


class ProducerAdmissionStatus(str, Enum):
    """Whether a derived producer URI SAN identity is admitted."""

    ADMITTED = "admitted"
    NOT_ADMITTED = "not_admitted"


@dataclass(frozen=True, slots=True)
class ProducerAdmissionResult:
    """Immutable result of an exact-match producer admission check.

    ``producer_uri`` is always populated, whether or not admission
    succeeded — consistent with
    ``producer-mtls-proxy-trust-boundary.md`` §11's own logging guidance
    that the derived URI SAN is "a non-secret, deployment-registered
    identity value per ADR-0008" safe to include in diagnostics, unlike raw
    certificate/PEM content, which this module never logs or includes in
    any message.
    """

    status: ProducerAdmissionStatus
    producer_uri: str


def admit_producer(
    producer_uri: str,
    admitted_producer_uris: AbstractSet[str],
) -> ProducerAdmissionResult:
    """Perform exact, case-sensitive producer admission matching.

    Per ADR-0008's "Exact admission matching": *producer_uri* (already
    derived verbatim by ``derive_producer_identity``) is admitted only when
    it exactly, case-sensitively equals an entry in
    *admitted_producer_uris*. No wildcard, prefix, suffix, substring,
    regular-expression, or case-insensitive matching is performed —
    neither side of the comparison is normalized, canonicalized, or
    case-folded.

    *admitted_producer_uris* must be a genuine set of exact identity
    strings (``set[str]``/``frozenset[str]``), never a bare ``str``. This is
    enforced at runtime (``ProducerAdmissionConfigurationError``), not only
    via the ``AbstractSet[str]`` type hint: a ``str`` is itself iterable and
    supports Python's ``in`` operator with *substring* semantics, so an
    accidentally scalar-string argument would otherwise silently turn exact
    membership matching into substring matching -- precisely the fuzzy
    admission behavior ADR-0008 forbids.

    Args:
        producer_uri: The URI SAN identity derived from a validated
            producer certificate. Never mutated.
        admitted_producer_uris: The deployment-configured set of admitted
            producer identities (exact strings). Never mutated. An empty
            set means no producer is ever admitted — the same
            safe-default-empty discipline
            ``OPERATION_PRODUCER_SUBJECT_IDS``/``classify_operation_producer``
            already establish for the legacy bearer-subject path.

    Returns:
        A ``ProducerAdmissionResult`` carrying ``ADMITTED`` when
        *producer_uri* is present in *admitted_producer_uris* by exact
        string equality, ``NOT_ADMITTED`` otherwise (including when
        *admitted_producer_uris* is empty).

    Raises:
        ProducerAdmissionConfigurationError: *admitted_producer_uris* is a
            bare ``str`` rather than a set of strings.
    """
    if isinstance(admitted_producer_uris, str):
        raise ProducerAdmissionConfigurationError(
            "admitted_producer_uris must be a set of exact producer identity "
            "strings, not a single str"
        )
    if producer_uri in admitted_producer_uris:
        return ProducerAdmissionResult(
            status=ProducerAdmissionStatus.ADMITTED,
            producer_uri=producer_uri,
        )
    return ProducerAdmissionResult(
        status=ProducerAdmissionStatus.NOT_ADMITTED,
        producer_uri=producer_uri,
    )
