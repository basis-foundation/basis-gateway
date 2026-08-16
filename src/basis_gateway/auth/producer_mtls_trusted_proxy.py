"""Trusted-proxy internal certificate-assertion retrieval boundary.

Phase 1B.2 of the bounded operation-producer reference implementation
(``basis-architecture`` ADR-0008 "Producer Workload Authentication and
Gateway Admission" and ADR-0009 "Trusted Producer mTLS Ingress and Gateway
Certificate Handoff"). Phase 1B.1
(``src/basis_gateway/auth/producer_mtls.py``) proved certificate identity
semantics — strict URL-escaped PEM decoding, X.509 parsing, exactly-one-URI-SAN
derivation, and exact admission — operating entirely on an already-supplied
certificate assertion *value*. This module proves the other half: that the
value reaching those primitives actually came from the trust boundary
ADR-0009 requires, not from an arbitrary caller-controlled HTTP header.

What this module is
--------------------
A narrowly scoped retrieval primitive for the private, ingress-to-gateway
transport header ``X-BASIS-Producer-Client-Cert``
(``producer-mtls-proxy-trust-boundary.md`` §11). It answers exactly one
question: *did a trusted-proxy-shaped certificate assertion arrive on this
request, and if so, what is its raw (still percent-encoded) value?*

What this module is not
------------------------
This module does **not** perform X.509 parsing, URI SAN derivation, or
producer admission (Phase 1B.1 owns all of that — see
``basis_gateway.auth.producer_mtls``). It does **not** itself perform
``OperationProducerTrust`` classification and does **not** decide whether a
missing assertion is fatal — Phase 1B.3 (``auth/operation_producer_mtls.py``)
composes this module's retrieval primitive with Phase 1B.1's pipeline to
build a live classification, and is the sole caller reachable from
``POST /v1/evaluate/operation-aware``; this module's own function signature
is unchanged since Phase 1B.2 and still does not accept or return an
``OperationProducerTrust``. This module's retrieval primitive still returns
``None`` for absence — it is a low-level shape/retrieval primitive whose
only responsibility is to report *whether an internal assertion was
present*; Phase 1B.3's live trusted-proxy resolver is the layer that treats
that absence as a fail-closed Layer-2 trust-boundary failure (see
``basis_gateway.auth.operation_producer_mtls.MissingProducerCertificateAssertionError``)
when live trusted-proxy mode is actually in effect for a request — a policy
decision this module deliberately does not make, since it has no visibility
into endpoint-level semantics. It does **not** validate
that the deployment is actually running behind the ADR-0009 NGINX ingress — that is a topology fact
this module cannot observe from within the ASGI application; it only
prevents an *ordinary* caller-controlled header from being treated as a
producer certificate assertion when trusted-proxy mode is enabled, per the
critical trust principle documented in
``GatewayConfig.operation_producer_mtls_trusted_proxy_enabled``: the header
name alone never creates trust — trust is a fact about the topology
(NGINX's unconditional ``proxy_set_header`` overwrite, plus the protected
Unix-domain-socket backend channel), not this module's code.

Trust-boundary invariants this module enforces
-----------------------------------------------
- When trusted-proxy mode is disabled, the header is never inspected at
  all — no lookup, no parsing trigger, no new behavior for ordinary TCP
  deployments.
- When trusted-proxy mode is enabled and the header is absent, this
  function returns ``None`` — no producer certificate assertion exists for
  this request, as far as this retrieval primitive is concerned. This
  function does **not** itself reject the request: whether that absence is
  fatal is an endpoint-level, live trusted-proxy-mode decision this module
  does not make. As of Phase 1B.3, the live resolver that calls this
  function (``basis_gateway.auth.operation_producer_mtls``) treats a
  ``None`` return as a fail-closed Layer-2 trust-boundary failure — it
  raises ``MissingProducerCertificateAssertionError`` rather than
  proceeding as an ordinary bearer-only caller — per the merged
  ``producer-mtls-proxy-trust-boundary.md`` §11/§18. This module's own
  return value and behavior are unchanged from Phase 1B.2; only the live
  caller's interpretation of ``None`` changed in Phase 1B.3.
- When trusted-proxy mode is enabled and the header appears more than once
  (case-insensitively by header name), the assertion is malformed and
  retrieval fails closed — this module never applies first-occurrence-wins,
  last-occurrence-wins, or comma-joining semantics.
- When trusted-proxy mode is enabled and the header's value exceeds
  ``MAX_ASSERTION_SIZE_BYTES``, retrieval fails closed before any decoding
  or X.509 parsing is attempted.
- The raw assertion value is never included in an exception message or log
  call anywhere in this module.

See also
--------
- ``basis-architecture``
  ``docs/architecture/producer-mtls-proxy-trust-boundary.md`` §9-§11, §15,
  §18 (Layer 2)
- ``src/basis_gateway/auth/producer_mtls.py`` — Phase 1B.1, the certificate
  identity pipeline this module's retrieved value is intended to feed
  (composition is the caller's responsibility; see
  ``docs/implementation/producer-mtls-phase-1b2.md`` for an example).
- ``docs/implementation/producer-mtls-phase-1b2.md``
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.requests import Request

__all__ = [
    "MAX_ASSERTION_SIZE_BYTES",
    "PRODUCER_CLIENT_CERT_HEADER_NAME",
    "DuplicateProducerCertificateAssertionError",
    "OversizedProducerCertificateAssertionError",
    "TrustedProxyAssertionError",
    "retrieve_trusted_producer_certificate_assertion",
]

# The private, ingress-to-gateway transport header ADR-0009 §11 defines.
# HTTP header-name comparison is case-insensitive.
PRODUCER_CLIENT_CERT_HEADER_NAME = "X-BASIS-Producer-Client-Cert"

_HEADER_NAME_LOWER = PRODUCER_CLIENT_CERT_HEADER_NAME.lower().encode("latin-1")

# 16 KiB, per producer-mtls-proxy-trust-boundary.md §11: "a generous bound
# such as 16 KB comfortably covers realistic certificate sizes including
# reasonable extension data without inviting a header-size denial-of-service
# surface." This bounds the *encoded* (still percent-escaped) header value,
# checked before any percent-decoding or X.509 parsing is attempted.
MAX_ASSERTION_SIZE_BYTES = 16 * 1024


class TrustedProxyAssertionError(Exception):
    """Base class for trusted-proxy certificate-assertion retrieval failures.

    Callers should treat any instance of this exception as "no trustworthy
    producer certificate assertion is available for this request" and fail
    closed (no producer admission). Messages never contain the raw header
    value.
    """


class DuplicateProducerCertificateAssertionError(TrustedProxyAssertionError):
    """More than one occurrence of the reserved internal certificate header
    was present on the request (case-insensitive by header name).

    This is a defense-in-depth check. In the ADR-0009 reference topology,
    the trusted NGINX ingress writes exactly one occurrence
    (``proxy_set_header`` overwrites rather than appends); this module does
    not assume the proxy is the only thing that could ever write to a
    channel it trusts (a same-host process with socket access is an
    accepted residual risk — see
    ``producer-mtls-proxy-trust-boundary.md`` §9, §19 item 3) and validates
    shape rather than assuming it. No first-occurrence-wins,
    last-occurrence-wins, or comma-joining fallback exists.
    """


class OversizedProducerCertificateAssertionError(TrustedProxyAssertionError):
    """The reserved internal certificate header's value exceeded
    ``MAX_ASSERTION_SIZE_BYTES``.

    Raised before any percent-decoding or X.509 parsing is attempted, to
    bound header-size denial-of-service exposure at this boundary
    specifically (this is not a general HTTP-header-size framework).
    """


def retrieve_trusted_producer_certificate_assertion(
    request: Request,
    *,
    trusted_proxy_enabled: bool,
) -> str | None:
    """Retrieve the raw (still percent-encoded) producer certificate
    assertion from *request*, if trusted-proxy mode is enabled and exactly
    one well-shaped occurrence is present.

    This function does **not** decode, parse, or otherwise interpret the
    returned value — pass it unchanged to
    ``basis_gateway.auth.producer_mtls.decode_producer_certificate_assertion``
    for that. It performs shape validation only: presence, cardinality, and
    size.

    Args:
        request: The current Starlette/FastAPI request. Only
            ``request.headers`` is read; nothing else about the request is
            inspected.
        trusted_proxy_enabled: The deployment's
            ``GatewayConfig.operation_producer_mtls_trusted_proxy_enabled``
            value, passed explicitly by the caller rather than read from
            global state, so this function's behavior is fully determined
            by its arguments.

    Returns:
        ``None`` when trusted-proxy mode is disabled (the header, if
        present, is never inspected — see this module's docstring), or when
        trusted-proxy mode is enabled but the header is absent (no producer
        certificate assertion exists for this request, as far as this
        retrieval primitive is concerned; this function does not by itself
        reject the request — see this module's docstring for how Phase
        1B.3's live resolver treats that ``None`` as fail-closed when
        trusted-proxy mode is actually in effect). Otherwise the single
        header value, unchanged and still percent-encoded.

    Raises:
        DuplicateProducerCertificateAssertionError: trusted-proxy mode is
            enabled and the header appears more than once
            (case-insensitively by header name).
        OversizedProducerCertificateAssertionError: trusted-proxy mode is
            enabled, exactly one occurrence is present, and its value
            exceeds ``MAX_ASSERTION_SIZE_BYTES``.
    """
    if not trusted_proxy_enabled:
        return None

    # Deliberately reads the RAW ASGI header list (``Headers.raw``, a
    # public/documented Starlette attribute — a list of ``(bytes, bytes)``
    # tuples reflecting scope["headers"] exactly, with every occurrence
    # preserved and none collapsed or comma-joined) and performs the
    # case-insensitive name comparison here explicitly, rather than relying
    # on ``Headers.getlist``. ``Headers.getlist`` only lowercases the
    # *lookup key*, not each stored raw name — the ASGI specification
    # requires a compliant server to deliver already-lowercased header
    # names, which real servers (Uvicorn) honor, but this module does not
    # assume that guarantee is the only thing standing between it and a
    # missed duplicate. Comparing every raw occurrence's name
    # case-insensitively here means duplicate detection is correct even if
    # that assumption is ever violated.
    matches = [value for name, value in request.headers.raw if name.lower() == _HEADER_NAME_LOWER]

    if len(matches) == 0:
        return None

    if len(matches) > 1:
        raise DuplicateProducerCertificateAssertionError(
            f"more than one occurrence of the {PRODUCER_CLIENT_CERT_HEADER_NAME!r} "
            f"header was present on the request ({len(matches)} occurrences); "
            "this is treated as a malformed assertion and rejected"
        )

    raw_value = matches[0]

    if len(raw_value) > MAX_ASSERTION_SIZE_BYTES:
        raise OversizedProducerCertificateAssertionError(
            f"the {PRODUCER_CLIENT_CERT_HEADER_NAME!r} header value exceeds the "
            f"maximum accepted size of {MAX_ASSERTION_SIZE_BYTES} bytes"
        )

    # HTTP header values are transmitted as a single byte per character
    # (RFC 9110); latin-1 is the byte-preserving decode Starlette itself
    # uses for header values, so this is a lossless, exact round trip back
    # to a str for Phase 1B.1's decode_producer_certificate_assertion.
    return raw_value.decode("latin-1")
