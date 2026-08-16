"""Live mTLS operation-producer trust resolution for basis-gateway.

Phase 1B.3 of the bounded operation-producer reference implementation
(``basis-architecture`` ADR-0008 "Producer Workload Authentication and
Gateway Admission" and ADR-0009 "Trusted Producer mTLS Ingress and Gateway
Certificate Handoff"). Phase 1B.1 (``auth/producer_mtls.py``) proved
certificate identity semantics operating on an already-supplied assertion
value. Phase 1B.2 (``auth/producer_mtls_trusted_proxy.py``) proved that the
value reaching those primitives actually came from the ADR-0009 trust
boundary. This module is the small orchestration layer Phase 1B.3 adds to
connect those two proven foundations into a live, request-scoped
``OperationProducerTrust`` classification — and to select, per request,
between that mTLS path and the existing legacy bearer-subject-allowlist path
(``classify_operation_producer``), with no fallback between them within a
single request.

This module does not duplicate certificate parsing, header retrieval, or
admission matching — every one of those steps is imported from Phase 1B.1/
1B.2 unchanged. It also does not authenticate the bearer subject (unchanged,
``auth/runtime.py``) and does not compose the operation-aware kernel request
(unchanged, ``core/operation_aware_composition.py``).

Pipeline this module composes
------------------------------
::

    retrieve_trusted_producer_certificate_assertion()   (Phase 1B.2)
        -> decode_producer_certificate_assertion()       (Phase 1B.1)
        -> parse_producer_leaf_certificate()              (Phase 1B.1)
        -> derive_producer_identity()                     (Phase 1B.1)
        -> admit_producer()                                (Phase 1B.1)
        -> OperationProducerTrust                          (this module)

Failure-layer behavior (see ``docs/implementation/producer-mtls-phase-1b3.md``
for the full specification, and ``basis-architecture``'s merged
``producer-mtls-proxy-trust-boundary.md`` §11/§17/§18/§19 item 17 and
Appendix B for the authoritative architecture this module implements):

- **Missing assertion** (trusted-proxy mode enabled, no
  ``X-BASIS-Producer-Client-Cert`` header present): *is* an exception —
  ``MissingProducerCertificateAssertionError``. Per the merged architecture's
  §11 "Missing-value behavior" and §18 Layer 2, absence of the internal
  certificate assertion on a request that has already reached
  ``basis-gateway`` through the trusted-proxy listener is a **Layer-2
  proxy/backend trust-boundary failure** — evidence that the trusted-proxy
  boundary itself did not hold (misconfiguration, an unexpected request
  path, or same-host socket access outside the intended process), not an
  ordinary "no producer certificate presented" condition. This module
  constructs **no** ``OperationProducerTrust`` for that case: it does not
  return an ``UNTRUSTED`` result, does not fall back to the
  ``OPERATION_PRODUCER_SUBJECT_IDS`` legacy allowlist, and does not permit
  the request to proceed as an ordinary bearer-only caller — the caller
  (the live route) must catch this exception, reject the request before any
  kernel evaluation, and never construct an ``OperationProducerTrust`` from
  a partial result. This is deliberately different from the genuine "no
  producer certificate presented" condition, which happens at Layer 1,
  entirely outside the gateway (a producer that supplies no TLS client
  certificate to NGINX is rejected at the TLS handshake; ``basis-gateway``
  is never reached for that case).
- **Duplicate assertion, oversized assertion, malformed percent-encoding,
  malformed X.509, zero eligible URI SANs, multiple eligible URI SANs**:
  every one of these *is* an exception (propagated unchanged from Phase
  1B.2/1B.1) — the caller (the live route) must catch it, reject the request
  before any kernel evaluation, and never construct an
  ``OperationProducerTrust`` for that request.
- **Structurally valid certificate, URI SAN not admitted**: not an
  exception. Returns ``UNTRUSTED`` / ``MTLS_URI_SAN_NOT_ADMITTED``, carrying
  the derived (non-secret) URI SAN in ``producer_workload_identity`` for
  diagnostics. This is a Layer-4 admission outcome, not a trust-boundary
  failure: the trusted-proxy boundary worked correctly and produced a
  genuine, parseable certificate identity the deployment simply has not
  admitted. The caller may proceed as an ordinary caller, subject to the
  existing producer-owned-context rejection.
- **Structurally valid certificate, URI SAN admitted**: returns ``TRUSTED``
  / ``MTLS_ADMITTED_URI_SAN``.

No fallback to the legacy allowlist
-------------------------------------
``resolve_operation_producer_trust`` — the mode-selecting entry point this
module exposes — never consults ``OPERATION_PRODUCER_SUBJECT_IDS`` when
trusted-proxy mode is enabled, in either branch above. A bearer subject that
happens to also be present in the legacy allowlist gains no advantage from
that fact while trusted-proxy mode is on for that request; conversely, an
admitted mTLS producer's URI SAN is never checked against, or required to
appear in, the legacy allowlist. The two mechanisms are fully independent
per ADR-0008's "Existing allowlist transition".
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from basis_gateway.auth.operation_producer import (
    OperationProducerTrust,
    OperationProducerTrustSource,
    OperationProducerTrustStatus,
    classify_operation_producer,
)
from basis_gateway.auth.producer_mtls import (
    ProducerAdmissionStatus,
    ProducerCertificateError,
    admit_producer,
    decode_producer_certificate_assertion,
    derive_producer_identity,
    parse_producer_leaf_certificate,
)
from basis_gateway.auth.producer_mtls_trusted_proxy import (
    TrustedProxyAssertionError,
    retrieve_trusted_producer_certificate_assertion,
)

if TYPE_CHECKING:
    from collections.abc import Set as AbstractSet

    from starlette.requests import Request

    from basis_gateway.auth.subject_mapper import NormalizedSubject
    from basis_gateway.config import GatewayConfig

__all__ = [
    "MissingProducerCertificateAssertionError",
    "ProducerCertificateError",
    "TrustedProxyAssertionError",
    "resolve_mtls_operation_producer_trust",
    "resolve_operation_producer_trust",
]


class MissingProducerCertificateAssertionError(TrustedProxyAssertionError):
    """Trusted-proxy producer certificate assertion required but absent.

    Raised only by this module (never by
    ``producer_mtls_trusted_proxy.retrieve_trusted_producer_certificate_assertion``,
    which still returns ``None`` for absence — a low-level shape/retrieval
    fact, not an endpoint-level policy decision). This module's live,
    mode-aware resolver is the layer that knows a given request is actually
    operating under live trusted-proxy mTLS semantics, and therefore that a
    ``None`` retrieval result is fatal for that request.

    A subtype of ``TrustedProxyAssertionError`` (the same Phase 1B.2 base
    class ``DuplicateProducerCertificateAssertionError`` and
    ``OversizedProducerCertificateAssertionError`` already use), so every
    Layer-2 trusted-proxy assertion failure — missing, duplicated, or
    oversized — is conceptually related and catchable together. Per the
    merged ``producer-mtls-proxy-trust-boundary.md`` §11/§18, this is a
    Layer-2 proxy/backend trust-boundary failure: callers must fail the
    request closed, never construct an ``OperationProducerTrust`` for it,
    never fall back to the legacy ``OPERATION_PRODUCER_SUBJECT_IDS``
    allowlist, and never invoke ``basis-core``.

    The exception message never contains certificate data, header values,
    bearer tokens, or request bodies — only a fixed, generic description of
    the failure category, consistent with every other exception in this
    module's dependency chain.
    """


def resolve_mtls_operation_producer_trust(
    request: Request,
    *,
    subject: NormalizedSubject,
    admitted_producer_uris: AbstractSet[str],
) -> OperationProducerTrust:
    """Resolve producer trust via the ADR-0009 trusted-proxy mTLS pipeline.

    Callers must invoke this function only when trusted-proxy mTLS mode is
    actually enabled for the current deployment
    (``GatewayConfig.operation_producer_mtls_trusted_proxy_enabled``) — this
    function does not itself take an enablement flag; it always retrieves
    the internal certificate header with
    ``trusted_proxy_enabled=True``, so calling it while the deployment
    intends legacy-only behavior would incorrectly start inspecting a
    header that mode is supposed to ignore entirely. The live route
    (``api.routes.evaluate_operation_aware``, via
    ``resolve_operation_producer_trust`` below) is the sole intended caller
    and upholds this precondition by construction.

    Reuses Phase 1B.1 (``auth.producer_mtls``) and Phase 1B.2
    (``auth.producer_mtls_trusted_proxy``) directly — no certificate
    parsing, header retrieval, or admission-matching logic is duplicated
    here.

    Args:
        request: The current Starlette/FastAPI request. Only its headers
            are read (via ``retrieve_trusted_producer_certificate_assertion``).
        subject: The already bearer-authenticated caller. Never mutated;
            used only to populate ``authorization_subject_id`` on the
            returned result, exactly as the legacy classifier does.
        admitted_producer_uris: The deployment-configured exact-match
            admission set (``GatewayConfig.operation_producer_mtls_admitted_uris``).
            Never mutated.

    Returns:
        An ``OperationProducerTrust`` for the "not admitted"
        (``MTLS_URI_SAN_NOT_ADMITTED``) and "admitted"
        (``MTLS_ADMITTED_URI_SAN``) outcomes only — see this module's
        docstring for the full behavior table. There is no returned result
        for a missing assertion; see ``Raises`` below.

    Raises:
        MissingProducerCertificateAssertionError: no
            ``X-BASIS-Producer-Client-Cert`` assertion was present on this
            request. A Layer-2 proxy/backend trust-boundary failure per the
            merged ``producer-mtls-proxy-trust-boundary.md`` §11/§18 — not
            an ordinary producer-trust outcome. No ``OperationProducerTrust``
            is constructed for this case.
        basis_gateway.auth.producer_mtls_trusted_proxy.DuplicateProducerCertificateAssertionError:
            more than one occurrence of the internal certificate header was
            present.
        basis_gateway.auth.producer_mtls_trusted_proxy.OversizedProducerCertificateAssertionError:
            the header's value exceeded the accepted size bound.
        basis_gateway.auth.producer_mtls.CertificateAssertionDecodingError:
            the header's value could not be strictly percent-decoded.
        basis_gateway.auth.producer_mtls.CertificateParsingError:
            the decoded value was not exactly one well-formed PEM/X.509
            leaf certificate.
        basis_gateway.auth.producer_mtls.NoEligibleUriSanError:
            the certificate has zero eligible URI SANs.
        basis_gateway.auth.producer_mtls.MultipleEligibleUriSansError:
            the certificate has more than one eligible URI SAN.

    Every exception above is a fail-closed boundary failure: callers must
    reject the request before any kernel evaluation and must never
    construct an ``OperationProducerTrust`` for that request from a partial
    result.
    """
    assertion = retrieve_trusted_producer_certificate_assertion(request, trusted_proxy_enabled=True)

    if assertion is None:
        # Per the merged producer-mtls-proxy-trust-boundary.md §11/§18: once
        # a request has reached basis-gateway through the trusted-proxy
        # listener, the internal certificate assertion is mandatory. Its
        # absence means a trusted-topology assumption failed (NGINX
        # misconfiguration, a request that did not traverse the intended
        # ingress, or a same-host process reaching the Unix socket
        # directly) -- not that the producer chose to omit a certificate.
        # This is a Layer-2 trust-boundary failure, not an ordinary
        # producer-trust outcome: no OperationProducerTrust is constructed,
        # there is no fallback to OPERATION_PRODUCER_SUBJECT_IDS, and the
        # caller must not treat this request as an ordinary bearer-only
        # caller. The exception message is a fixed, generic description --
        # never certificate data, header values, bearer tokens, or request
        # bodies.
        raise MissingProducerCertificateAssertionError(
            "a trusted-proxy producer certificate assertion is required but was not "
            "present on this request"
        )

    # Any exception from this point propagates unchanged to the caller —
    # Layer 2 (decoding-shape) and Layer 3 (certificate-identity-derivation)
    # failures must fail closed before any OperationProducerTrust is
    # constructed at all (see this module's docstring).
    pem_bytes = decode_producer_certificate_assertion(assertion)
    certificate = parse_producer_leaf_certificate(pem_bytes)
    producer_uri = derive_producer_identity(certificate)

    admission = admit_producer(producer_uri, admitted_producer_uris)
    if admission.status is ProducerAdmissionStatus.ADMITTED:
        return OperationProducerTrust(
            status=OperationProducerTrustStatus.TRUSTED,
            source=OperationProducerTrustSource.MTLS_ADMITTED_URI_SAN,
            authorization_subject_id=subject.subject_id,
            operation_producer_subject_id=None,
            producer_workload_identity=producer_uri,
        )
    return OperationProducerTrust(
        status=OperationProducerTrustStatus.UNTRUSTED,
        source=OperationProducerTrustSource.MTLS_URI_SAN_NOT_ADMITTED,
        authorization_subject_id=subject.subject_id,
        operation_producer_subject_id=None,
        producer_workload_identity=producer_uri,
    )


def resolve_operation_producer_trust(
    request: Request,
    *,
    subject: NormalizedSubject,
    config: GatewayConfig,
) -> OperationProducerTrust:
    """Mode-selecting producer-trust entry point for the live operation-aware route.

    When ``config.operation_producer_mtls_trusted_proxy_enabled`` is
    ``True``, producer trust is established *exclusively* via
    ``resolve_mtls_operation_producer_trust`` above —
    ``config.operation_producer_subject_ids`` is never read and
    ``classify_operation_producer`` is never called in that branch, so a
    bearer subject present in the legacy allowlist gains no advantage
    within a trusted-proxy-mode request (ADR-0008 "Existing allowlist
    transition"; no fallback).

    When trusted-proxy mode is disabled (the default), this function
    delegates to the unchanged, existing
    ``classify_operation_producer(subject, config.operation_producer_subject_ids)``
    — the private certificate header, if present at all (an ordinary
    caller-controlled value in this mode — see
    ``producer_mtls_trusted_proxy``'s own module docstring), is never
    inspected.

    Raises:
        Every exception ``resolve_mtls_operation_producer_trust`` may raise,
        propagated unchanged, only when trusted-proxy mode is enabled.
        ``classify_operation_producer`` never raises.
    """
    if config.operation_producer_mtls_trusted_proxy_enabled:
        return resolve_mtls_operation_producer_trust(
            request,
            subject=subject,
            admitted_producer_uris=config.operation_producer_mtls_admitted_uris,
        )
    return classify_operation_producer(subject, config.operation_producer_subject_ids)
