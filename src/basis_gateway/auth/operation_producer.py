"""Operation-producer trust classification for basis-gateway.

Part of the operation-aware gateway integration
(``docs/implementation/operation-aware-gateway-integration-plan.md``, §5a,
§7, §16 PR 4). This module answers exactly one question, for exactly one
already-authenticated caller: *is this caller also a trusted operation
producer?*

Authorization subject vs. operation producer
----------------------------------------------
The **authorization subject** is the human, service, or workload whose
authority is being evaluated — established by Bearer-token authentication,
unchanged and untouched by this module (``auth/subject_mapper.py``,
``auth/runtime.py``).

The **operation producer** is a narrower, separate concept: the adapter,
gateway integration, or trusted service permitted to assert
operation-producer-only context (location, device, protocol evidence,
operation intent, safety/environment/risk context, identity/adapter evidence
references). An authenticated subject is *not* automatically an operation
producer. This module classifies that narrower fact, from configuration
checked against the already-verified subject — never from anything the
caller supplies in a request body, header, or claim structure the caller
controls.

Safe default
-------------
With no ``OPERATION_PRODUCER_SUBJECT_IDS`` configured, **no caller is a
trusted operation producer**. This is the load-bearing safety property this
module exists to enforce: absence of configuration must never be
interpreted as implicit trust.

What this module never does
-----------------------------
- Never infers trust from request-body fields, operation-aware context
  values, action/resource, network source, or any caller-provided claim of
  producer status.
- Never falls back to role membership, attribute values, or any mechanism
  other than the configured exact subject-ID allowlist.
- Never performs wildcard, prefix, or case-insensitive matching.
- Never mutates the ``NormalizedSubject`` or the configured allowlist it is
  given.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from enum import Enum

from basis_gateway.auth.subject_mapper import NormalizedSubject

__all__ = [
    "OperationProducerTrust",
    "OperationProducerTrustSource",
    "OperationProducerTrustStatus",
    "classify_operation_producer",
]


class OperationProducerTrustStatus(str, Enum):
    """Whether the authenticated caller is classified as an operation producer."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class OperationProducerTrustSource(str, Enum):
    """Why a given ``OperationProducerTrustStatus`` was reached.

    A closed vocabulary so the classification is fully auditable: every
    reachable classification path has a distinct, named source.

    The two ``MTLS_*`` members below are additive, Phase 1B.3 members
    (``basis-architecture`` ADR-0008/ADR-0009 — see
    ``basis_gateway.auth.operation_producer_mtls``). They are reached only
    when ``GatewayConfig.operation_producer_mtls_trusted_proxy_enabled`` is
    ``True``; the three original members above remain the exhaustive
    vocabulary for the unchanged legacy bearer-subject-allowlist path.
    Trust reached through one family is never reported using a source name
    from the other family — the two mechanisms are fully distinguishable
    from ``source`` alone.

    There is deliberately no third ``MTLS_*`` member representing a missing
    certificate assertion. Per the merged
    ``producer-mtls-proxy-trust-boundary.md`` §11/§18 ("Missing-value
    behavior" / Layer 2), a trusted-proxy-mode request that reaches
    ``basis-gateway`` without ``X-BASIS-Producer-Client-Cert`` is a Layer-2
    proxy/backend trust-boundary failure, not an ordinary producer-trust
    outcome — ``basis_gateway.auth.operation_producer_mtls`` raises a
    dedicated exception for that case instead of constructing an
    ``OperationProducerTrust`` at all. A previous revision of this
    vocabulary carried an ``MTLS_ASSERTION_ABSENT`` member for that case;
    it has been removed because it is no longer architecturally
    representable.
    """

    CONFIGURED_SUBJECT_ID_ALLOWLIST = "configured_subject_id_allowlist"
    NOT_CONFIGURED = "not_configured"
    SUBJECT_ID_NOT_ALLOWED = "subject_id_not_allowed"

    #: Trusted-proxy mTLS mode is enabled; a valid producer certificate
    #: assertion was retrieved, decoded, parsed, and yielded exactly one URI
    #: SAN that exactly matches an entry in
    #: ``GatewayConfig.operation_producer_mtls_admitted_uris``.
    MTLS_ADMITTED_URI_SAN = "mtls_admitted_uri_san"

    #: Trusted-proxy mTLS mode is enabled; a valid producer certificate
    #: assertion yielded exactly one, structurally valid URI SAN, but that
    #: URI is not present in (or is not enabled in) the admitted-identity
    #: configuration. Distinct from a malformed/absent assertion — the
    #: certificate identity was successfully derived; it simply is not an
    #: admitted producer.
    MTLS_URI_SAN_NOT_ADMITTED = "mtls_uri_san_not_admitted"


@dataclass(frozen=True, slots=True)
class OperationProducerTrust:
    """Immutable result of classifying an authenticated caller as a producer.

    Keeps ``authorization_subject_id`` (the authenticated caller — always
    present) and ``operation_producer_subject_id`` (the same value, but only
    when the caller is trusted through the legacy bearer-subject-allowlist
    mechanism; otherwise ``None``) as separate fields. The two are equal
    when ``source`` is ``CONFIGURED_SUBJECT_ID_ALLOWLIST``, but that equality
    is an implementation detail of that specific transport, not a statement
    that the two concepts are the same fact — see this module's docstring.

    ``producer_workload_identity`` (Phase 1B.3, additive) carries the mTLS
    producer's certificate-derived URI SAN when ``source`` is one of the
    ``MTLS_*`` members above (``None`` on the legacy path). There is no
    ``OperationProducerTrust`` for a missing certificate assertion at all —
    that case raises a dedicated exception before construction (see
    ``basis_gateway.auth.operation_producer_mtls.MissingProducerCertificateAssertionError``).
    This field is a **producer workload identity**, never an
    authorization-subject identity: it must never be
    read as, assigned to, or compared against ``operation_producer_subject_id``,
    ``authorization_subject_id``, or any field ``basis-core`` consumes as the
    authorization subject (ADR-0008 "Producer vs. authorization subject").
    """

    status: OperationProducerTrustStatus
    source: OperationProducerTrustSource
    authorization_subject_id: str
    operation_producer_subject_id: str | None
    producer_workload_identity: str | None = None


def classify_operation_producer(
    subject: NormalizedSubject,
    trusted_subject_ids: Collection[str],
) -> OperationProducerTrust:
    """Classify *subject* as a trusted or untrusted operation producer.

    Uses only ``subject.subject_id`` (the verified ``sub`` claim, via
    ``auth/subject_mapper.py``) checked against *trusted_subject_ids* — an
    exact, case-sensitive membership test. No other field of *subject*
    (``roles``, ``attributes``, ``name``) is inspected or has any bearing on
    the result.

    Args:
        subject: The already-authenticated, verified caller. Never mutated.
        trusted_subject_ids: The configured allowlist
            (``GatewayConfig.operation_producer_subject_ids``, or an
            equivalent collection in tests). Never mutated.

    Returns:
        An immutable ``OperationProducerTrust``:

        - Empty *trusted_subject_ids* → ``UNTRUSTED`` / ``NOT_CONFIGURED``,
          ``operation_producer_subject_id=None``. The safe default.
        - *subject.subject_id* present in *trusted_subject_ids* → ``TRUSTED``
          / ``CONFIGURED_SUBJECT_ID_ALLOWLIST``,
          ``operation_producer_subject_id=subject.subject_id``.
        - *subject.subject_id* absent from a non-empty *trusted_subject_ids*
          → ``UNTRUSTED`` / ``SUBJECT_ID_NOT_ALLOWED``,
          ``operation_producer_subject_id=None``.
    """
    if not trusted_subject_ids:
        return OperationProducerTrust(
            status=OperationProducerTrustStatus.UNTRUSTED,
            source=OperationProducerTrustSource.NOT_CONFIGURED,
            authorization_subject_id=subject.subject_id,
            operation_producer_subject_id=None,
        )

    if subject.subject_id in trusted_subject_ids:
        return OperationProducerTrust(
            status=OperationProducerTrustStatus.TRUSTED,
            source=OperationProducerTrustSource.CONFIGURED_SUBJECT_ID_ALLOWLIST,
            authorization_subject_id=subject.subject_id,
            operation_producer_subject_id=subject.subject_id,
        )

    return OperationProducerTrust(
        status=OperationProducerTrustStatus.UNTRUSTED,
        source=OperationProducerTrustSource.SUBJECT_ID_NOT_ALLOWED,
        authorization_subject_id=subject.subject_id,
        operation_producer_subject_id=None,
    )
