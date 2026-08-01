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
    """

    CONFIGURED_SUBJECT_ID_ALLOWLIST = "configured_subject_id_allowlist"
    NOT_CONFIGURED = "not_configured"
    SUBJECT_ID_NOT_ALLOWED = "subject_id_not_allowed"


@dataclass(frozen=True, slots=True)
class OperationProducerTrust:
    """Immutable result of classifying an authenticated caller as a producer.

    Keeps ``authorization_subject_id`` (the authenticated caller — always
    present) and ``operation_producer_subject_id`` (the same value, but only
    when the caller is trusted; otherwise ``None``) as separate fields. The
    two are equal in this PR's only supported trust mechanism (shared-token,
    configured-allowlist), but that equality is an implementation detail of
    the current transport, not a statement that the two concepts are the
    same fact — see this module's docstring.
    """

    status: OperationProducerTrustStatus
    source: OperationProducerTrustSource
    authorization_subject_id: str
    operation_producer_subject_id: str | None


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
