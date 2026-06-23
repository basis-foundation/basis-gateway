"""Resource identifier composition boundary for basis-gateway.

The gateway is the runtime boundary between *adapter-normalized* operations and
*kernel-compatible* authorization requests. Just as ``basis-adapters`` emit a
**bare verb** that the gateway composes into a composite action (see
``basis_gateway.core.actions``), adapters also emit a **local resource_id**
(e.g. ``rooftop-1``) alongside a separate ``resource_type`` (e.g. ``ahu``).
``basis-core`` expects a **typed** resource identifier in the
``{type}:{qualifier}`` form (e.g. ``ahu:rooftop-1``). This module composes the
former into the latter so a single ``POST /v1/evaluate`` endpoint can accept
both request styles.

Architectural boundary — what this module does and does not do:
  - It **composes** a typed resource_id from a resource_type and a local
    resource_id, and detects when a resource_id is already typed.
  - It does **not** evaluate authorization, invent a resource taxonomy, parse
    any protocol, maintain a device registry, or act as an adapter.
  - It performs only conservative *typed/local* detection (presence of a
    ``:``). ``basis-core`` remains the authority that validates the resulting
    resource identifier; the gateway never substitutes for it.

This module shares the reserved gateway evidence namespace and the
``resource_type`` evidence key with ``basis_gateway.core.actions`` so that, for
an adapter-normalized request, action and resource composition agree on a single
``basis_gateway.resource_type`` value.

This module imports nothing from ``basis-adapters`` or ``basis-console``.
"""

from __future__ import annotations

from dataclasses import dataclass

from basis_gateway.core.actions import (
    EVIDENCE_RESOURCE_TYPE,
    RESERVED_CONTEXT_PREFIX,
)

# Evidence keys written to the evaluation context when (and only when) the
# gateway composes a local resource_id into a typed one. ``EVIDENCE_RESOURCE_TYPE``
# is reused from the action-composition module: for an adapter-normalized request
# the same ``resource_type`` drives both action and resource composition, so a
# single key with one value is recorded.
EVIDENCE_RESOURCE_COMPOSED = f"{RESERVED_CONTEXT_PREFIX}resource_composed"
EVIDENCE_ORIGINAL_RESOURCE_ID = f"{RESERVED_CONTEXT_PREFIX}original_resource_id"
EVIDENCE_COMPOSED_RESOURCE_ID = f"{RESERVED_CONTEXT_PREFIX}composed_resource_id"


class ResourceCompositionError(ValueError):
    """Raised when a resource_type / resource_id combination cannot be composed.

    The message is safe to surface to callers — it never contains secrets,
    tokens, or identity material.
    """


@dataclass(frozen=True)
class ResourceCompositionResult:
    """Outcome of resource identifier composition.

    Attributes:
        resource_id: The canonical resource identifier handed to ``basis-core``.
            ``None`` for a resource-independent request.
        composed: ``True`` only when a local resource_id was composed into a
            typed one. ``False`` for pass-through and resource-independent
            requests, so evidence is recorded only when composition occurred.
        original_resource_id: The caller's local resource_id, recorded as
            evidence; ``None`` unless ``composed`` is ``True``.
        resource_type: The resource_type used to compose; ``None`` unless
            ``composed`` is ``True``.
    """

    resource_id: str | None
    composed: bool
    original_resource_id: str | None = None
    resource_type: str | None = None


def is_typed_resource_id(resource_id: str) -> bool:
    """Return True when ``resource_id`` is already in typed (colon-bearing) form.

    Conservative detection only — a single ``:`` is sufficient to treat the
    identifier as already typed (e.g. ``ahu:rooftop-1``, ``sensor:co2:lobby``).
    ``basis-core`` remains the authority that fully validates the format.
    """
    return ":" in resource_id


def compose_resource_id(
    resource_type: str | None, resource_id: str | None
) -> ResourceCompositionResult:
    """Compose a kernel-compatible resource identifier.

    Deterministic rules (mirrors the action-composition boundary):

    - **resource_id absent** (``None``): no resource composition occurs. The
      request is resource-independent (or domain-level — ``resource_type`` may
      still drive *action* composition). ``resource_id`` stays ``None``.
    - **resource_id already typed, no resource_type:** pass through unchanged.
    - **resource_id already typed, resource_type supplied:** rejected. The
      gateway must not accept two sources of resource-type truth, even when the
      prefix matches — that ambiguity is the caller's to resolve.
    - **local resource_id + resource_type supplied:** composed into
      ``"{resource_type}:{resource_id}"`` and evidence is recorded.
    - **local resource_id, no resource_type:** rejected. The gateway cannot
      construct a canonical resource identifier from a local id alone.

    ``resource_type`` is treated as *supplied* when it is not ``None``.

    Raises:
        ResourceCompositionError: for an already-typed resource_id supplied with
            a resource_type, or a local resource_id without a resource_type.
    """
    resource_type_supplied = resource_type is not None

    if resource_id is None:
        # Resource-independent (or domain-level) request. No composition; a
        # resource_type, if present, is consumed by action composition only.
        return ResourceCompositionResult(resource_id=None, composed=False)

    if is_typed_resource_id(resource_id):
        if resource_type_supplied:
            raise ResourceCompositionError(
                f"resource_type ({resource_type!r}) must not be supplied when resource_id "
                f"is already typed ({resource_id!r}). Provide either a typed resource_id "
                "(e.g. 'ahu:rooftop-1') or a resource_type plus a local resource_id "
                "(e.g. resource_type='ahu', resource_id='rooftop-1') — not both."
            )
        # Already kernel-compatible — pass through unchanged.
        return ResourceCompositionResult(resource_id=resource_id, composed=False)

    # Local resource_id — composition is required.
    if not resource_type_supplied:
        raise ResourceCompositionError(
            f"resource_id {resource_id!r} is local and cannot be composed into a canonical "
            "typed identifier without a resource_type. Send a typed resource_id "
            "(e.g. 'ahu:rooftop-1') or add resource_type (e.g. 'ahu')."
        )

    composed = f"{resource_type}:{resource_id}"
    return ResourceCompositionResult(
        resource_id=composed,
        composed=True,
        original_resource_id=resource_id,
        resource_type=resource_type,
    )


def build_resource_composition_evidence(
    *, original_resource_id: str, resource_type: str, composed_resource_id: str
) -> dict[str, str]:
    """Build the reserved-namespace evidence recorded when a resource is composed.

    Returned only for composed requests, so a pass-through or resource-independent
    request never falsely claims composition. All values are strings (the
    evaluation context is ``dict[str, str]``).
    """
    return {
        EVIDENCE_RESOURCE_COMPOSED: "true",
        EVIDENCE_ORIGINAL_RESOURCE_ID: original_resource_id,
        EVIDENCE_RESOURCE_TYPE: resource_type,
        EVIDENCE_COMPOSED_RESOURCE_ID: composed_resource_id,
    }
