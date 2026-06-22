"""Action composition boundary for basis-gateway.

The gateway is the runtime boundary between *adapter-normalized* operations and
*kernel-compatible* authorization requests. ``basis-adapters`` emit a **bare
verb** in ``action`` and carry the domain in a separate ``resource_type`` field
(e.g. ``action="read"``, ``resource_type="ahu"``). ``basis-core`` requires the
composite ``{verb}:{domain}[:{object}]`` form (e.g. ``read:ahu``). This module
composes the former into the latter so that a single ``POST /v1/evaluate``
endpoint can accept both request styles.

Architectural boundary — what this module does and does not do:
  - It **composes** an action string from a verb and a resource_type.
  - It does **not** evaluate authorization, invent decisions, define or extend
    the action vocabulary, parse any protocol, or act as an adapter.
  - It validates only the *shape* of the segments (conservative, lowercase
    identifier). ``basis-core`` remains the authority that validates and
    enforces the action contract; the gateway never substitutes for it.

This module imports nothing from ``basis-adapters`` or ``basis-console``.
"""

from __future__ import annotations

import re

# Reserved context namespace for gateway-injected evidence. Caller-supplied
# context keys in this namespace are rejected so the gateway's own evidence
# cannot be forged or silently overwritten.
RESERVED_CONTEXT_PREFIX = "basis_gateway."

# Evidence keys written to the evaluation context when (and only when) the
# gateway composes a bare action into a composite one.
EVIDENCE_ACTION_COMPOSED = f"{RESERVED_CONTEXT_PREFIX}action_composed"
EVIDENCE_ORIGINAL_ACTION = f"{RESERVED_CONTEXT_PREFIX}original_action"
EVIDENCE_RESOURCE_TYPE = f"{RESERVED_CONTEXT_PREFIX}resource_type"
EVIDENCE_COMPOSED_ACTION = f"{RESERVED_CONTEXT_PREFIX}composed_action"

# A single action/resource segment: a lowercase letter followed by lowercase
# letters, digits, hyphens, or underscores. This mirrors *one segment* of
# basis-core's action regex (``basis_core.decisions.models._ACTION_RE``); the
# gateway validates segment shape only and leaves full enforcement to the kernel.
_SEGMENT_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


class ActionCompositionError(ValueError):
    """Raised when an action / resource_type combination cannot be composed.

    The message is safe to surface to callers — it never contains secrets,
    tokens, or identity material.
    """


def is_composite_action(action: str) -> bool:
    """Return True when ``action`` is already in composite (colon-bearing) form."""
    return ":" in action


def compose_action(action: str, resource_type: str | None) -> str:
    """Compose a kernel-compatible action string from a verb and a resource_type.

    Two request styles are supported:

    - **Composite (kernel-compatible):** ``action`` already contains a ``:``
      (e.g. ``read:ahu``). It is returned **unchanged**. Supplying a
      ``resource_type`` alongside a composite action is ambiguous and rejected.
    - **Adapter-normalized:** ``action`` is a bare verb (e.g. ``read``) and a
      ``resource_type`` (e.g. ``ahu``) is supplied. Both segments are validated
      and the composed ``"{action}:{resource_type}"`` is returned.

    ``resource_type`` is treated as *supplied* when it is not ``None``; an empty
    string counts as supplied (and is rejected for a bare action).

    Raises:
        ActionCompositionError: for an empty action, a bare action without a
            resource_type, a composite action with a resource_type, or a segment
            that is not a conservative lowercase identifier.
    """
    if not action or not action.strip():
        raise ActionCompositionError("action must not be empty")

    resource_type_supplied = resource_type is not None

    if is_composite_action(action):
        # Already kernel-compatible — pass through unchanged.
        if resource_type_supplied:
            raise ActionCompositionError(
                f"resource_type must not be supplied when action is already composite "
                f"({action!r}). Provide either a composite action (e.g. 'read:ahu') or a "
                "bare verb plus resource_type (e.g. action='read', resource_type='ahu') — "
                "not both."
            )
        return action

    # Bare verb — composition is required.
    if not resource_type_supplied:
        raise ActionCompositionError(
            f"resource_type is required when action is a bare verb ({action!r}). "
            "Send a composite action (e.g. 'read:ahu') or add resource_type (e.g. 'ahu')."
        )

    assert resource_type is not None  # narrowed by resource_type_supplied
    if not resource_type:
        raise ActionCompositionError(
            "resource_type must not be empty when composing a bare action."
        )
    if not _SEGMENT_RE.match(action):
        raise ActionCompositionError(
            f"action verb {action!r} is not a valid lowercase identifier segment "
            "(letters, digits, '-', '_'; must start with a letter)."
        )
    if not _SEGMENT_RE.match(resource_type):
        raise ActionCompositionError(
            f"resource_type {resource_type!r} is not a valid lowercase identifier segment "
            "(letters, digits, '-', '_'; must start with a letter)."
        )
    return f"{action}:{resource_type}"


def reserved_key_collisions(context: dict[str, str]) -> list[str]:
    """Return any caller-supplied context keys in the reserved gateway namespace.

    Callers must not set ``basis_gateway.*`` keys; doing so could forge or
    overwrite the gateway's own composition evidence. The handler rejects a
    request when this returns a non-empty list.
    """
    return sorted(k for k in context if k.startswith(RESERVED_CONTEXT_PREFIX))


def build_composition_evidence(
    *, original_action: str, resource_type: str, composed_action: str
) -> dict[str, str]:
    """Build the reserved-namespace evidence recorded when composition occurs.

    Returned only for composed requests, so a non-composed request never falsely
    claims composition. All values are strings (the evaluation context is
    ``dict[str, str]``).
    """
    return {
        EVIDENCE_ACTION_COMPOSED: "true",
        EVIDENCE_ORIGINAL_ACTION: original_action,
        EVIDENCE_RESOURCE_TYPE: resource_type,
        EVIDENCE_COMPOSED_ACTION: composed_action,
    }
