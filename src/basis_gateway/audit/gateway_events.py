"""Gateway-level audit event emission.

Emits ``AuditEvent`` records for gateway outcomes that occur before or outside
the kernel's ``EnforcementPoint`` evaluation: authentication failures,
validation failures, pre-evaluation receipts, evaluator unavailability, and
fail-closed evaluation exceptions.

These events **complement** kernel decision events — they do not replace them.
All events flow through the same ``AuditWriter`` used for kernel events and
use the existing basis-core ``AuditEvent`` schema.

Stable action vocabulary
────────────────────────
The ``action`` field of each gateway-level event uses one of the constants
defined in this module, e.g. ``AUTHENTICATION_FAILED``.  Reason strings are
drawn from the ``REASON_*`` constants.

Security invariants
───────────────────
- Raw JWT strings, Authorization header values, and token contents are
  **never** included in emitted events.
- Audit write failures are logged and discarded — they must not propagate to
  the caller or alter any authorization decision.
- If ``writer`` is ``None`` the function returns immediately without error.
"""

from __future__ import annotations

import logging
from typing import Any

from basis_core.audit import AuditEvent, AuditEventType, AuditOutcome, AuditWriter

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Stable gateway action vocabulary
# ---------------------------------------------------------------------------

#: Request received and authenticated; evaluation is about to begin.
EVALUATION_REQUESTED = "gateway.evaluation_requested"

#: Authentication failed before a kernel decision could be produced.
AUTHENTICATION_FAILED = "gateway.authentication_failed"

#: Request body failed validation before authentication was attempted.
VALIDATION_FAILED = "gateway.validation_failed"

#: Evaluator is not initialized; request failed closed without kernel evaluation.
EVALUATOR_UNAVAILABLE = "gateway.evaluator_unavailable"

#: Evaluation raised unexpectedly; request failed closed.
EVALUATION_FAILED_CLOSED = "gateway.evaluation_failed_closed"

#: Lightweight probe emitted by the fail-closed check when the audit writer is
#: degraded.  If this write succeeds, the writer recovers automatically and
#: the request continues.  If it fails, the writer remains degraded and the
#: request is rejected with 503.  Contains no request content — only the
#: correlation ID and request path are recorded.
AUDIT_RECOVERY_PROBE = "gateway.audit_recovery_probe"

# ---------------------------------------------------------------------------
# Stable reason category vocabulary
# ---------------------------------------------------------------------------

REASON_MISSING_TOKEN = "missing_bearer_token"
REASON_MALFORMED_HEADER = "malformed_authorization_header"
REASON_INVALID_TOKEN = "invalid_token"
REASON_TOKEN_EXPIRED = "expired_token"
REASON_ISSUER_MISMATCH = "issuer_mismatch"
REASON_AUDIENCE_MISMATCH = "audience_mismatch"
REASON_JWKS_FAILURE = "jwks_verification_failure"
REASON_IDENTITY_NORMALIZATION_FAILED = "identity_normalization_failed"
REASON_VERIFIER_NOT_CONFIGURED = "verifier_not_configured"
REASON_EVALUATOR_NOT_INITIALIZED = "evaluator_not_initialized"
REASON_MALFORMED_BODY = "malformed_request_body"
REASON_INVALID_FIELDS = "invalid_request_fields"
REASON_EVALUATION_EXCEPTION = "unexpected_evaluation_exception"
REASON_INVALID_DECISION_REQUEST = "invalid_decision_request"

# ---------------------------------------------------------------------------
# Emission helper
# ---------------------------------------------------------------------------


def emit_gateway_event(
    writer: AuditWriter | None,
    *,
    action: str,
    correlation_id: str | None = None,
    request_path: str | None = None,
    http_method: str | None = None,
    outcome: AuditOutcome | None = None,
    reason: str | None = None,
    policy_version: str | None = None,
    subject_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Emit a gateway-level audit event via *writer*.

    This function is **always safe to call**:
    - Returns immediately if *writer* is ``None``.
    - Catches and logs any exception raised by the writer rather than
      propagating it to the caller.

    Args:
        writer:        The ``AuditWriter`` to emit to, or ``None`` to no-op.
        action:        Stable gateway action constant (e.g. ``AUTHENTICATION_FAILED``).
        correlation_id: The request correlation ID (from ``request.state.correlation_id``).
        request_path:  The HTTP request path (e.g. ``/v1/evaluate``).
        http_method:   The HTTP method (e.g. ``POST``).
        outcome:       ``AuditOutcome`` or ``None`` for informational events.
        reason:        Stable reason category string (``REASON_*`` constants).
        policy_version: Policy version from the evaluator, if known.
        subject_id:    Normalized subject ID, if available at the point of failure.
        detail:        Extra structured context.  Must not contain secrets or tokens.
    """
    if writer is None:
        return

    event_detail: dict[str, object] = {}
    if http_method is not None:
        event_detail["http_method"] = http_method
    if request_path is not None:
        event_detail["request_path"] = request_path
    if detail:
        event_detail.update(detail)

    try:
        event = AuditEvent(
            event_type=AuditEventType.SYSTEM_EVENT,
            action=action,
            outcome=outcome,
            reason=reason,
            correlation_id=correlation_id,
            subject_id=subject_id,
            policy_version=policy_version,
            detail=event_detail,
        )
        writer.write(event)
    except Exception as exc:
        log.error(
            "Gateway audit write failed (action=%s, correlation_id=%s): %s",
            action,
            correlation_id,
            exc,
        )
