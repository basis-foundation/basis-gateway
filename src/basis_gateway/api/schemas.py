"""Request and response schemas for basis-gateway API endpoints."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator


class EvaluateRequest(BaseModel):
    """Request body for ``POST /v1/evaluate``.

    The caller provides the action and optional resource identifier.
    Subject identity (who is making the request) is derived exclusively
    from the verified Bearer token — it must not be provided by the caller.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: str | None = None
    action: str
    resource_id: str | None = None
    context: dict[str, str] = {}

    @model_validator(mode="before")
    @classmethod
    def reject_caller_supplied_subject(cls, data: Any) -> Any:
        """Reject any attempt to assert subject identity via the request body.

        Accepting caller-supplied subject_id or subject_roles would allow
        a caller to claim arbitrary identities. The gateway derives subject
        identity exclusively from the verified Bearer token.
        """
        if isinstance(data, dict):
            disallowed = {"subject_id", "subject_roles"} & data.keys()
            if disallowed:
                raise ValueError(
                    f"Fields {sorted(disallowed)} must not be provided by the caller. "
                    "Subject identity is derived from the verified Bearer token."
                )
        return data

    @field_validator("action")
    @classmethod
    def action_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("action must not be empty")
        return v


class EvaluateResponse(BaseModel):
    """Response body for ``POST /v1/evaluate``.

    Returned for both ALLOW (200) and DENY/NOT_APPLICABLE (403).
    ``correlation_id`` matches the ``X-Correlation-ID`` response header and
    any gateway audit events emitted for this request.
    """

    request_id: str
    outcome: str  # "allow", "deny", or "not_applicable"
    reason: str
    policy_version: str | None = None
    correlation_id: str | None = None


class ErrorResponse(BaseModel):
    """Canonical error response body.

    ``error`` is a stable machine-readable code (see below).
    ``message`` is a human-readable explanation safe to surface to callers.
    ``correlation_id`` matches the ``X-Correlation-ID`` response header and any
    gateway audit events emitted for this request.

    Stable error codes:
      authentication_required  — no Bearer token was presented
      authentication_failed    — token present but invalid or unverifiable
      validation_failed        — request body failed schema validation
      evaluator_unavailable    — evaluator not initialized (service not ready)
      evaluation_failed_closed — unexpected error during evaluation (fail-closed)
      audit_fail_closed        — audit pipeline degraded; evaluation suspended
      internal_error           — unexpected internal error
    """

    error: str
    message: str | None = None
    correlation_id: str | None = None
