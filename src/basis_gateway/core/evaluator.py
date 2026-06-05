"""basis-core EnforcementPoint wrapper for basis-gateway.

Responsibilities:
- Build a Subject and IdentityContext from a NormalizedSubject and raw token
- Construct a DecisionRequest from the HTTP request payload
- Call EnforcementPoint.evaluate() and return the DecisionResponse

The EnforcementPoint is a singleton for the process lifetime. It is
initialized once during the FastAPI lifespan and stored in app.state.

Policy loading:
  Policies are loaded from a JSON file at startup via
  basis_gateway.policy.loader.load_policy_engine(). The caller is
  responsible for loading the PolicyEngine before calling build_evaluator().
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass
from typing import Any

from basis_core.audit import AuditWriter, NullAuditWriter
from basis_core.decisions import DecisionOutcome, DecisionRequest, DecisionResponse
from basis_core.domain import IdentityContext, Subject, SubjectType
from basis_core.domain import action as actions
from basis_core.enforcement import EnforcementPoint
from basis_core.policy import PolicyEngine, RolePolicyRule

from basis_gateway.auth.subject_mapper import NormalizedSubject

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Subject and IdentityContext construction
# ---------------------------------------------------------------------------


def _build_subject(normalized: NormalizedSubject) -> Subject:
    """Translate a gateway NormalizedSubject to a basis-core Subject.

    Attributes that are not strings are silently dropped because
    Subject.attrs is typed as dict[str, str].
    """
    str_attrs: dict[str, str] = {
        k: str(v) for k, v in normalized.attributes.items() if isinstance(v, str)
    }
    return Subject(
        id=normalized.subject_id,
        name=normalized.name,
        type=SubjectType.HUMAN,
        roles=list(normalized.roles),
        attrs=str_attrs,
    )


def _build_identity_context(
    subject: Subject,
    raw_token: str,
    claims: dict[str, Any],
) -> IdentityContext:
    """Build a basis-core IdentityContext from verified claims.

    ``token`` stores the raw Bearer token. ``issued_at`` and ``expires_at``
    are extracted from standard JWT claims.
    """
    iat = claims.get("iat")
    exp = claims.get("exp")

    issued_at: datetime.datetime
    if isinstance(iat, (int, float)):
        issued_at = datetime.datetime.fromtimestamp(iat, tz=datetime.timezone.utc)
    else:
        issued_at = datetime.datetime.now(datetime.timezone.utc)

    expires_at: datetime.datetime | None = None
    if isinstance(exp, (int, float)):
        expires_at = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)

    return IdentityContext(
        subject=subject,
        token=raw_token,
        issued_at=issued_at,
        expires_at=expires_at,
    )


# ---------------------------------------------------------------------------
# GatewayEvaluator
# ---------------------------------------------------------------------------


@dataclass
class GatewayEvaluator:
    """Process-lifetime wrapper around basis-core EnforcementPoint.

    Constructed once at startup. Thread-safe after initialization because
    EnforcementPoint is stateless after construction.
    """

    _enforcement_point: EnforcementPoint

    def evaluate(
        self,
        *,
        normalized_subject: NormalizedSubject,
        raw_token: str,
        claims: dict[str, Any],
        action: str,
        resource_id: str | None,
        request_id: str,
        correlation_id: str | None,
        context: dict[str, str],
    ) -> DecisionResponse:
        """Evaluate an authorization request.

        Args:
            normalized_subject: Verified and normalized caller identity.
            raw_token: The raw Bearer token (for IdentityContext).
            claims: Verified JWT claims dict (for timestamps + IdentityContext).
            action: Action string in ``{verb}:{domain}[:{object}]`` format.
            resource_id: Resource identifier or None.
            request_id: Caller-supplied or gateway-generated request ID.
            correlation_id: Optional correlation ID for audit trace.
            context: Caller-supplied evaluation context (string key/value pairs).

        Returns:
            DecisionResponse from basis-core. Never raises — the
            EnforcementPoint guarantees DENY on all error paths.
        """
        subject = _build_subject(normalized_subject)
        identity_context = _build_identity_context(subject, raw_token, claims)

        decision_request = DecisionRequest(
            request_id=request_id,
            subject_id=subject.id,
            subject_roles=list(subject.roles),
            subject_attrs=subject.attrs,
            action=action,
            resource_id=resource_id,
            context=context,
            timestamp=datetime.datetime.now(datetime.timezone.utc),
        )

        return self._enforcement_point.evaluate(
            request=decision_request,
            subject=subject,
            identity_context=identity_context,
            correlation_id=correlation_id,
        )

    @property
    def policy_version(self) -> str | None:
        """The policy version string configured on the EnforcementPoint.

        Reads from the kernel public API. The value originates from the
        ``policy_version`` parameter passed to ``build_evaluator()`` and is
        owned by ``EnforcementPoint`` after construction. It is propagated
        verbatim into every ``DecisionResponse`` and ``AuditEvent`` the
        enforcement point produces.
        """
        return self._enforcement_point.policy_version


def build_evaluator(
    engine: PolicyEngine,
    audit_writer: AuditWriter,
    policy_version: str | None = None,
) -> GatewayEvaluator:
    """Build a GatewayEvaluator from a loaded PolicyEngine.

    Args:
        engine: A PolicyEngine constructed from the loaded policy file.
        audit_writer: The audit writer to use. Must implement AuditWriter protocol.
        policy_version: Optional version string included in responses and audit records.

    Returns:
        An initialized GatewayEvaluator ready to serve requests.
    """
    ep = EnforcementPoint(
        engine=engine,
        audit_writer=audit_writer,
        policy_version=policy_version,
    )
    log.info("GatewayEvaluator initialized, version=%s", policy_version)
    return GatewayEvaluator(_enforcement_point=ep)


def build_null_evaluator() -> GatewayEvaluator:
    """Build a GatewayEvaluator with a minimal in-memory policy. For tests only."""
    engine = PolicyEngine(
        policies=[
            RolePolicyRule(
                role_table={
                    actions.READ_SENSOR_TELEMETRY: {"viewer", "operator", "admin"},
                    actions.READ_HVAC_STATE: {"viewer", "operator", "admin"},
                    actions.READ_ZONE_STATE: {"viewer", "operator", "admin"},
                    actions.READ_DEVICE_STATE: {"viewer", "operator", "admin"},
                    actions.READ_AUDIT_LOG: {"admin"},
                    actions.READ_POLICY: {"admin"},
                    actions.READ_RESOURCES: {"viewer", "operator", "admin"},
                    actions.WRITE_HVAC_SETPOINT: {"operator", "admin"},
                    actions.WRITE_HVAC_MODE: {"operator", "admin"},
                    actions.WRITE_DEVICE_SETPOINT: {"operator", "admin"},
                    actions.WRITE_POLICY: {"admin"},
                    actions.EXECUTE_DEVICE_COMMAND: {"operator", "admin"},
                    actions.SUBSCRIBE_TELEMETRY: {"viewer", "operator", "admin"},
                    actions.DISCONNECT_TELEMETRY: {"operator", "admin"},
                },
                rule_name="test-rbac",
            )
        ]
    )
    ep = EnforcementPoint(engine=engine, audit_writer=NullAuditWriter(), policy_version="test")
    return GatewayEvaluator(_enforcement_point=ep)


# Re-export DecisionOutcome for use in routes without importing basis-core directly.
__all__ = [
    "GatewayEvaluator",
    "DecisionOutcome",
    "build_evaluator",
    "build_null_evaluator",
]
