"""Audit writer for basis-gateway.

basis-core's EnforcementPoint writes audit events automatically via the
AuditWriter passed at construction. The gateway's responsibility is to
provide a correctly configured AuditWriter instance at startup.

For v0.1 the gateway uses basis-core's LogAuditWriter directly. A thin
GatewayAuditWriter wrapper is provided for future operational hooks (metrics,
alerting) without requiring changes to the EnforcementPoint setup.

Audit write failures:
  - Must not propagate to the caller.
  - Must not alter authorization decisions.
  - Must be logged as operational errors so they are visible in metrics/alerts.
  This is the v0.1 decision (see docs/implementation/basis-gateway-v0.1-plan.md §9).
"""

from __future__ import annotations

import logging

from basis_core.audit import AuditEvent, AuditWriter, LogAuditWriter

log = logging.getLogger(__name__)


class GatewayAuditWriter:
    """Thin AuditWriter wrapper that logs write failures as operational errors.

    Delegates to an inner ``AuditWriter`` (default: ``LogAuditWriter``).

    Write failures are caught, logged, and discarded — they must never
    propagate to the caller or alter the authorization decision.
    """

    def __init__(self, inner: AuditWriter | None = None) -> None:
        self._inner: AuditWriter = inner if inner is not None else LogAuditWriter()
        self._failed_write_count = 0

    def write(self, event: AuditEvent) -> None:
        """Write *event* to the inner writer.

        On failure: increments the failure counter and logs an ERROR.
        Never raises.
        """
        try:
            self._inner.write(event)
        except Exception as exc:
            self._failed_write_count += 1
            log.error(
                "Audit write failed (total failures: %d): %s",
                self._failed_write_count,
                exc,
            )

    @property
    def failed_write_count(self) -> int:
        """Number of audit write failures since startup. Useful for monitoring."""
        return self._failed_write_count


def build_audit_writer() -> GatewayAuditWriter:
    """Build the default audit writer for production use."""
    return GatewayAuditWriter(inner=LogAuditWriter())
