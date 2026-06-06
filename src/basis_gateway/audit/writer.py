"""Audit writer for basis-gateway.

basis-core's EnforcementPoint writes audit events automatically via the
AuditWriter passed at construction. The gateway's responsibility is to
provide a correctly configured AuditWriter instance at startup.

For v0.1 the gateway uses basis-core's LogAuditWriter directly. A thin
GatewayAuditWriter wrapper is provided for operational hooks: failure
tracking, threshold-based readiness degradation, and automatic recovery.

Audit write failures:
  - Must not propagate to the caller.
  - Must not alter authorization decisions.
  - Are logged as operational errors so they are visible in logs/alerts.
  - After ``failure_threshold`` consecutive failures, the ``audit_writer``
    readiness component is marked not-ready, causing ``/ready`` to return
    503 until audit writes recover.

Failure escalation behavior (see docs/audit-failure-escalation.md):
  - ``consecutive_failure_count`` increments on each failed write.
  - A successful write resets ``consecutive_failure_count`` to zero.
  - When ``consecutive_failure_count >= failure_threshold`` and the writer
    is not already degraded, readiness is marked not-ready (Model B default).
  - Recovery is automatic: the first successful write after degradation
    marks the component ready again.
  - ``failed_write_count`` is monotonic and never resets.
"""

from __future__ import annotations

import logging

from basis_core.audit import AuditEvent, AuditWriter, LogAuditWriter

from basis_gateway.readiness import ReadinessState

log = logging.getLogger(__name__)

_AUDIT_WRITER_COMPONENT = "audit_writer"


class GatewayAuditWriter:
    """AuditWriter wrapper with consecutive-failure tracking and readiness integration.

    Delegates to an inner ``AuditWriter`` (default: ``LogAuditWriter``).

    Write failures are caught, logged, and counted. When ``consecutive_failure_count``
    reaches ``failure_threshold``, the ``audit_writer`` readiness component is marked
    not-ready. The first successful write after degradation restores readiness.

    Exceptions never propagate to callers. Authorization decisions are never affected.

    Args:
        inner: Inner ``AuditWriter`` delegate. Defaults to ``LogAuditWriter()``.
        readiness_state: ``ReadinessState`` instance used to signal degradation and
            recovery. If ``None``, readiness signaling is disabled (useful in tests
            that do not need readiness integration).
        failure_threshold: Consecutive failures before readiness degrades. Must be >= 1.
            Defaults to 10.
    """

    def __init__(
        self,
        inner: AuditWriter | None = None,
        readiness_state: ReadinessState | None = None,
        failure_threshold: int = 10,
    ) -> None:
        self._inner: AuditWriter = inner if inner is not None else LogAuditWriter()
        self._readiness_state = readiness_state
        self._failure_threshold = max(1, failure_threshold)

        self._failed_write_count: int = 0
        self._consecutive_failure_count: int = 0
        self._degraded: bool = False

    # ------------------------------------------------------------------
    # Core write path
    # ------------------------------------------------------------------

    def write(self, event: AuditEvent) -> None:
        """Write *event* to the inner writer.

        On success:
          - Resets ``consecutive_failure_count`` to 0.
          - If previously degraded, logs recovery and marks readiness ready.

        On failure:
          - Increments ``failed_write_count`` (monotonic) and ``consecutive_failure_count``.
          - Logs the failure at ERROR level (without exposing secrets).
          - If threshold is crossed and not already degraded, logs at CRITICAL
            and marks readiness not-ready.

        Never raises.
        """
        try:
            self._inner.write(event)
        except Exception as exc:
            self._failed_write_count += 1
            self._consecutive_failure_count += 1
            log.error(
                "Audit write failed (consecutive: %d, total: %d): %s",
                self._consecutive_failure_count,
                self._failed_write_count,
                exc,
            )
            if self._consecutive_failure_count >= self._failure_threshold and not self._degraded:
                self._degraded = True
                log.critical(
                    "Audit write failures reached threshold (%d consecutive); "
                    "marking audit_writer not-ready",
                    self._consecutive_failure_count,
                )
                if self._readiness_state is not None:
                    self._readiness_state.mark_not_ready(
                        reason=(
                            f"Audit write failures exceeded threshold "
                            f"({self._consecutive_failure_count} consecutive failures)"
                        ),
                        component=_AUDIT_WRITER_COMPONENT,
                    )
            return

        # Successful write path.
        if self._degraded:
            log.info(
                "Audit write recovered after %d consecutive failures; marking audit_writer ready",
                self._consecutive_failure_count,
            )
            self._degraded = False
            if self._readiness_state is not None:
                self._readiness_state.mark_ready(component=_AUDIT_WRITER_COMPONENT)

        self._consecutive_failure_count = 0

    # ------------------------------------------------------------------
    # Public state properties
    # ------------------------------------------------------------------

    @property
    def failed_write_count(self) -> int:
        """Total audit write failures since startup. Monotonic; never resets."""
        return self._failed_write_count

    @property
    def consecutive_failure_count(self) -> int:
        """Consecutive failures since the last successful write. Resets on success."""
        return self._consecutive_failure_count

    @property
    def degraded(self) -> bool:
        """True when consecutive failures have crossed the threshold."""
        return self._degraded

    @property
    def failure_threshold(self) -> int:
        """Configured consecutive-failure threshold."""
        return self._failure_threshold


def build_audit_writer(
    readiness_state: ReadinessState | None = None,
    failure_threshold: int = 10,
) -> GatewayAuditWriter:
    """Build the default audit writer for production use.

    Args:
        readiness_state: Passed through to ``GatewayAuditWriter`` for readiness
            signaling. Should be the application's shared ``ReadinessState``.
        failure_threshold: Consecutive failures before ``audit_writer`` readiness
            degrades. Sourced from ``AUDIT_FAILURE_THRESHOLD`` env var.
    """
    return GatewayAuditWriter(
        inner=LogAuditWriter(),
        readiness_state=readiness_state,
        failure_threshold=failure_threshold,
    )
