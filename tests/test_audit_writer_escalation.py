"""Unit tests for GatewayAuditWriter failure escalation behavior.

Covers:
  - single failure does not degrade readiness
  - consecutive failures below threshold do not degrade
  - threshold crossing marks audit_writer not-ready
  - success after degradation restores readiness and resets counter
  - failed_write_count is monotonic
  - consecutive_failure_count resets on success
  - inner writer exceptions are caught; none propagate
  - threshold-crossing log message is emitted (CRITICAL)
  - recovery log message is emitted (INFO)
"""

from __future__ import annotations

from unittest.mock import MagicMock

from basis_gateway.audit.writer import GatewayAuditWriter
from basis_gateway.readiness import ReadinessState

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _AlwaysFailingWriter:
    def write(self, event: object) -> None:
        raise OSError("audit sink down")


class _AlwaysSucceedingWriter:
    def write(self, event: object) -> None:
        pass


_FAKE_EVENT = MagicMock()


def _make_writer(
    *,
    fail: bool = True,
    threshold: int = 3,
    readiness_state: ReadinessState | None = None,
) -> GatewayAuditWriter:
    inner = _AlwaysFailingWriter() if fail else _AlwaysSucceedingWriter()
    return GatewayAuditWriter(
        inner=inner,
        readiness_state=readiness_state,
        failure_threshold=threshold,
    )


def _fail_n(writer: GatewayAuditWriter, n: int) -> None:
    for _ in range(n):
        writer.write(_FAKE_EVENT)


# ---------------------------------------------------------------------------
# Basic failure counting
# ---------------------------------------------------------------------------


def test_single_failure_does_not_degrade():
    writer = _make_writer(fail=True, threshold=3)
    writer.write(_FAKE_EVENT)
    assert not writer.degraded
    assert writer.consecutive_failure_count == 1
    assert writer.failed_write_count == 1


def test_failures_below_threshold_do_not_degrade():
    writer = _make_writer(fail=True, threshold=5)
    _fail_n(writer, 4)
    assert not writer.degraded
    assert writer.consecutive_failure_count == 4
    assert writer.failed_write_count == 4


def test_threshold_crossing_marks_degraded():
    writer = _make_writer(fail=True, threshold=3)
    _fail_n(writer, 3)
    assert writer.degraded
    assert writer.consecutive_failure_count == 3


def test_threshold_crossing_exactly_at_threshold():
    writer = _make_writer(fail=True, threshold=1)
    writer.write(_FAKE_EVENT)
    assert writer.degraded


def test_additional_failures_after_threshold_stay_degraded():
    writer = _make_writer(fail=True, threshold=2)
    _fail_n(writer, 5)
    assert writer.degraded
    assert writer.consecutive_failure_count == 5
    assert writer.failed_write_count == 5


# ---------------------------------------------------------------------------
# failed_write_count is monotonic
# ---------------------------------------------------------------------------


def test_failed_write_count_is_monotonic():
    """failed_write_count never decreases, even after recovery."""
    rs = ReadinessState()
    rs.mark_ready("audit_writer")
    writer = GatewayAuditWriter(
        inner=_AlwaysFailingWriter(),
        readiness_state=rs,
        failure_threshold=2,
    )
    _fail_n(writer, 3)
    total_before = writer.failed_write_count

    # Switch to a succeeding writer and recover
    writer._inner = _AlwaysSucceedingWriter()
    writer.write(_FAKE_EVENT)

    assert writer.failed_write_count == total_before  # unchanged
    assert writer.failed_write_count >= 3


# ---------------------------------------------------------------------------
# consecutive_failure_count resets on success
# ---------------------------------------------------------------------------


def test_consecutive_count_resets_on_success():
    rs = ReadinessState()
    rs.mark_ready("audit_writer")
    writer = GatewayAuditWriter(
        inner=_AlwaysFailingWriter(),
        readiness_state=rs,
        failure_threshold=5,
    )
    _fail_n(writer, 3)
    assert writer.consecutive_failure_count == 3

    writer._inner = _AlwaysSucceedingWriter()
    writer.write(_FAKE_EVENT)

    assert writer.consecutive_failure_count == 0
    assert writer.failed_write_count == 3  # total not reset


def test_consecutive_count_resets_even_below_threshold():
    writer = _make_writer(fail=True, threshold=10)
    _fail_n(writer, 4)
    assert writer.consecutive_failure_count == 4

    writer._inner = _AlwaysSucceedingWriter()
    writer.write(_FAKE_EVENT)

    assert writer.consecutive_failure_count == 0
    assert not writer.degraded


# ---------------------------------------------------------------------------
# Recovery after degradation
# ---------------------------------------------------------------------------


def test_success_after_degradation_marks_ready():
    rs = ReadinessState()
    rs.mark_ready("audit_writer")
    writer = GatewayAuditWriter(
        inner=_AlwaysFailingWriter(),
        readiness_state=rs,
        failure_threshold=3,
    )
    _fail_n(writer, 3)
    assert writer.degraded
    assert not rs.is_ready  # audit_writer is not-ready

    writer._inner = _AlwaysSucceedingWriter()
    writer.write(_FAKE_EVENT)

    assert not writer.degraded
    assert writer.consecutive_failure_count == 0
    assert rs.components.get("audit_writer") is True


def test_recovery_restores_readiness_immediately():
    rs = ReadinessState()
    rs.mark_ready("configuration_loaded")
    rs.mark_ready("audit_writer")

    writer = GatewayAuditWriter(
        inner=_AlwaysFailingWriter(),
        readiness_state=rs,
        failure_threshold=2,
    )
    _fail_n(writer, 2)
    assert not rs.is_ready

    writer._inner = _AlwaysSucceedingWriter()
    writer.write(_FAKE_EVENT)

    assert rs.is_ready


# ---------------------------------------------------------------------------
# Readiness state interactions
# ---------------------------------------------------------------------------


def test_threshold_crossing_calls_mark_not_ready():
    rs = ReadinessState()
    rs.mark_ready("audit_writer")
    writer = GatewayAuditWriter(
        inner=_AlwaysFailingWriter(),
        readiness_state=rs,
        failure_threshold=3,
    )
    _fail_n(writer, 3)
    assert rs.components.get("audit_writer") is False


def test_threshold_crossing_only_calls_mark_not_ready_once():
    """Repeated failures after threshold do not call mark_not_ready again."""
    rs = MagicMock(spec=ReadinessState)
    writer = GatewayAuditWriter(
        inner=_AlwaysFailingWriter(),
        readiness_state=rs,
        failure_threshold=2,
    )
    _fail_n(writer, 5)
    # mark_not_ready called exactly once (at threshold crossing)
    assert rs.mark_not_ready.call_count == 1


def test_no_readiness_state_does_not_raise():
    """Writer without readiness_state works normally; no AttributeError."""
    writer = _make_writer(fail=True, threshold=2, readiness_state=None)
    _fail_n(writer, 3)  # crosses threshold — must not raise
    assert writer.degraded


# ---------------------------------------------------------------------------
# Inner exceptions never propagate
# ---------------------------------------------------------------------------


def test_inner_exception_never_propagates():
    class _BombWriter:
        def write(self, event: object) -> None:
            raise RuntimeError("catastrophic failure")

    writer = GatewayAuditWriter(inner=_BombWriter(), failure_threshold=5)
    # Must not raise
    writer.write(_FAKE_EVENT)
    assert writer.failed_write_count == 1


def test_inner_exception_type_variety():
    # Only Exception subclasses are caught by the writer's guard.
    # BaseException subclasses (e.g. KeyboardInterrupt) are intentionally not caught.
    for exc_class in (OSError, ValueError, MemoryError, RuntimeError):

        class _Writer:
            _exc = exc_class

            def write(self, event: object) -> None:
                raise self._exc("boom")

        writer = GatewayAuditWriter(inner=_Writer(), failure_threshold=99)
        writer.write(_FAKE_EVENT)  # must not raise
    # If we got here, no exception propagated


# ---------------------------------------------------------------------------
# Logging behavior
# ---------------------------------------------------------------------------


def test_threshold_crossing_logs_critical(caplog):
    import logging

    writer = _make_writer(fail=True, threshold=2, readiness_state=None)
    with caplog.at_level(logging.CRITICAL, logger="basis_gateway.audit.writer"):
        _fail_n(writer, 2)

    critical_msgs = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    assert critical_msgs, "Expected CRITICAL log at threshold crossing"
    assert "threshold" in critical_msgs[0].message.lower()


def test_recovery_logs_info(caplog):
    import logging

    rs = ReadinessState()
    rs.mark_ready("audit_writer")
    writer = GatewayAuditWriter(
        inner=_AlwaysFailingWriter(),
        readiness_state=rs,
        failure_threshold=2,
    )
    _fail_n(writer, 2)

    writer._inner = _AlwaysSucceedingWriter()
    with caplog.at_level(logging.INFO, logger="basis_gateway.audit.writer"):
        writer.write(_FAKE_EVENT)

    info_msgs = [
        r for r in caplog.records if r.levelno == logging.INFO and "recover" in r.message.lower()
    ]
    assert info_msgs, "Expected INFO recovery log after successful write"


def test_failure_logs_error(caplog):
    import logging

    writer = _make_writer(fail=True, threshold=10, readiness_state=None)
    with caplog.at_level(logging.ERROR, logger="basis_gateway.audit.writer"):
        writer.write(_FAKE_EVENT)

    error_msgs = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert error_msgs, "Expected ERROR log on audit write failure"


# ---------------------------------------------------------------------------
# failure_threshold property
# ---------------------------------------------------------------------------


def test_failure_threshold_property():
    writer = GatewayAuditWriter(inner=_AlwaysSucceedingWriter(), failure_threshold=7)
    assert writer.failure_threshold == 7


def test_failure_threshold_minimum_is_one():
    writer = GatewayAuditWriter(inner=_AlwaysSucceedingWriter(), failure_threshold=0)
    assert writer.failure_threshold == 1
