"""Integration tests for audit failure escalation behavior.

Covers:
  - /ready returns 503 with audit_writer: false when threshold crossed
  - /ready returns 200 after audit writer recovers
  - AUDIT_FAIL_CLOSED=false (default): degraded audit writer does not block /v1/evaluate
  - AUDIT_FAIL_CLOSED=true: degraded audit writer returns 503 from /v1/evaluate
  - strict fail-closed mode recovers after successful audit write
  - startup with POLICY_PATH registers audit_writer as a readiness component
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from basis_gateway.audit.writer import GatewayAuditWriter
from basis_gateway.main import create_app
from basis_gateway.readiness import reset_readiness_state

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


def _write_policy(tmp_path: Path, data: object = None) -> str:
    if data is None:
        data = {
            "rules": [
                {
                    "rule_name": "test-rbac",
                    "role_table": {
                        "read:sensor:telemetry": ["viewer", "admin"],
                        "write:hvac:setpoint": ["admin"],
                    },
                }
            ]
        }
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def _degrade_writer(writer: GatewayAuditWriter) -> None:
    """Force the writer past its threshold by injecting failures.

    Leaves ``writer._inner`` as ``_AlwaysFailingWriter`` — the caller controls
    when (or whether) to heal the backend.  This is intentional: tests that
    want the writer to stay degraded need the inner to keep failing; tests that
    want organic recovery switch ``writer._inner`` to a succeeding writer after
    calling this helper.
    """
    writer._inner = _AlwaysFailingWriter()
    threshold = writer.failure_threshold
    for _ in range(threshold):
        writer.write(_FAKE_EVENT)
    assert writer.degraded


def _post_evaluate(client: TestClient) -> Any:
    return client.post(
        "/v1/evaluate",
        json={"action": "read:sensor:telemetry", "resource_id": "sensor:ahu-1"},
        headers={"Authorization": "Bearer fake"},
    )


# ---------------------------------------------------------------------------
# /ready — audit_writer component in readiness
# ---------------------------------------------------------------------------


def test_startup_with_policy_path_registers_audit_writer_component(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """audit_writer appears in /ready components when policy path is configured."""
    p = _write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", p)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        body = c.get("/ready").json()
        assert "audit_writer" in body["components"]
        assert body["components"]["audit_writer"] is True


def test_ready_503_when_audit_writer_degraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/ready returns 503 with audit_writer: false when threshold is crossed."""
    p = _write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", p)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        writer: GatewayAuditWriter = app.state.audit_writer
        _degrade_writer(writer)

        resp = c.get("/ready")
        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "not_ready"
        assert body["components"]["audit_writer"] is False


def test_ready_200_after_audit_writer_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/ready returns 200 once the audit writer recovers after degradation."""
    p = _write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", p)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        writer: GatewayAuditWriter = app.state.audit_writer

        # Degrade the writer
        _degrade_writer(writer)
        assert c.get("/ready").status_code == 503

        # Switch to a succeeding inner writer and trigger recovery
        writer._inner = _AlwaysSucceedingWriter()
        writer.write(_FAKE_EVENT)
        assert not writer.degraded

        resp = c.get("/ready")
        assert resp.status_code == 200
        assert resp.json()["components"]["audit_writer"] is True


def test_ready_reason_mentions_audit_writer_on_degradation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", p)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        writer: GatewayAuditWriter = app.state.audit_writer
        _degrade_writer(writer)
        body = c.get("/ready").json()
        assert "reason" in body
        assert body["reason"]  # non-empty reason string


# ---------------------------------------------------------------------------
# Fail-closed mode: AUDIT_FAIL_CLOSED=false (default)
# ---------------------------------------------------------------------------


def test_fail_open_default_degraded_writer_does_not_block_evaluate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AUDIT_FAIL_CLOSED=false (default): degraded audit writer does NOT block /v1/evaluate."""
    p = _write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", p)
    monkeypatch.delenv("AUDIT_FAIL_CLOSED", raising=False)
    reset_readiness_state()
    app = create_app()

    with TestClient(app, raise_server_exceptions=False) as c:
        # Wire a mock verifier so authentication doesn't fail
        from tests.conftest import MockVerifier

        mock_verifier = MockVerifier(
            claims={
                "sub": "user1",
                "iss": "https://test.example.com",
                "preferred_username": "alice",
                "realm_access": {"roles": ["admin", "viewer"]},
                "iat": int(time.time()),
                "exp": int(time.time()) + 600,
            }
        )
        app.state.verifier = mock_verifier

        writer: GatewayAuditWriter = app.state.audit_writer
        _degrade_writer(writer)
        # /ready is 503 (degraded)
        assert c.get("/ready").status_code == 503

        # /v1/evaluate still processes (200 or 403) — not 503 from audit degradation
        resp = _post_evaluate(c)
        assert resp.status_code != 503 or "audit" not in resp.json().get("message", "").lower()


# ---------------------------------------------------------------------------
# Fail-closed mode: AUDIT_FAIL_CLOSED=true
# ---------------------------------------------------------------------------


def test_fail_closed_true_degraded_writer_returns_503_from_evaluate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AUDIT_FAIL_CLOSED=true: degraded audit writer causes /v1/evaluate to return 503."""
    p = _write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", p)
    monkeypatch.setenv("AUDIT_FAIL_CLOSED", "true")
    reset_readiness_state()
    app = create_app()

    with TestClient(app, raise_server_exceptions=False) as c:
        from tests.conftest import MockVerifier

        app.state.verifier = MockVerifier(
            claims={
                "sub": "user1",
                "iss": "https://test.example.com",
                "preferred_username": "alice",
                "realm_access": {"roles": ["admin", "viewer"]},
                "iat": int(time.time()),
                "exp": int(time.time()) + 600,
            }
        )

        writer: GatewayAuditWriter = app.state.audit_writer
        _degrade_writer(writer)

        resp = _post_evaluate(c)
        assert resp.status_code == 503
        assert "audit" in resp.json().get("message", "").lower()


def test_fail_closed_true_recovers_organically_via_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Strict mode recovers automatically when the backend heals — no restart needed.

    The fail-closed check emits a lightweight probe event before blocking.
    If the probe write succeeds (backend has recovered), the writer self-heals
    and the request proceeds normally.  No external ``write()`` call or process
    restart is required — the probe IS the recovery mechanism.

    Regression test for the strict-mode recovery deadlock: without the probe,
    no audit write would ever fire in strict mode, so the writer could never
    exit the degraded state.
    """
    p = _write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", p)
    monkeypatch.setenv("AUDIT_FAIL_CLOSED", "true")
    reset_readiness_state()
    app = create_app()

    with TestClient(app, raise_server_exceptions=False) as c:
        from tests.conftest import MockVerifier

        app.state.verifier = MockVerifier(
            claims={
                "sub": "user1",
                "iss": "https://test.example.com",
                "preferred_username": "alice",
                "realm_access": {"roles": ["admin", "viewer"]},
                "iat": int(time.time()),
                "exp": int(time.time()) + 600,
            }
        )

        writer: GatewayAuditWriter = app.state.audit_writer

        # Degrade the writer (inner writer raises).
        _degrade_writer(writer)
        assert _post_evaluate(c).status_code == 503

        # Heal the backend WITHOUT calling write() directly.
        # Recovery must happen organically through the probe in the next request.
        writer._inner = _AlwaysSucceedingWriter()
        assert writer.degraded  # still degraded — no write has fired yet

        # Next request: probe fires, succeeds, writer recovers, evaluation proceeds.
        resp = _post_evaluate(c)
        assert resp.status_code in (200, 401, 403), (
            f"Expected normal evaluation after probe recovery, got {resp.status_code}: "
            f"{resp.json()}"
        )
        assert not writer.degraded  # confirmed recovery via probe


def test_fail_closed_still_blocks_when_probe_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Strict mode stays blocked when the probe write itself fails.

    If the audit backend has not recovered, the probe will fail, the writer
    remains degraded, and /v1/evaluate continues to return 503.
    """
    p = _write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", p)
    monkeypatch.setenv("AUDIT_FAIL_CLOSED", "true")
    reset_readiness_state()
    app = create_app()

    with TestClient(app, raise_server_exceptions=False) as c:
        from tests.conftest import MockVerifier

        app.state.verifier = MockVerifier(
            claims={
                "sub": "user1",
                "iss": "https://test.example.com",
                "preferred_username": "alice",
                "realm_access": {"roles": ["admin", "viewer"]},
                "iat": int(time.time()),
                "exp": int(time.time()) + 600,
            }
        )

        writer: GatewayAuditWriter = app.state.audit_writer

        # Degrade the writer and keep the inner writer failing.
        _degrade_writer(writer)
        # Inner writer still raises — backend has NOT recovered.

        # Multiple requests: probe fires each time, fails each time, 503 each time.
        for _ in range(3):
            resp = _post_evaluate(c)
            assert resp.status_code == 503
            assert "audit" in resp.json().get("message", "").lower()
        assert writer.degraded  # confirmed still degraded


def test_fail_closed_false_explicit_degraded_does_not_block_evaluate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AUDIT_FAIL_CLOSED=false explicitly: /v1/evaluate is NOT blocked."""
    p = _write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", p)
    monkeypatch.setenv("AUDIT_FAIL_CLOSED", "false")
    reset_readiness_state()
    app = create_app()

    with TestClient(app, raise_server_exceptions=False) as c:
        from tests.conftest import MockVerifier

        app.state.verifier = MockVerifier(
            claims={
                "sub": "user1",
                "iss": "https://test.example.com",
                "preferred_username": "alice",
                "realm_access": {"roles": ["admin", "viewer"]},
                "iat": int(time.time()),
                "exp": int(time.time()) + 600,
            }
        )

        writer: GatewayAuditWriter = app.state.audit_writer
        _degrade_writer(writer)

        # With fail-closed=false, evaluate proceeds normally
        resp = _post_evaluate(c)
        # Should NOT be 503 for audit degradation reason
        detail = resp.json().get("message", "")
        assert not (resp.status_code == 503 and "audit" in detail.lower())


# ---------------------------------------------------------------------------
# Existing components not broken
# ---------------------------------------------------------------------------


def test_existing_readiness_components_still_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All pre-existing readiness components are still present and correct."""
    p = _write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", p)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        body = c.get("/ready").json()
        assert body["status"] == "ready"
        components = body["components"]
        assert components["configuration_loaded"] is True
        assert components["policy_loaded"] is True
        assert components["evaluator_initialized"] is True
        assert components["audit_writer"] is True
