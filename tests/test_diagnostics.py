"""Operational diagnostics tests for basis-gateway.

Covers:
  - /ready includes per-component reasons when degraded
  - /ready includes multi-reason map when multiple components are degraded
  - invalid configuration produces a clear validation failure with actionable detail
  - audit writer degraded appears in /ready readiness response
  - strict audit fail-closed returns 503 with a clear error message
  - no secrets are exposed in diagnostic responses
  - startup logs show expected milestones (via caplog)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from basis_gateway.audit.writer import GatewayAuditWriter
from basis_gateway.config import EvaluationConfigError, GatewayConfig, validate_evaluation_config
from basis_gateway.main import create_app
from basis_gateway.readiness import ReadinessState, get_readiness_state, reset_readiness_state

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_policy(tmp_path: Path) -> str:
    data = {
        "rules": [
            {
                "rule_name": "rbac",
                "role_table": {"read:sensor:telemetry": ["viewer", "admin"]},
            }
        ]
    }
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# /ready includes degraded component reasons
# ---------------------------------------------------------------------------


def test_ready_not_ready_includes_reason_for_degraded_component(client):
    """reason field describes the failing component, not a generic message."""
    get_readiness_state().mark_not_ready(
        "Policy file not found: '/etc/basis/policy.json'",
        component="policy_loaded",
    )
    response = client.get("/ready")
    assert response.status_code == 503
    body = response.json()
    assert "reason" in body
    assert "policy" in body["reason"].lower() or "Policy" in body["reason"]


def test_ready_not_ready_includes_reasons_dict(client):
    """reasons dict maps every degraded component to its reason."""
    state = get_readiness_state()
    state.mark_not_ready("OIDC discovery failed", component="oidc_configured")
    state.mark_not_ready("JWKS endpoint unreachable", component="jwks_available")
    response = client.get("/ready")
    assert response.status_code == 503
    body = response.json()
    assert "reasons" in body
    assert body["reasons"]["oidc_configured"] == "OIDC discovery failed"
    assert body["reasons"]["jwks_available"] == "JWKS endpoint unreachable"


def test_ready_reasons_omitted_when_ready(client):
    """`reasons` is absent from the response when the service is fully ready."""
    response = client.get("/ready")
    assert response.status_code == 200
    body = response.json()
    assert "reasons" not in body


def test_ready_not_ready_single_component_has_reasons_dict(client):
    """Even a single degraded component produces a reasons dict."""
    get_readiness_state().mark_not_ready("evaluator init failed", component="evaluator_initialized")
    body = client.get("/ready").json()
    assert "reasons" in body
    assert "evaluator_initialized" in body["reasons"]
    assert body["reasons"]["evaluator_initialized"] == "evaluator init failed"


# ---------------------------------------------------------------------------
# Multi-reason: reasons dict contains all failing components
# ---------------------------------------------------------------------------


def test_ready_reasons_dict_contains_all_failing_components(client):
    """All degraded components appear in the reasons dict, not just the first."""
    state = get_readiness_state()
    state.mark_ready("configuration_loaded")
    state.mark_not_ready("policy file missing", component="policy_loaded")
    state.mark_not_ready("evaluator not built", component="evaluator_initialized")
    body = client.get("/ready").json()
    assert set(body["reasons"].keys()) == {"policy_loaded", "evaluator_initialized"}


def test_ready_components_map_reflects_mixed_state(client):
    """components shows true for ready and false for not-ready entries."""
    state = get_readiness_state()
    state.mark_ready("configuration_loaded")
    state.mark_not_ready("policy load error", component="policy_loaded")
    body = client.get("/ready").json()
    assert body["components"]["configuration_loaded"] is True
    assert body["components"]["policy_loaded"] is False


# ---------------------------------------------------------------------------
# Configuration validation: clear failure messages
# ---------------------------------------------------------------------------


def test_validate_evaluation_config_oidc_without_policy_names_missing_var():
    """Error message specifically names POLICY_PATH as the missing variable."""
    config = GatewayConfig(oidc_issuer="https://idp.example.com")
    with pytest.raises(EvaluationConfigError) as exc_info:
        validate_evaluation_config(config)
    assert "POLICY_PATH" in str(exc_info.value)


def test_startup_oidc_without_policy_path_ready_reason_names_policy_path(monkeypatch):
    """When startup fails due to missing POLICY_PATH, /ready reason mentions it."""
    monkeypatch.setenv("OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.delenv("POLICY_PATH", raising=False)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        body = c.get("/ready").json()
    assert "POLICY_PATH" in body.get("reason", "")


def test_startup_missing_policy_file_reason_is_actionable(tmp_path, monkeypatch):
    """Missing policy file reason tells operator what to fix."""
    missing = str(tmp_path / "nonexistent.json")
    monkeypatch.setenv("POLICY_PATH", missing)
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        body = c.get("/ready").json()
    reason = body.get("reason", "")
    # Reason should name the file and direct the operator
    assert "nonexistent.json" in reason or "not found" in reason.lower()


# ---------------------------------------------------------------------------
# Audit writer degraded in readiness response
# ---------------------------------------------------------------------------


def test_ready_shows_audit_writer_degraded(client):
    """When audit_writer is degraded, /ready shows it as false in components."""
    get_readiness_state().mark_ready("audit_writer")  # start healthy
    get_readiness_state().mark_not_ready(
        "Audit write failures exceeded threshold (10 consecutive failures)",
        component="audit_writer",
    )
    response = client.get("/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["components"].get("audit_writer") is False
    assert "audit_writer" in body.get("reasons", {})


def test_ready_audit_writer_degraded_reason_is_informative(client):
    """The audit_writer degradation reason mentions the failure count."""
    get_readiness_state().mark_not_ready(
        "Audit write failures exceeded threshold (5 consecutive failures)",
        component="audit_writer",
    )
    body = client.get("/ready").json()
    reason = body["reasons"]["audit_writer"]
    assert "threshold" in reason.lower() or "consecutive" in reason.lower()


def test_gateway_audit_writer_marks_readiness_not_ready_after_threshold():
    """GatewayAuditWriter marks readiness not-ready when threshold is crossed."""
    from basis_core.audit import AuditEvent

    class _FailingWriter:
        def write(self, event: AuditEvent) -> None:
            raise OSError("sink unavailable")

    state = ReadinessState()
    state.mark_ready("audit_writer")
    writer = GatewayAuditWriter(
        inner=_FailingWriter(),
        readiness_state=state,
        failure_threshold=3,
    )
    event = MagicMock(spec=AuditEvent)

    writer.write(event)
    writer.write(event)
    assert state.is_ready, "should still be ready before threshold"

    writer.write(event)  # crosses threshold
    assert not state.is_ready
    assert state.components.get("audit_writer") is False


def test_gateway_audit_writer_recovers_after_successful_write():
    """A successful write after degradation restores readiness."""
    from basis_core.audit import AuditEvent

    fail = True

    class _ConditionalWriter:
        def write(self, event: AuditEvent) -> None:
            if fail:
                raise OSError("down")

    state = ReadinessState()
    state.mark_ready("audit_writer")
    writer = GatewayAuditWriter(
        inner=_ConditionalWriter(),
        readiness_state=state,
        failure_threshold=2,
    )
    event = MagicMock(spec=AuditEvent)

    writer.write(event)
    writer.write(event)  # crosses threshold; writer now degraded
    assert not state.is_ready

    fail = False  # noqa: F841 — conditionally makes writer succeed
    writer.write(event)
    assert state.is_ready


# ---------------------------------------------------------------------------
# Strict audit fail-closed: clear 503 with informative message
# ---------------------------------------------------------------------------


def test_fail_closed_503_message_is_clear(evaluate_client):
    """When fail-closed and audit writer is degraded, 503 message explains why."""
    from basis_core.audit import AuditEvent

    class _FailingInner:
        def write(self, event: AuditEvent) -> None:
            raise OSError("down")

    # Install a degraded GatewayAuditWriter with fail-closed mode
    writer = GatewayAuditWriter(inner=_FailingInner(), failure_threshold=1)
    # Force it into degraded state
    event = MagicMock(spec=AuditEvent)
    writer.write(event)  # crosses threshold=1
    assert writer.degraded

    evaluate_client.app.state.audit_writer = writer
    # Patch config to enable fail-closed mode
    cfg = MagicMock()
    cfg.audit_fail_closed = True
    evaluate_client.app.state.config = cfg

    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": "read:sensor:telemetry", "resource_id": "sensor:ahu-1"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 503
    body = resp.json()
    # Message must explain the situation clearly
    message = body.get("message", "").lower()
    assert "audit" in message or "degraded" in message
    assert "fail-closed" in message or "suspended" in message


def test_fail_closed_503_does_not_expose_secrets(evaluate_client):
    """Fail-closed 503 response contains no sensitive content."""
    from basis_core.audit import AuditEvent

    class _FailingInner:
        def write(self, event: AuditEvent) -> None:
            raise OSError("down")

    writer = GatewayAuditWriter(inner=_FailingInner(), failure_threshold=1)
    event = MagicMock(spec=AuditEvent)
    writer.write(event)

    evaluate_client.app.state.audit_writer = writer
    cfg = MagicMock()
    cfg.audit_fail_closed = True
    evaluate_client.app.state.config = cfg

    resp = evaluate_client.post(
        "/v1/evaluate",
        json={"action": "read:sensor:telemetry", "resource_id": "sensor:ahu-1"},
        headers={"Authorization": "Bearer super-secret-token"},
    )
    raw = resp.text
    assert "super-secret-token" not in raw
    assert "Bearer" not in raw


# ---------------------------------------------------------------------------
# No secrets in diagnostic responses
# ---------------------------------------------------------------------------


def test_ready_response_does_not_expose_secrets(client):
    """The /ready response never leaks tokens, secrets, or credentials."""
    get_readiness_state().mark_not_ready(
        "OIDC discovery failed for issuer 'https://idp.example.com'",
        component="oidc_configured",
    )
    body = client.get("/ready").json()
    raw = json.dumps(body)
    # No Authorization header values, JWT patterns, or secret-like tokens
    assert "Bearer" not in raw
    assert "eyJ" not in raw  # JWT prefix pattern
    assert "secret" not in raw.lower()


def test_startup_failure_response_does_not_expose_internal_paths(tmp_path, monkeypatch):
    """/ready failure reason may include a file path but no internal stack or secrets."""
    sensitive_name = tmp_path / "missing-policy.json"
    monkeypatch.setenv("POLICY_PATH", str(sensitive_name))
    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        body = c.get("/ready").json()
    raw = json.dumps(body)
    # Should not contain stack trace fragments
    assert "Traceback" not in raw
    assert "File " not in raw
    # Should not contain secret-like content
    assert "password" not in raw.lower()
    assert "token" not in raw.lower()


# ---------------------------------------------------------------------------
# Startup diagnostic logging milestones
# ---------------------------------------------------------------------------


def test_startup_logs_configuration_loaded(tmp_path, monkeypatch, caplog):
    """Startup emits a 'Configuration loaded' info log."""
    monkeypatch.setenv("POLICY_PATH", write_policy(tmp_path))
    reset_readiness_state()
    with caplog.at_level(logging.INFO, logger="basis_gateway.main"):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True):
            pass
    messages = [r.message for r in caplog.records]
    assert any("Configuration loaded" in m for m in messages)


def test_startup_logs_gateway_ready(tmp_path, monkeypatch, caplog):
    """Startup emits a 'basis-gateway ready' log when all components initialize."""
    monkeypatch.setenv("POLICY_PATH", write_policy(tmp_path))
    reset_readiness_state()
    with caplog.at_level(logging.INFO, logger="basis_gateway.main"):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True):
            pass
    messages = [r.message for r in caplog.records]
    assert any("basis-gateway ready" in m for m in messages)


def test_startup_logs_audit_writer_initialized(tmp_path, monkeypatch, caplog):
    """Startup emits an 'Audit writer initialized' log including the threshold."""
    monkeypatch.setenv("POLICY_PATH", write_policy(tmp_path))
    monkeypatch.setenv("AUDIT_FAILURE_THRESHOLD", "7")
    reset_readiness_state()
    with caplog.at_level(logging.INFO, logger="basis_gateway.main"):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True):
            pass
    messages = [r.message for r in caplog.records]
    assert any("Audit writer initialized" in m for m in messages)
    assert any("threshold=7" in m for m in messages)


def test_startup_logs_policy_loading_milestone(tmp_path, monkeypatch, caplog):
    """Startup emits a 'Loading policy from ...' log before loading the file."""
    policy_path = write_policy(tmp_path)
    monkeypatch.setenv("POLICY_PATH", policy_path)
    reset_readiness_state()
    with caplog.at_level(logging.INFO, logger="basis_gateway.main"):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True):
            pass
    messages = [r.message for r in caplog.records]
    assert any("Loading policy from" in m for m in messages)


def test_startup_failure_log_includes_exception_type(monkeypatch, caplog):
    """When startup fails, the error log includes the exception class name."""
    monkeypatch.setenv("OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.delenv("POLICY_PATH", raising=False)
    reset_readiness_state()
    with caplog.at_level(logging.ERROR, logger="basis_gateway.main"):
        app = create_app()
        with TestClient(app, raise_server_exceptions=False):
            pass
    error_messages = [r.message for r in caplog.records if r.levelno >= logging.ERROR]
    # At least one error log should include the exception class in brackets
    assert any("[" in m and "]" in m for m in error_messages)


def test_startup_oidc_not_set_warning_is_actionable(monkeypatch, caplog):
    """When OIDC_ISSUER is not set, the warning tells the operator what to do."""
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.delenv("POLICY_PATH", raising=False)
    reset_readiness_state()
    with caplog.at_level(logging.WARNING, logger="basis_gateway.main"):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True):
            pass
    warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("OIDC_ISSUER" in m for m in warning_messages)
