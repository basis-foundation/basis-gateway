"""Tests for configuration loading (config.py)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from basis_gateway.config import GatewayConfig


def test_default_config_loads():
    config = GatewayConfig()
    assert config.service_name == "basis-gateway"
    assert config.host == "0.0.0.0"
    assert config.port == 8000
    assert config.log_level == "INFO"
    assert config.environment == "local"


def test_env_override_port(monkeypatch):
    monkeypatch.setenv("PORT", "9000")
    config = GatewayConfig()
    assert config.port == 9000


def test_env_override_log_level(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "debug")
    config = GatewayConfig()
    assert config.log_level == "DEBUG"


def test_env_override_environment(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    config = GatewayConfig()
    assert config.environment == "production"


def test_env_override_service_name(monkeypatch):
    monkeypatch.setenv("SERVICE_NAME", "my-gateway")
    config = GatewayConfig()
    assert config.service_name == "my-gateway"


def test_invalid_log_level_raises():
    with pytest.raises(ValidationError, match="LOG_LEVEL"):
        GatewayConfig(log_level="VERBOSE")


def test_invalid_port_raises():
    with pytest.raises(ValidationError):
        GatewayConfig(port=99999)


def test_invalid_environment_raises():
    with pytest.raises(ValidationError):
        GatewayConfig(environment="unknown")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Audit failure escalation configuration
# ---------------------------------------------------------------------------


def test_default_audit_failure_threshold_is_10():
    config = GatewayConfig()
    assert config.audit_failure_threshold == 10


def test_env_override_audit_failure_threshold(monkeypatch):
    monkeypatch.setenv("AUDIT_FAILURE_THRESHOLD", "5")
    config = GatewayConfig()
    assert config.audit_failure_threshold == 5


def test_audit_failure_threshold_minimum_is_1(monkeypatch):
    monkeypatch.setenv("AUDIT_FAILURE_THRESHOLD", "1")
    config = GatewayConfig()
    assert config.audit_failure_threshold == 1


def test_audit_failure_threshold_zero_fails_validation(monkeypatch):
    monkeypatch.setenv("AUDIT_FAILURE_THRESHOLD", "0")
    with pytest.raises(ValidationError):
        GatewayConfig()


def test_audit_failure_threshold_negative_fails_validation(monkeypatch):
    monkeypatch.setenv("AUDIT_FAILURE_THRESHOLD", "-1")
    with pytest.raises(ValidationError):
        GatewayConfig()


def test_default_audit_fail_closed_is_false():
    config = GatewayConfig()
    assert config.audit_fail_closed is False


def test_env_audit_fail_closed_true(monkeypatch):
    monkeypatch.setenv("AUDIT_FAIL_CLOSED", "true")
    config = GatewayConfig()
    assert config.audit_fail_closed is True


def test_env_audit_fail_closed_false_explicit(monkeypatch):
    monkeypatch.setenv("AUDIT_FAIL_CLOSED", "false")
    config = GatewayConfig()
    assert config.audit_fail_closed is False


def test_env_audit_fail_closed_1(monkeypatch):
    monkeypatch.setenv("AUDIT_FAIL_CLOSED", "1")
    config = GatewayConfig()
    assert config.audit_fail_closed is True


def test_env_audit_fail_closed_yes(monkeypatch):
    monkeypatch.setenv("AUDIT_FAIL_CLOSED", "yes")
    config = GatewayConfig()
    assert config.audit_fail_closed is True
