"""Unit tests for ``live_gateway_request_log_app.py`` -- the test-only ASGI
wrapper Phase 1B.3's real-NGINX live-gateway suite
(``test_producer_mtls_live_gateway.py``) uses in front of the real
``basis_gateway.main:app``.

These tests run without ``nginx``, without a subprocess, and without a Unix
socket -- they only need to prove the wrapper itself does what its docstring
promises: record method+path, never anything sensitive, and forward the
request/response unchanged. The real-NGINX suite is what proves the
end-to-end topology; this module is deliberately narrow.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from live_gateway_request_log_app import app as wrapped_app


@pytest.fixture()
def request_log_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    log_path = tmp_path / "requests.log"
    log_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("BASIS_TEST_REQUEST_LOG_PATH", str(log_path))
    return log_path


def _read_log(log_path: Path) -> list[str]:
    return [line for line in log_path.read_text(encoding="utf-8").splitlines() if line]


def test_one_request_produces_exactly_one_log_entry(request_log_path: Path) -> None:
    with TestClient(wrapped_app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert _read_log(request_log_path) == ["GET /health"]


def test_multiple_requests_produce_one_entry_each_in_order(request_log_path: Path) -> None:
    with TestClient(wrapped_app) as client:
        client.get("/health")
        client.get("/health")
        client.get("/ready")
    assert _read_log(request_log_path) == ["GET /health", "GET /health", "GET /ready"]


def test_response_is_unchanged_from_the_real_application(request_log_path: Path) -> None:
    from basis_gateway.main import app as real_app

    with TestClient(real_app) as real_client:
        real_response = real_client.get("/health")
    with TestClient(wrapped_app) as wrapped_client:
        wrapped_response = wrapped_client.get("/health")

    assert wrapped_response.status_code == real_response.status_code
    assert wrapped_response.json() == real_response.json()


def test_authorization_header_is_not_recorded(request_log_path: Path) -> None:
    with TestClient(wrapped_app) as client:
        client.get("/health", headers={"Authorization": "Bearer super-secret-token-value"})
    logged = _read_log(request_log_path)
    assert logged == ["GET /health"]
    assert "super-secret-token-value" not in "\n".join(logged)


def test_producer_certificate_header_is_not_recorded(request_log_path: Path) -> None:
    with TestClient(wrapped_app) as client:
        client.get(
            "/health",
            headers={"X-BASIS-Producer-Client-Cert": "-----BEGIN CERTIFICATE-----secret"},
        )
    logged = _read_log(request_log_path)
    assert logged == ["GET /health"]
    assert "CERTIFICATE" not in "\n".join(logged)


def test_request_body_is_not_recorded(request_log_path: Path) -> None:
    with TestClient(wrapped_app) as client:
        # /v1/evaluate/operation-aware is not registered in this test's
        # (unconfigured) app instance, so this is expected to 404 -- the
        # point is only that the body content never reaches the log file,
        # regardless of how the delegated-to real application handles it.
        client.post("/v1/evaluate/operation-aware", json={"action": "read:ahu-secret-resource"})
    logged = _read_log(request_log_path)
    assert logged == ["POST /v1/evaluate/operation-aware"]
    assert "read:ahu-secret-resource" not in "\n".join(logged)


def test_no_env_var_means_no_log_file_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("BASIS_TEST_REQUEST_LOG_PATH", raising=False)
    with TestClient(wrapped_app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert list(tmp_path.iterdir()) == []
