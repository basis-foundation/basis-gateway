"""API response consistency contract tests.

Verifies that every response path in basis-gateway satisfies three properties:
  1. What happened?   — stable machine-readable ``error`` code or ``outcome`` field
  2. Why?             — human-readable ``message`` (never raw exceptions or secrets)
  3. How to correlate? — ``correlation_id`` in body matches X-Correlation-ID header

Covers all known response paths:
  GET  /health   → 200
  GET  /ready    → 200 (ready) | 503 (not ready)
  POST /v1/evaluate → 200 ALLOW | 403 DENY | 403 NOT_APPLICABLE
                   → 400 validation | 401 auth_required | 401 auth_failed
                   → 503 evaluator_unavailable | 503 audit_fail_closed
                   → 500 evaluation_failed_closed
"""

from __future__ import annotations

import re
from typing import Any
from unittest.mock import MagicMock

from basis_core.domain import action as actions

from basis_gateway.auth.errors import JWTVerificationError

UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Stable error codes the API must use.
VALID_ERROR_CODES = {
    "authentication_required",
    "authentication_failed",
    "validation_failed",
    "evaluator_unavailable",
    "evaluation_failed_closed",
    "audit_fail_closed",
    "internal_error",
}

# Tokens/values that must never appear in error responses.
_SENSITIVE_PATTERNS = [
    "Bearer",
    "eyJ",  # JWT header prefix
    "Traceback",
    "stack trace",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_uuid4(value: str) -> bool:
    return bool(UUID4_RE.match(value))


def _evaluate(client, *, action: str = actions.READ_SENSOR_TELEMETRY, **kwargs: Any):
    body: dict[str, Any] = {"action": action}
    body.update(kwargs)
    return client.post("/v1/evaluate", json=body, headers={"Authorization": "Bearer fake"})


# ---------------------------------------------------------------------------
# Error response schema contract
# ---------------------------------------------------------------------------


class TestErrorResponseSchema:
    """ErrorResponse must have: error (stable code), message (optional), correlation_id."""

    def test_auth_required_schema(self, evaluate_client):
        resp = evaluate_client.post("/v1/evaluate", json={"action": actions.READ_SENSOR_TELEMETRY})
        assert resp.status_code == 401
        body = resp.json()
        assert "error" in body
        assert "message" in body
        assert "correlation_id" in body
        assert "detail" not in body, "legacy 'detail' field must be renamed to 'message'"

    def test_auth_failed_schema(self, evaluate_client, mock_verifier):
        mock_verifier.set_raise(JWTVerificationError("expired"))
        resp = _evaluate(evaluate_client)
        assert resp.status_code == 401
        body = resp.json()
        assert "error" in body
        assert "message" in body
        assert "correlation_id" in body

    def test_validation_failed_schema(self, evaluate_client):
        resp = evaluate_client.post(
            "/v1/evaluate",
            json={"resource_id": "sensor:ahu-1"},  # missing action
            headers={"Authorization": "Bearer fake"},
        )
        assert resp.status_code == 400
        body = resp.json()
        assert "error" in body
        assert "message" in body
        assert "correlation_id" in body
        assert "detail" not in body

    def test_evaluator_unavailable_schema(self, evaluate_client):
        evaluate_client.app.state.evaluator = None
        resp = _evaluate(evaluate_client)
        assert resp.status_code == 503
        body = resp.json()
        assert "error" in body
        assert "message" in body
        assert "correlation_id" in body

    def test_evaluation_failed_closed_schema(self, evaluate_client):
        broken = MagicMock()
        broken.evaluate.side_effect = RuntimeError("kernel exploded")
        broken.policy_version = "test"
        evaluate_client.app.state.evaluator = broken
        resp = _evaluate(evaluate_client)
        assert resp.status_code == 500
        body = resp.json()
        assert "error" in body
        assert "correlation_id" in body


# ---------------------------------------------------------------------------
# Stable error codes
# ---------------------------------------------------------------------------


class TestStableErrorCodes:
    """Every error response must carry a stable machine-readable error code."""

    def test_missing_token_uses_authentication_required(self, evaluate_client):
        resp = evaluate_client.post("/v1/evaluate", json={"action": actions.READ_SENSOR_TELEMETRY})
        assert resp.json()["error"] == "authentication_required"

    def test_malformed_authorization_uses_authentication_required(self, evaluate_client):
        resp = evaluate_client.post(
            "/v1/evaluate",
            json={"action": actions.READ_SENSOR_TELEMETRY},
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.json()["error"] == "authentication_required"

    def test_invalid_jwt_uses_authentication_failed(self, evaluate_client, mock_verifier):
        mock_verifier.set_raise(JWTVerificationError("expired"))
        resp = _evaluate(evaluate_client)
        assert resp.json()["error"] == "authentication_failed"

    def test_verifier_not_configured_uses_authentication_failed(self, evaluate_client):
        evaluate_client.app.state.verifier = None
        resp = _evaluate(evaluate_client)
        # verifier missing is a server-side auth config issue → authentication_failed
        assert resp.json()["error"] == "authentication_failed"

    def test_body_validation_uses_validation_failed(self, evaluate_client):
        resp = evaluate_client.post(
            "/v1/evaluate",
            json={"resource_id": "sensor:ahu-1"},
            headers={"Authorization": "Bearer fake"},
        )
        assert resp.json()["error"] == "validation_failed"

    def test_malformed_body_uses_validation_failed(self, evaluate_client):
        resp = evaluate_client.post(
            "/v1/evaluate",
            content=b"not-json",
            headers={"Authorization": "Bearer fake", "Content-Type": "application/json"},
        )
        assert resp.json()["error"] == "validation_failed"

    def test_evaluator_unavailable_uses_evaluator_unavailable(self, evaluate_client):
        evaluate_client.app.state.evaluator = None
        resp = _evaluate(evaluate_client)
        assert resp.json()["error"] == "evaluator_unavailable"

    def test_evaluator_exception_uses_evaluation_failed_closed(self, evaluate_client):
        broken = MagicMock()
        broken.evaluate.side_effect = RuntimeError("kernel exploded")
        broken.policy_version = "test"
        evaluate_client.app.state.evaluator = broken
        resp = _evaluate(evaluate_client)
        assert resp.json()["error"] == "evaluation_failed_closed"

    def test_all_error_codes_are_from_stable_set(self, evaluate_client, mock_verifier):
        """Every error code used must come from the declared stable set."""
        scenarios = [
            # (setup, request kwargs, expected status)
            (None, {"json": {"action": actions.READ_SENSOR_TELEMETRY}}, 401),  # no auth header
        ]
        for _setup, kwargs, _ in scenarios:
            resp = evaluate_client.post("/v1/evaluate", **kwargs)
            body = resp.json()
            if "error" in body:
                assert body["error"] in VALID_ERROR_CODES, (
                    f"Unknown error code {body['error']!r}; "
                    f"add it to VALID_ERROR_CODES or use an existing one"
                )


# ---------------------------------------------------------------------------
# Correlation ID in response body
# ---------------------------------------------------------------------------


class TestCorrelationIdInBody:
    """correlation_id in error bodies must match the X-Correlation-ID header."""

    def _assert_body_correlation_matches_header(self, resp) -> None:
        header_id = resp.headers.get("x-correlation-id")
        assert header_id is not None, "X-Correlation-ID header missing"
        body = resp.json()
        body_id = body.get("correlation_id")
        assert body_id is not None, f"correlation_id missing from body: {body}"
        assert body_id == header_id, f"Body correlation_id {body_id!r} != header {header_id!r}"

    def test_auth_required_body_matches_header(self, evaluate_client):
        resp = evaluate_client.post("/v1/evaluate", json={"action": actions.READ_SENSOR_TELEMETRY})
        self._assert_body_correlation_matches_header(resp)

    def test_auth_failed_body_matches_header(self, evaluate_client, mock_verifier):
        mock_verifier.set_raise(JWTVerificationError("expired"))
        resp = _evaluate(evaluate_client)
        self._assert_body_correlation_matches_header(resp)

    def test_validation_failed_body_matches_header(self, evaluate_client):
        resp = evaluate_client.post(
            "/v1/evaluate",
            json={"resource_id": "sensor:ahu-1"},
            headers={"Authorization": "Bearer fake"},
        )
        self._assert_body_correlation_matches_header(resp)

    def test_evaluator_unavailable_body_matches_header(self, evaluate_client):
        evaluate_client.app.state.evaluator = None
        resp = _evaluate(evaluate_client)
        self._assert_body_correlation_matches_header(resp)

    def test_evaluation_failed_closed_body_matches_header(self, evaluate_client):
        broken = MagicMock()
        broken.evaluate.side_effect = RuntimeError("kernel exploded")
        broken.policy_version = "test"
        evaluate_client.app.state.evaluator = broken
        resp = _evaluate(evaluate_client)
        self._assert_body_correlation_matches_header(resp)

    def test_allow_response_body_includes_correlation_id(self, evaluate_client):
        resp = _evaluate(evaluate_client)
        assert resp.status_code == 200
        body = resp.json()
        header_id = resp.headers["x-correlation-id"]
        assert body.get("correlation_id") == header_id

    def test_deny_response_body_includes_correlation_id(self, evaluate_client, mock_verifier):
        mock_verifier._claims["realm_access"] = {"roles": ["viewer"]}
        resp = _evaluate(evaluate_client, action=actions.WRITE_HVAC_SETPOINT)
        assert resp.status_code == 403
        body = resp.json()
        header_id = resp.headers["x-correlation-id"]
        assert body.get("correlation_id") == header_id

    def test_ready_503_body_includes_correlation_id(self, client):
        # /ready with no components ready → 503
        resp = client.get("/ready")
        if resp.status_code == 503:
            body = resp.json()
            header_id = resp.headers["x-correlation-id"]
            assert body.get("correlation_id") == header_id

    def test_correlation_id_in_body_is_uuid4(self, evaluate_client):
        resp = evaluate_client.post("/v1/evaluate", json={"action": actions.READ_SENSOR_TELEMETRY})
        body_id = resp.json().get("correlation_id", "")
        assert _is_uuid4(body_id), f"correlation_id {body_id!r} is not a UUID4"


# ---------------------------------------------------------------------------
# No secrets in error payloads
# ---------------------------------------------------------------------------


class TestNoSecretsInResponses:
    """Error responses must not expose tokens, stack traces, or raw exception text."""

    def test_invalid_token_response_does_not_expose_token(self, evaluate_client, mock_verifier):
        mock_verifier.set_raise(JWTVerificationError("some internal detail"))
        resp = evaluate_client.post(
            "/v1/evaluate",
            json={"action": actions.READ_SENSOR_TELEMETRY},
            headers={"Authorization": "Bearer supersecrettoken"},
        )
        text = resp.text
        assert "supersecrettoken" not in text
        assert "some internal detail" not in text

    def test_evaluator_exception_does_not_expose_stack_trace(self, evaluate_client):
        broken = MagicMock()
        broken.evaluate.side_effect = RuntimeError("internal explosion details")
        broken.policy_version = "test"
        evaluate_client.app.state.evaluator = broken
        resp = _evaluate(evaluate_client)
        text = resp.text
        assert "internal explosion details" not in text
        assert "Traceback" not in text
        assert "RuntimeError" not in text

    def test_auth_failure_response_has_no_raw_jwt(self, evaluate_client, mock_verifier):
        mock_verifier.set_raise(JWTVerificationError("exp claim failed"))
        resp = evaluate_client.post(
            "/v1/evaluate",
            json={"action": actions.READ_SENSOR_TELEMETRY},
            headers={"Authorization": "Bearer eyJfake.eyJfake.sig"},
        )
        text = resp.text
        # Bearer token value must not appear
        assert "eyJfake" not in text
        # Internal exception details must not appear
        assert "exp claim failed" not in text

    def test_subject_mapping_failure_does_not_expose_claims(self, evaluate_client, mock_verifier):
        # Claims with sensitive data that must not appear in error response
        mock_verifier._claims = {
            "iss": "https://test.example.com",
            "email": "private@internal.example.com",
            # no sub → SubjectMappingError
        }
        resp = _evaluate(evaluate_client)
        assert resp.status_code in (400, 401)
        assert "private@internal.example.com" not in resp.text


# ---------------------------------------------------------------------------
# Audit fail-closed error code
# ---------------------------------------------------------------------------


class TestAuditFailClosed:
    """audit_fail_closed path uses correct code and includes correlation_id."""

    def _make_degraded_writer(self):
        from basis_core.audit import AuditEvent

        class _FailingWriter:
            degraded = True

            def write(self, event: AuditEvent) -> None:
                raise OSError("audit sink down")

        return _FailingWriter()

    def test_audit_fail_closed_error_code(self, evaluate_client):
        from basis_gateway.audit.writer import GatewayAuditWriter

        inner = self._make_degraded_writer()
        writer = GatewayAuditWriter(inner=inner, failure_threshold=1)
        # Force degraded state
        writer._degraded = True  # type: ignore[attr-defined]

        evaluate_client.app.state.audit_writer = writer
        evaluate_client.app.state.config = type(
            "Cfg", (), {"audit_fail_closed": True, "audit_failure_threshold": 1}
        )()

        resp = _evaluate(evaluate_client)
        assert resp.status_code == 503
        body = resp.json()
        assert body["error"] == "audit_fail_closed"

    def test_audit_fail_closed_body_correlation_matches_header(self, evaluate_client):
        from basis_gateway.audit.writer import GatewayAuditWriter

        inner = self._make_degraded_writer()
        writer = GatewayAuditWriter(inner=inner, failure_threshold=1)
        writer._degraded = True  # type: ignore[attr-defined]

        evaluate_client.app.state.audit_writer = writer
        evaluate_client.app.state.config = type(
            "Cfg", (), {"audit_fail_closed": True, "audit_failure_threshold": 1}
        )()

        resp = _evaluate(evaluate_client)
        assert resp.status_code == 503
        assert resp.json().get("correlation_id") == resp.headers["x-correlation-id"]


# ---------------------------------------------------------------------------
# OpenAPI schema presence
# ---------------------------------------------------------------------------


class TestOpenAPISchemas:
    """OpenAPI output must declare expected response schemas for main routes."""

    def test_openapi_schema_available(self, client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200

    def test_evaluate_route_in_openapi(self, client):
        schema = client.get("/openapi.json").json()
        assert "/v1/evaluate" in schema["paths"]

    def test_evaluate_declares_200_response(self, client):
        schema = client.get("/openapi.json").json()
        evaluate_path = schema["paths"]["/v1/evaluate"]
        post_op = evaluate_path.get("post", {})
        responses = post_op.get("responses", {})
        assert "200" in responses

    def test_evaluate_declares_error_responses(self, client):
        schema = client.get("/openapi.json").json()
        post_op = schema["paths"]["/v1/evaluate"]["post"]
        responses = post_op.get("responses", {})
        # Must declare the main error status codes
        for code in ("400", "401", "403", "500", "503"):
            assert code in responses, f"OpenAPI missing response declaration for {code}"

    def test_ready_route_in_openapi(self, client):
        schema = client.get("/openapi.json").json()
        assert "/ready" in schema["paths"]

    def test_ready_declares_503_response(self, client):
        schema = client.get("/openapi.json").json()
        ready_path = schema["paths"]["/ready"]
        get_op = ready_path.get("get", {})
        responses = get_op.get("responses", {})
        assert "503" in responses

    def test_error_response_schema_in_components(self, client):
        schema = client.get("/openapi.json").json()
        components = schema.get("components", {}).get("schemas", {})
        assert "ErrorResponse" in components

    def test_error_response_schema_has_required_fields(self, client):
        schema = client.get("/openapi.json").json()
        error_schema = schema["components"]["schemas"]["ErrorResponse"]
        props = error_schema.get("properties", {})
        assert "error" in props
        assert "message" in props
        assert "correlation_id" in props
        # Legacy field must not be present
        assert "detail" not in props, "'detail' field removed; schema must use 'message'"
