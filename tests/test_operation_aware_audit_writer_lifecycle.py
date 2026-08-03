"""Early-failure lifecycle tests for the shared audit writer (PR 7 follow-up).

Proves the ordering fix in ``main.py``: the shared ``GatewayAuditWriter`` is
constructed at step 1b — immediately after configuration loads and the
operation-aware router registers — strictly *before* evaluation-config
validation (step 2), authentication initialization (step 3), v0.1 policy
loading (step 4), and operation-aware validation/evaluator construction
(step 6). Each test below fails one of those later steps deterministically
and locally (no network, no Docker, no live IdP) and asserts the writer
still exists on ``app.state`` and its readiness component is still ready.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from basis_gateway.audit.writer import GatewayAuditWriter
from basis_gateway.main import create_app
from basis_gateway.readiness import get_readiness_state, reset_readiness_state

VALID_BUNDLE: dict = {
    "bundle_id": "audit-writer-lifecycle-bundle",
    "bundle_version": "1.0.0",
    "schema_version": "1.0.0",
    "policy_owner": "test-owner",
    "rules": [{"rule_id": "rule-1", "effect": "allow", "match": {"actions": ["read:ahu"]}}],
}


def _write_bundle(tmp_path: Path, data: object, filename: str = "bundle.json") -> str:
    p = tmp_path / filename
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# Authentication initialization (step 3) fails; operation-aware enabled
# ---------------------------------------------------------------------------


def test_audit_writer_present_when_authentication_initialization_fails(
    monkeypatch, tmp_path
) -> None:
    """A deterministic, local, network-free authentication-configuration
    failure: BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON's one entry looks like a
    private key, which ``BasisLocalTokenTrustConfig`` rejects at
    construction time (step 3) — no JWKS fetch, no OIDC discovery, no
    external dependency of any kind. Step 2's presence check has already
    passed (issuer/audience/keys-json/policy_path are all non-empty), so
    this failure is specific to step 3, not step 2.
    """
    monkeypatch.setenv("AUTH_MODE", "basis_local_token")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_ISSUER", "https://identity.basis.example.com")
    monkeypatch.setenv("BASIS_LOCAL_TOKEN_AUDIENCE", "basis-gateway")
    monkeypatch.setenv(
        "BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON",
        json.dumps(
            {"key-1": "-----BEGIN PRIVATE KEY-----\nnotarealkey\n-----END PRIVATE KEY-----"}
        ),
    )
    # Required by validate_evaluation_config for basis_local_token mode; its
    # content is irrelevant here because step 3 raises before step 4 (policy
    # loading) is ever reached.
    monkeypatch.setenv("POLICY_PATH", str(tmp_path / "unused-policy.json"))
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    bundle_path = _write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", bundle_path)

    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        # Operation-aware route registration (step 1a) is unaffected by the
        # later step-3 failure.
        assert app.state.operation_aware_router_registered is True

        # The step 1b writer survives the step-3 failure.
        assert isinstance(app.state.audit_writer, GatewayAuditWriter)
        assert get_readiness_state().components.get("audit_writer") is True

        # Neither evaluator was reached (step 3 aborted startup before step
        # 4/5/6 ran).
        assert app.state.verifier is None
        assert app.state.basis_local_token_trust_config is None
        assert app.state.evaluator is None
        assert app.state.operation_aware_evaluator is None

        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503


# ---------------------------------------------------------------------------
# v0.1 policy loading (step 4) fails; both v0.1 and operation-aware enabled
# ---------------------------------------------------------------------------


def test_audit_writer_present_when_v01_policy_loading_fails_with_both_modes_enabled(
    monkeypatch, tmp_path
) -> None:
    """POLICY_PATH points at a nonexistent file (a deterministic, local
    ``PolicyLoadError`` at step 4) while operation-aware integration is
    enabled with a valid, present bundle. The writer was already
    constructed at step 1b — before step 4 ever ran — so it must survive
    this failure even though the v0.1 evaluator (step 5) and the
    operation-aware evaluator (step 6) are never reached.
    """
    monkeypatch.setenv("POLICY_PATH", str(tmp_path / "does-not-exist-policy.json"))
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    bundle_path = _write_bundle(tmp_path, VALID_BUNDLE)
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", bundle_path)

    reset_readiness_state()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        assert app.state.operation_aware_router_registered is True

        assert isinstance(app.state.audit_writer, GatewayAuditWriter)
        assert get_readiness_state().components.get("audit_writer") is True

        # Startup aborted at step 4 (policy loading) — neither evaluator was
        # constructed.
        assert app.state.evaluator is None
        assert app.state.operation_aware_evaluator is None
        assert get_readiness_state().components.get("policy_loaded") is False

        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503
