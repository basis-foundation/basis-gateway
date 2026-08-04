#!/usr/bin/env python3
"""Bounded, reproducible, offline demonstration of the operation-aware gateway path.

See ``demo/operation-aware/README.md`` for the full narrative. This script exercises
the *real* ``basis-gateway`` FastAPI application
(``basis_gateway.main.create_app()``), through its real ASGI lifespan, over the real
HTTP route ``POST /v1/evaluate/operation-aware``:

    signed BASIS-local identity token
        -> real Bearer-token authentication (AUTH_MODE=basis_local_token)
        -> operation-producer trust classification
        -> request validation and composition
        -> field-level provenance
        -> the real public basis-core OperationAwareEnforcementPoint
        -> HTTP enforcement classification
        -> GatewayAuditEvent + AuditEvidence
        -> readiness diagnostics

It does not call route functions directly, does not bypass authentication or
authorization, does not mock the kernel result, and does not patch the HTTP
classifier or audit assembly. The only thing swapped after startup is the audit
writer's innermost log sink (see ``_CapturingSink`` below) -- the exact pattern
already used by this repository's own tests -- so this script can display the
real audit record instead of only writing it to the process log.

Usage:
    python demo/operation-aware/run_demo.py
    python demo/operation-aware/run_demo.py --scenario allow
    python demo/operation-aware/run_demo.py --json

Requires this repository's normal development installation (``pip install -e
../basis-core && pip install -e ".[dev]"`` -- see the top-level README's "Local
setup"). No network access, no live identity provider, no Docker, no external
secrets. See ``demo/operation-aware/README.md``'s "Safety" section.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEMO_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEMO_DIR.parent.parent
_SRC = REPO_ROOT / "src"
if str(_SRC) not in sys.path and _SRC.is_dir():
    # Allow running this script directly from a checkout that has not been
    # `pip install -e`'d yet, matching the repository's own "Local setup"
    # instructions as closely as possible without requiring it.
    sys.path.insert(0, str(_SRC))

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from fastapi.testclient import TestClient
except ImportError as exc:  # pragma: no cover - environment guidance only
    print(
        "This demo requires the repository's development installation "
        '(pip install -e ../basis-core && pip install -e ".[dev]"). '
        f"Missing dependency: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc

from basis_gateway.audit.operation_aware_gateway_events import (  # noqa: E402
    AUTHORIZATION_COMPLETED,
)
from basis_gateway.main import create_app  # noqa: E402
from basis_gateway.readiness import reset_readiness_state  # noqa: E402

# ---------------------------------------------------------------------------
# Synthetic, non-resolvable demonstration identity values.
# ---------------------------------------------------------------------------
# ".invalid" per RFC 2606 -- guaranteed never to resolve. No live issuer, no
# JWKS endpoint, no network call is ever made to these values; they exist only
# as claims inside locally-signed, locally-verified tokens.
ISSUER = "https://identity.demo.basis.invalid"
AUDIENCE = "basis-gateway-demo"
KID = "demo-key-1"
TRUSTED_PRODUCER_SUBJECT = "adapter-demo-1"
OPERATOR_SUBJECT = "operator-demo-1"

VALID_BUNDLE_PATH = DEMO_DIR / "policy-bundles" / "operation-aware-demo-bundle.json"
INVALID_BUNDLE_PATH = DEMO_DIR / "policy-bundles" / "operation-aware-invalid-bundle.json"
EXPECTED_SUMMARY_PATH = DEMO_DIR / "expected" / "scenario-summary.json"

OA_PATH = "/v1/evaluate/operation-aware"

SCENARIO_ORDER: tuple[str, ...] = (
    "allow",
    "explicit-deny",
    "default-deny",
    "not-applicable",
    "untrusted-producer",
    "semantic-startup-failure",
)

_READINESS_COMPONENTS_TO_SHOW: tuple[str, ...] = (
    "configuration_loaded",
    "basis_local_token_configured",
    "audit_writer",
    "operation_aware_mode_enabled",
    "operation_aware_bundle_loaded",
    "operation_aware_evaluator_initialized",
    "operation_aware_policy_semantically_valid",
)

_OPERATION_AWARE_COMPONENTS: tuple[str, ...] = (
    "operation_aware_mode_enabled",
    "operation_aware_bundle_loaded",
    "operation_aware_evaluator_initialized",
    "operation_aware_policy_semantically_valid",
)

_DISPLAYED_PROVENANCE_KEYS: tuple[str, ...] = (
    "action",
    "resource_id",
    "resource_type",
    "operation_producer_subject_id",
    "operation_producer_trust",
)


# ---------------------------------------------------------------------------
# Ephemeral signing material -- generated in memory, never written to disk,
# never printed, never reused across runs.
# ---------------------------------------------------------------------------


def _generate_rsa_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _public_pem(key: RSAPrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


def issue_demo_token(
    private_key: RSAPrivateKey,
    *,
    subject_id: str,
    roles: tuple[str, ...] = (),
) -> str:
    """Issue a signed, demonstration-only BASIS-local identity token.

    Mirrors the real BASIS-local token claim shape this repository's own
    ``AUTH_MODE=basis_local_token`` tests use (see
    ``tests/test_auth_mode_evaluate.py``), submitted through the real
    ``Authorization: Bearer ...`` header and verified by the real gateway
    authentication dispatch (``basis_gateway.auth.runtime.authenticate``).
    Claims are deterministic except for the RS256 signature bytes themselves
    and the per-call ``jti``/timestamps. The subject's identity is derived
    from this token only -- never from a request body.
    """
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": subject_id,
        "aud": [AUDIENCE],
        "iat": now,
        "exp": now + 600,
        "jti": f"demo-{uuid.uuid4()}",
        "typ": "basis-local-identity",
        "basis": {
            "session_id": f"demo-session-{subject_id}",
            "provider_id": "basis-identity-demo",
            "authority_mode": "standalone",
            "authentication_protocol": "demo-local",
            "canonical_identity": {
                "subject": {
                    "subject_id": subject_id,
                    "roles": list(roles),
                    "display_name": subject_id,
                },
            },
        },
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": KID})


def redact_token(token: str) -> str:
    """Never print a full token. Kept for callers that want a bounded,
    non-reversible correlation hint only; unused by this script's own output,
    which never prints a bearer header or token at all."""
    if len(token) <= 16:
        return "<redacted>"
    return f"{token[:6]}...{token[-6:]} (redacted)"


# ---------------------------------------------------------------------------
# Capturing audit sink -- injected UNDER the real GatewayAuditWriter after
# startup, mirroring the pattern already established by this repository's own
# tests (tests/test_operation_aware_endpoint_audit.py's _CapturingWriter).
# The real GatewayAuditWriter (failure tracking, readiness integration,
# threshold/degraded-state behavior) is completely untouched -- only its
# innermost delegate (normally basis_core.audit.LogAuditWriter) is swapped so
# this script can read back the exact AuditEvent objects the real audit
# assembly produced, instead of only writing them to the process log.
#
# ``GatewayAuditWriter._inner`` is an internal attribute, not a public API
# or a supported production plugin interface. This demo and the repository's
# own tests are the only sanctioned callers of this pattern; no new
# extension point is introduced by this file.
# ---------------------------------------------------------------------------


class _CapturingSink:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def write(self, event: Any) -> None:
        self.events.append(event)


@dataclass
class DemoApp:
    client: TestClient
    sink: _CapturingSink

    def close(self) -> None:
        self.client.__exit__(None, None, None)


_ENV_KEYS: tuple[str, ...] = (
    "AUTH_MODE",
    "OIDC_ISSUER",
    "LOG_LEVEL",
    "BASIS_LOCAL_TOKEN_ISSUER",
    "BASIS_LOCAL_TOKEN_AUDIENCE",
    "BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON",
    "BASIS_LOCAL_TOKEN_ALLOWED_ALGORITHMS",
    "POLICY_PATH",
    "OPERATION_AWARE_ENABLED",
    "OPERATION_AWARE_POLICY_BUNDLE_PATH",
    "OPERATION_PRODUCER_SUBJECT_IDS",
)


@contextlib.contextmanager
def _demo_environment(
    *, bundle_path: Path, v01_policy_path: Path, public_key_pem: str
) -> Iterator[None]:
    """Set the real gateway environment variables for the duration of the
    block, restoring whatever was previously set on exit.

    Uses the real ``AUTH_MODE=basis_local_token`` path so this demonstration
    never requires OIDC discovery or a live JWKS endpoint. Every variable set
    here is a real, documented ``GatewayConfig`` environment variable (see
    ``docs/configuration.md``) -- nothing gateway-specific is bypassed or
    invented for this demo.
    """
    saved = {key: os.environ.get(key) for key in _ENV_KEYS}
    try:
        os.environ["AUTH_MODE"] = "basis_local_token"
        os.environ.pop("OIDC_ISSUER", None)
        # Keep startup logs quiet by default so the demo's own formatted
        # output is the visible signal; expected failures (the semantic
        # preflight in the invalid-bundle scenario) still log at ERROR.
        os.environ.setdefault("LOG_LEVEL", "WARNING")
        os.environ["BASIS_LOCAL_TOKEN_ISSUER"] = ISSUER
        os.environ["BASIS_LOCAL_TOKEN_AUDIENCE"] = AUDIENCE
        os.environ["BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON"] = json.dumps({KID: public_key_pem})
        os.environ["BASIS_LOCAL_TOKEN_ALLOWED_ALGORITHMS"] = "RS256"
        os.environ["POLICY_PATH"] = str(v01_policy_path)
        os.environ["OPERATION_AWARE_ENABLED"] = "true"
        os.environ["OPERATION_AWARE_POLICY_BUNDLE_PATH"] = str(bundle_path)
        os.environ["OPERATION_PRODUCER_SUBJECT_IDS"] = TRUSTED_PRODUCER_SUBJECT
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def build_demo_app(*, bundle_path: Path, v01_policy_path: Path, public_key_pem: str) -> DemoApp:
    """Build and start a real gateway application instance for this demo.

    Exercises the real ``basis_gateway.main.create_app()`` and its real ASGI
    lifespan (via ``fastapi.testclient.TestClient`` as a context manager --
    part of this repository's own development/test dependencies). Route
    functions are never called directly; middleware and authentication are
    never bypassed.
    """
    with _demo_environment(
        bundle_path=bundle_path, v01_policy_path=v01_policy_path, public_key_pem=public_key_pem
    ):
        reset_readiness_state()
        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)
        client.__enter__()  # runs the real lifespan startup, under the env above

    sink = _CapturingSink()
    if app.state.audit_writer is not None:
        # Demonstration-only: swap the real GatewayAuditWriter's innermost
        # delegate so this script can read back the real audit records.
        # GatewayAuditWriter itself -- failure counting, readiness
        # degradation/recovery -- is untouched. ``_inner`` is an internal
        # attribute (not a public API or supported plugin interface); this
        # assignment mirrors the existing test-only pattern and does not
        # introduce a new production extension point.
        app.state.audit_writer._inner = sink  # noqa: SLF001 - mirrors existing test pattern
    return DemoApp(client=client, sink=sink)


def _write_v01_policy(tmp_dir: Path) -> Path:
    """Write the minimal v0.1 role-table policy this demo's AUTH_MODE=
    basis_local_token configuration requires at startup (``POLICY_PATH`` is a
    required, unrelated startup dependency of that auth mode -- see
    ``basis_gateway.config.validate_evaluation_config``). This demo never
    calls ``POST /v1/evaluate`` (the v0.1 endpoint); only
    ``POST /v1/evaluate/operation-aware`` is exercised.
    """
    path = tmp_dir / "v01-role-table.json"
    path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "rule_name": "demo-unused-v01-policy",
                        "role_table": {"read:sensor:telemetry": ["operator"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# Scenario reporting
# ---------------------------------------------------------------------------


@dataclass
class ScenarioReport:
    name: str
    passed: bool
    lines: list[str]
    details: dict[str, Any] = field(default_factory=dict)
    mismatches: list[str] = field(default_factory=list)


def _decode_json(resp: Any) -> dict[str, Any]:
    try:
        return dict(resp.json())
    except Exception:
        return {}


def _compare(actual: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    mismatches = []
    for key, expected_value in expected.items():
        actual_value = actual.get(key)
        if actual_value != expected_value:
            mismatches.append(f"{key}: expected {expected_value!r}, got {actual_value!r}")
    return mismatches


def _post_oa(client: TestClient, token: str, body: dict[str, Any]) -> Any:
    return client.post(OA_PATH, json=body, headers={"Authorization": f"Bearer {token}"})


def _bundle_label(bundle_id: str | None, bundle_version: str | None) -> str:
    if bundle_id is None:
        return "(none)"
    if bundle_version is None:
        return bundle_id
    return f"{bundle_id}@{bundle_version}"


def _display_provenance(provenance: dict[str, str] | None) -> str:
    if not provenance:
        return "(none)"
    parts = [f"{key}={provenance[key]}" for key in _DISPLAYED_PROVENANCE_KEYS if key in provenance]
    return ", ".join(parts) if parts else "(none)"


def _format_block(title: str, rows: list[tuple[str, str]]) -> list[str]:
    lines = [title]
    for label, value in rows:
        lines.append(f"  {label:<22}{value}")
    return lines


def run_completed_scenario(
    *,
    name: str,
    app: DemoApp,
    subject_id: str,
    token: str,
    action_verb: str,
    resource_type: str,
    resource_id: str,
    expected: dict[str, Any],
    explanation: list[str],
) -> ScenarioReport:
    """Run one of the four scenarios expected to reach a completed kernel
    evaluation (allow / explicit-deny / default-deny / not-applicable)."""
    body = {"action": action_verb, "resource_type": resource_type, "resource_id": resource_id}
    before = len(app.sink.events)
    resp = _post_oa(app.client, token, body)
    payload = _decode_json(resp)
    new_events = app.sink.events[before:]

    actual = {
        "http_status": resp.status_code,
        "evaluation_status": payload.get("evaluation_status"),
        "outcome": payload.get("outcome"),
        "disposition": payload.get("disposition"),
    }
    mismatches = _compare(actual, expected)

    completed = [e for e in new_events if getattr(e, "action", None) == AUTHORIZATION_COMPLETED]
    gw_event: dict[str, Any] | None = None
    evidence: dict[str, Any] | None = None
    provenance: dict[str, str] | None = None
    if len(completed) != 1:
        mismatches.append(f"expected exactly one completed audit record, got {len(completed)}")
    else:
        detail = completed[0].detail
        gw_event = detail.get("gateway_audit_event")
        evidence = detail.get("audit_evidence")
        provenance = detail.get("provenance")
        if gw_event is None or evidence is None:
            mismatches.append(
                "completed audit record is missing gateway_audit_event/audit_evidence"
            )
        elif gw_event.get("audit_evidence_id") != evidence.get("evidence_id"):
            mismatches.append("gateway_audit_event.audit_evidence_id != audit_evidence.evidence_id")

    composed_action = f"{action_verb}:{resource_type}"
    composed_resource = f"{resource_type}:{resource_id}"

    details = {
        "http_status": resp.status_code,
        "evaluation_status": payload.get("evaluation_status"),
        "outcome": payload.get("outcome"),
        "failure_reason": payload.get("failure_reason"),
        "disposition": payload.get("disposition"),
        "request_id": payload.get("request_id"),
        "correlation_id": payload.get("correlation_id"),
        "trace_id": payload.get("trace_id"),
        "bundle_id": payload.get("bundle_id"),
        "bundle_version": payload.get("bundle_version"),
        "matched_rule_ids": (evidence or {}).get("matched_rule_ids"),
        "evidence_id": (evidence or {}).get("evidence_id"),
        "audit_evidence_id": (gw_event or {}).get("audit_evidence_id"),
        "enforcement_action": (gw_event or {}).get("enforcement_action"),
        "authorization_subject": subject_id,
        "operation_producer_subject_id": None,
        "composed_action": composed_action,
        "composed_resource": composed_resource,
        "provenance": provenance,
    }

    lines: list[str] = []
    lines.append("=" * 64)
    lines.append(f"Scenario: {name.upper()}")
    lines.append("=" * 64)
    lines.extend(
        _format_block(
            "Request",
            [
                ("Subject:", subject_id),
                ("Producer:", "(not a classified operation producer)"),
                ("Action supplied:", action_verb),
                ("Resource type:", resource_type),
                ("Resource supplied:", resource_id),
            ],
        )
    )
    lines.append("")
    lines.extend(
        _format_block(
            "Gateway result",
            [
                ("HTTP status:", str(resp.status_code)),
                ("Evaluation status:", str(payload.get("evaluation_status"))),
                ("Kernel outcome:", str(payload.get("outcome"))),
                ("Enforcement:", str(payload.get("disposition"))),
            ],
        )
    )
    lines.append("")
    lines.extend(
        _format_block(
            "Composition",
            [
                ("Composed action:", composed_action),
                ("Composed resource:", composed_resource),
            ],
        )
    )
    lines.append("")
    lines.extend(
        _format_block(
            "Evidence",
            [
                ("Request ID:", str(payload.get("request_id"))),
                ("Correlation ID:", str(payload.get("correlation_id"))),
                ("Trace ID:", str(payload.get("trace_id"))),
                ("Evidence ID:", str((evidence or {}).get("evidence_id"))),
                (
                    "Bundle:",
                    _bundle_label(payload.get("bundle_id"), payload.get("bundle_version")),
                ),
                (
                    "Matched rules:",
                    ", ".join((evidence or {}).get("matched_rule_ids") or []) or "(none)",
                ),
                ("Provenance:", _display_provenance(provenance)),
            ],
        )
    )
    lines.append("")
    lines.append("Explanation")
    for note in explanation:
        lines.append(f"  - {note}")
    lines.append("")

    return ScenarioReport(
        name=name, passed=not mismatches, lines=lines, details=details, mismatches=mismatches
    )


def run_untrusted_producer_scenario(
    *, app: DemoApp, subject_id: str, token: str, expected: dict[str, Any]
) -> ScenarioReport:
    """An authenticated caller not in OPERATION_PRODUCER_SUBJECT_IDS submits
    one producer-only field. Must be rejected before the kernel is invoked --
    no AuditEvidence, no GatewayAuditEvent, no fabricated kernel evidence."""
    body = {"action": "read:ahu", "operation_intent": "read_only"}
    before = len(app.sink.events)
    resp = _post_oa(app.client, token, body)
    payload = _decode_json(resp)
    new_events = app.sink.events[before:]

    actual = {"http_status": resp.status_code}
    mismatches = _compare(actual, expected)

    completed = [e for e in new_events if getattr(e, "action", None) == AUTHORIZATION_COMPLETED]
    if completed:
        mismatches.append(
            "kernel was invoked (a completed audit record was written) for a request "
            "that should have been rejected before the kernel ran"
        )

    system_events = [e for e in new_events if e is not None]
    system_event = system_events[0] if len(system_events) == 1 else None
    if len(system_events) != 1:
        mismatches.append(
            f"expected exactly one gateway system audit event, got {len(system_events)}"
        )

    kernel_invoked = bool(completed)
    gateway_audit_event_present = False
    audit_evidence_present = False

    details = {
        "http_status": resp.status_code,
        "kernel_invoked": kernel_invoked,
        "gateway_audit_event_present": gateway_audit_event_present,
        "audit_evidence_present": audit_evidence_present,
        "gateway_system_audit_event_present": system_event is not None,
        "system_event_action": getattr(system_event, "action", None),
        "system_event_reason": getattr(system_event, "reason", None),
        "authorization_subject": subject_id,
        "operation_producer_subject_id": None,
        "message": payload.get("message"),
    }

    lines: list[str] = []
    lines.append("=" * 64)
    lines.append("Scenario: UNTRUSTED-PRODUCER")
    lines.append("=" * 64)
    lines.extend(
        _format_block(
            "Request",
            [
                ("Subject:", subject_id),
                ("Producer:", "untrusted (not in OPERATION_PRODUCER_SUBJECT_IDS)"),
                ("Action supplied:", "read:ahu"),
                ("Producer-only field:", "operation_intent=read_only"),
            ],
        )
    )
    lines.append("")
    lines.extend(
        _format_block(
            "Gateway result",
            [
                ("HTTP status:", str(resp.status_code)),
                ("Kernel invoked:", "no"),
                ("GatewayAuditEvent:", "absent"),
                ("AuditEvidence:", "absent"),
                (
                    "Gateway system audit event:",
                    "present" if system_event is not None else "absent",
                ),
                ("System event action:", str(getattr(system_event, "action", None))),
                ("System event reason:", str(getattr(system_event, "reason", None))),
            ],
        )
    )
    lines.append("")
    lines.append("Explanation")
    for note in (
        "Authentication succeeded -- the token verified and the subject is known.",
        "Producer trust did not: this subject is not in OPERATION_PRODUCER_SUBJECT_IDS.",
        "Producer-only context was rejected before authorization evaluation; the kernel never ran.",
        "Roles do not create producer trust -- only the exact, configured subject-ID "
        "allowlist does.",
        "The gateway did not fabricate kernel evidence for this rejection.",
    ):
        lines.append(f"  - {note}")
    lines.append("")

    return ScenarioReport(
        name="untrusted-producer",
        passed=not mismatches,
        lines=lines,
        details=details,
        mismatches=mismatches,
    )


def run_semantic_startup_failure_scenario(
    *, public_key_pem: str, v01_policy_path: Path, expected: dict[str, Any]
) -> ScenarioReport:
    """Start a *separate* application instance against the structurally
    valid but semantically invalid demo bundle (duplicate rule_id). Must
    remain live (/health 200) but not ready (/ready 503); the operation-aware
    route must remain registered (503, never 404)."""
    app = build_demo_app(
        bundle_path=INVALID_BUNDLE_PATH,
        v01_policy_path=v01_policy_path,
        public_key_pem=public_key_pem,
    )
    try:
        health_resp = app.client.get("/health")
        ready_resp = app.client.get("/ready")
        ready_body = _decode_json(ready_resp)
        components = ready_body.get("components", {}) or {}

        token = issue_demo_token(
            _KEY_HOLDER["key"], subject_id=OPERATOR_SUBJECT, roles=("operator",)
        )
        oa_resp = _post_oa(app.client, token, {"action": "read:ahu"})
        oa_body = _decode_json(oa_resp)

        actual = {
            "health_status": health_resp.status_code,
            "ready_status": ready_resp.status_code,
            "operation_aware_route_status": oa_resp.status_code,
        }
        mismatches = _compare(actual, expected)

        for component in _OPERATION_AWARE_COMPONENTS[:-1]:
            if components.get(component) is not True:
                mismatches.append(
                    f"expected {component} to be ready, got {components.get(component)!r}"
                )
        if components.get("operation_aware_policy_semantically_valid") is not False:
            mismatches.append(
                "expected operation_aware_policy_semantically_valid to be not-ready, got "
                f"{components.get('operation_aware_policy_semantically_valid')!r}"
            )
        if oa_resp.status_code == 404:
            mismatches.append(
                "operation-aware route returned 404 (unregistered) instead of a governed failure"
            )

        details = {
            "health_status": health_resp.status_code,
            "ready_status": ready_resp.status_code,
            "components": {name: components.get(name) for name in _OPERATION_AWARE_COMPONENTS},
            "operation_aware_route_status": oa_resp.status_code,
            "operation_aware_route_error": oa_body.get("error"),
        }

        lines: list[str] = []
        lines.append("=" * 64)
        lines.append("Scenario: SEMANTIC-STARTUP-FAILURE")
        lines.append("=" * 64)
        lines.extend(
            _format_block(
                "Startup",
                [
                    (
                        "Bundle:",
                        "policy-bundles/operation-aware-invalid-bundle.json (duplicate rule_id)",
                    ),
                    ("GET /health:", str(health_resp.status_code)),
                    ("GET /ready:", str(ready_resp.status_code)),
                ],
            )
        )
        lines.append("")
        lines.extend(
            _format_block(
                "Readiness components",
                [
                    (f"{name}:", "ready" if components.get(name) else "not ready")
                    for name in _OPERATION_AWARE_COMPONENTS
                ],
            )
        )
        lines.append("")
        lines.extend(
            _format_block(
                "Operation-aware route",
                [
                    (f"POST {OA_PATH}:", f"{oa_resp.status_code} (registered, governed failure)"),
                    ("Error:", str(oa_body.get("error"))),
                ],
            )
        )
        lines.append("")
        lines.append("Explanation")
        for note in (
            "The process is alive: GET /health still returns 200.",
            "The policy is not ready: GET /ready returns 503.",
            "The route remains registered because the feature (OPERATION_AWARE_ENABLED) was "
            "enabled at startup -- a request to it returns a governed 503, never FastAPI's "
            "ordinary 404.",
            "Semantic readiness failed before serving authorization: the bundle structurally "
            "loaded and the evaluator constructed, but the startup semantic preflight rejected "
            "it (duplicate rule_id across the bundle's rules).",
        ):
            lines.append(f"  - {note}")
        lines.append("")

        return ScenarioReport(
            name="semantic-startup-failure",
            passed=not mismatches,
            lines=lines,
            details=details,
            mismatches=mismatches,
        )
    finally:
        app.close()


# ---------------------------------------------------------------------------
# Readiness summary
# ---------------------------------------------------------------------------


def print_readiness_summary(app: DemoApp) -> list[str]:
    resp = app.client.get("/ready")
    body = _decode_json(resp)
    components = body.get("components", {}) or {}
    lines = ["=" * 64, "Readiness", "=" * 64]
    for name in _READINESS_COMPONENTS_TO_SHOW:
        if name in components:
            state = "ready" if components.get(name) else "not ready"
        else:
            state = "(not registered)"
        lines.append(f"  {name:<45}{state}")
    lines.append(f"  {'overall /ready status':<45}{resp.status_code}")
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_KEY_HOLDER: dict[str, RSAPrivateKey] = {}


def _load_expected_summary() -> dict[str, dict[str, Any]]:
    with EXPECTED_SUMMARY_PATH.open(encoding="utf-8") as fh:
        return dict(json.load(fh))


def run_demo(
    *, scenario: str | None = None, json_output: bool = False
) -> tuple[int, list[ScenarioReport]]:
    """Run the selected scenario(s) (or all, in ``SCENARIO_ORDER``) and
    return ``(exit_code, reports)``. Never raises for an expected mismatch --
    a mismatch is reported as a failed ``ScenarioReport`` instead."""
    expected = _load_expected_summary()
    selected = (scenario,) if scenario else SCENARIO_ORDER
    for name in selected:
        if name not in SCENARIO_ORDER:
            raise SystemExit(
                f"Unknown scenario: {name!r}. Choose from: {', '.join(SCENARIO_ORDER)}"
            )

    private_key = _generate_rsa_key()
    _KEY_HOLDER["key"] = private_key
    public_key_pem = _public_pem(private_key)

    tmp_dir = Path(tempfile.mkdtemp(prefix="basis-gateway-oa-demo-"))
    reports: list[ScenarioReport] = []
    output_lines: list[str] = []
    try:
        v01_policy_path = _write_v01_policy(tmp_dir)

        needs_valid_app = any(name != "semantic-startup-failure" for name in selected)
        app: DemoApp | None = None
        if needs_valid_app:
            app = build_demo_app(
                bundle_path=VALID_BUNDLE_PATH,
                v01_policy_path=v01_policy_path,
                public_key_pem=public_key_pem,
            )
            if not json_output:
                output_lines.extend(print_readiness_summary(app))

            operator_token = issue_demo_token(
                private_key, subject_id=OPERATOR_SUBJECT, roles=("operator",)
            )

            if "allow" in selected:
                reports.append(
                    run_completed_scenario(
                        name="allow",
                        app=app,
                        subject_id=OPERATOR_SUBJECT,
                        token=operator_token,
                        action_verb="read",
                        resource_type="ahu",
                        resource_id="rooftop-1",
                        expected=expected["allow"],
                        explanation=[
                            "The allow-read-ahu rule matches any authenticated caller "
                            "reading an AHU.",
                            "The kernel outcome (allow) and the gateway's enforcement "
                            "(allow) agree.",
                        ],
                    )
                )
            if "explicit-deny" in selected:
                reports.append(
                    run_completed_scenario(
                        name="explicit-deny",
                        app=app,
                        subject_id=OPERATOR_SUBJECT,
                        token=operator_token,
                        action_verb="write",
                        resource_type="ahu",
                        resource_id="protected-1",
                        expected=expected["explicit-deny"],
                        explanation=[
                            "Both allow-write-ahu (operator role) and "
                            "deny-write-protected-ahu (this resource) match.",
                            "The explicit deny rule wins -- matched_rule_ids names both "
                            "rules, distinguishing this from a default deny.",
                        ],
                    )
                )
            if "default-deny" in selected:
                reports.append(
                    run_completed_scenario(
                        name="default-deny",
                        app=app,
                        subject_id=OPERATOR_SUBJECT,
                        token=operator_token,
                        action_verb="execute",
                        resource_type="ahu",
                        resource_id="rooftop-1",
                        expected=expected["default-deny"],
                        explanation=[
                            "execute:ahu is within the bundle's governed scope, but no "
                            "allow or deny rule matches it.",
                            "This is the kernel's default-deny result -- matched_rule_ids "
                            "is empty, and no deny rule was fabricated.",
                        ],
                    )
                )
            if "not-applicable" in selected:
                reports.append(
                    run_completed_scenario(
                        name="not-applicable",
                        app=app,
                        subject_id=OPERATOR_SUBJECT,
                        token=operator_token,
                        action_verb="read",
                        resource_type="lighting",
                        resource_id="lobby-1",
                        expected=expected["not-applicable"],
                        explanation=[
                            "read:lighting is outside the bundle's governed scope "
                            "entirely (scope.actions does not include it).",
                            "not_applicable is the KERNEL OUTCOME; deny is the GATEWAY "
                            "ENFORCEMENT DISPOSITION -- these are two different facts.",
                            "not_applicable is never the same thing as deny, even though "
                            "both HTTP statuses are 403.",
                        ],
                    )
                )
            if "untrusted-producer" in selected:
                reports.append(
                    run_untrusted_producer_scenario(
                        app=app,
                        subject_id=OPERATOR_SUBJECT,
                        token=operator_token,
                        expected=expected["untrusted-producer"],
                    )
                )

        if "semantic-startup-failure" in selected:
            reports.append(
                run_semantic_startup_failure_scenario(
                    public_key_pem=public_key_pem,
                    v01_policy_path=v01_policy_path,
                    expected=expected["semantic-startup-failure"],
                )
            )

        if app is not None:
            app.close()
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    if not json_output:
        for report in reports:
            output_lines.extend(report.lines)
        for line in output_lines:
            print(line)

    passed = sum(1 for r in reports if r.passed)
    total = len(reports)
    exit_code = 0 if passed == total else 1

    if json_output:
        summary = {
            "scenarios": {
                r.name: {"passed": r.passed, "mismatches": r.mismatches, "details": r.details}
                for r in reports
            },
            "passed": passed,
            "total": total,
            "success": exit_code == 0,
        }
        print(json.dumps(summary, indent=2, default=str))
    else:
        print("-" * 64)
        if exit_code == 0:
            print(f"{passed} scenario(s) passed")
            print("Operation-aware gateway demonstration completed successfully")
        else:
            print(f"{passed}/{total} scenario(s) passed")
            for report in reports:
                if not report.passed:
                    print(f"FAILED: {report.name}")
                    for mismatch in report.mismatches:
                        print(f"  - {mismatch}")
            print("Operation-aware gateway demonstration FAILED")

    return exit_code, reports


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Bounded, reproducible, offline demonstration of the operation-aware gateway path."
        )
    )
    parser.add_argument(
        "--scenario",
        choices=SCENARIO_ORDER,
        default=None,
        help="Run only this scenario (default: run all scenarios in order).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON results instead of the human-readable terminal report.",
    )
    args = parser.parse_args()
    exit_code, _ = run_demo(scenario=args.scenario, json_output=args.json)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
