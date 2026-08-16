"""Route-level tests for live mTLS producer trust in
``POST /v1/evaluate/operation-aware`` (Phase 1B.3).

Uses the real FastAPI route with a real, real-kernel-backed
``OperationAwareGatewayEvaluator`` wrapped in a call-counting shim (to prove
the "kernel never invoked" property explicitly for every fail-closed case),
a mock OIDC verifier (bearer authentication, independent of producer
trust), and directly injected ``X-BASIS-Producer-Client-Cert`` header
values -- this suite does not run real NGINX or real TLS (that is
``tests/integration/test_producer_mtls_live_gateway.py``); it proves the
live route consumes Phase 1B.1/1B.2/the Phase 1B.3 orchestration module
correctly once a (simulated) trustworthy assertion has already arrived.

Dual synthetic identities, used throughout per the task's own required
proof:

    producer workload:  spiffe://example.test/basis/reference-producer-01
    authorization subject: service-maintenance-operator-01

The positive-path bearer subject is deliberately never a member of
``OPERATION_PRODUCER_SUBJECT_IDS`` in these tests.
"""

from __future__ import annotations

import contextlib
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from basis_core.policy import PolicyBundle
from fastapi.testclient import TestClient
from helpers import MockVerifier

from basis_gateway.auth.producer_mtls_trusted_proxy import PRODUCER_CLIENT_CERT_HEADER_NAME
from basis_gateway.core.operation_aware_evaluator import (
    OperationAwareGatewayEvaluator,
    build_operation_aware_evaluator,
)
from basis_gateway.main import create_app
from basis_gateway.readiness import reset_readiness_state

_INTEGRATION_DIR = Path(__file__).parent / "integration"
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from mtls_certs import (  # noqa: E402  (path shim above must run first)
    MULTI_URI_SAN_A,
    ONE_URI_SAN,
    MTLSFixtureSet,
    build_fixture_set,
)

PRODUCER_URI = ONE_URI_SAN
BEARER_SUBJECT = "service-maintenance-operator-01"

VALID_BUNDLE = PolicyBundle(
    bundle_id="oa-producer-mtls-bundle",
    bundle_version="1.0.0",
    schema_version="1.0.0",
    policy_owner="test-owner",
    rules=[
        {"rule_id": "allow-read-ahu", "effect": "allow", "match": {"actions": ["read:ahu"]}},
    ],
)

_NONEXISTENT_BUNDLE_PATH = "/tmp/basis-gateway-test-oa-producer-mtls-bundle-does-not-exist.json"


class _CountingEvaluator:
    """Wraps a real ``OperationAwareGatewayEvaluator``, counting ``evaluate()``
    calls -- proves the "kernel never invoked" property explicitly rather
    than only inferring it from an HTTP status code."""

    def __init__(self, inner: OperationAwareGatewayEvaluator) -> None:
        self._inner = inner
        self.call_count = 0

    def evaluate(self, *args: Any, **kwargs: Any) -> Any:
        self.call_count += 1
        return self._inner.evaluate(*args, **kwargs)


class _CapturingAuditWriter:
    """Appends every written ``AuditEvent`` to a caller-supplied list --
    used to assert on the specific audit action/reason a request produced,
    not merely on the HTTP status code."""

    def __init__(self, sink: list[Any]) -> None:
        self._sink = sink

    def write(self, event: Any) -> None:
        self._sink.append(event)


@pytest.fixture(scope="module")
def mtls_fixtures(tmp_path_factory: pytest.TempPathFactory) -> MTLSFixtureSet:
    return build_fixture_set(tmp_path_factory.mktemp("oa-endpoint-producer-mtls-pki"))


def _escape_pem(pem_bytes: bytes) -> str:
    return quote(pem_bytes, safe="")


@contextlib.contextmanager
def _client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    trusted_proxy_enabled: bool,
    admitted_uris: list[str] | None = None,
    subject_ids: str | None = None,
    verifier_claims: dict[str, Any] | None = None,
    audit_events: list[Any] | None = None,
) -> Iterator[tuple[TestClient, _CountingEvaluator]]:
    monkeypatch.setenv("OPERATION_AWARE_ENABLED", "true")
    monkeypatch.setenv("OPERATION_AWARE_POLICY_BUNDLE_PATH", _NONEXISTENT_BUNDLE_PATH)
    monkeypatch.setenv(
        "OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED",
        "true" if trusted_proxy_enabled else "false",
    )
    if admitted_uris is not None:
        import json

        monkeypatch.setenv("OPERATION_PRODUCER_MTLS_ADMITTED_URIS", json.dumps(admitted_uris))
    else:
        monkeypatch.delenv("OPERATION_PRODUCER_MTLS_ADMITTED_URIS", raising=False)
    if subject_ids is not None:
        monkeypatch.setenv("OPERATION_PRODUCER_SUBJECT_IDS", subject_ids)
    else:
        monkeypatch.delenv("OPERATION_PRODUCER_SUBJECT_IDS", raising=False)

    reset_readiness_state()
    app = create_app()
    counting = _CountingEvaluator(build_operation_aware_evaluator(VALID_BUNDLE))
    verifier = MockVerifier(
        claims=verifier_claims
        or {
            "sub": BEARER_SUBJECT,
            "iss": "https://test.example.com",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
        }
    )
    with TestClient(app, raise_server_exceptions=False) as c:
        app.state.verifier = verifier
        app.state.operation_aware_evaluator = counting
        if audit_events is not None:
            app.state.audit_writer = _CapturingAuditWriter(audit_events)
        yield c, counting


def _post(
    client: TestClient,
    *,
    headers: dict[str, str] | None = None,
    producer_cert_pem: bytes | None = None,
    bearer: str | None = "Bearer fake",
    **body: Any,
) -> Any:
    all_headers: dict[str, str] = dict(headers or {})
    if bearer is not None:
        all_headers.setdefault("Authorization", bearer)
    if producer_cert_pem is not None:
        all_headers[PRODUCER_CLIENT_CERT_HEADER_NAME] = _escape_pem(producer_cert_pem)
    return client.post("/v1/evaluate/operation-aware", json=body, headers=all_headers)


# ---------------------------------------------------------------------------
# mTLS positive path (dual-identity proof)
# ---------------------------------------------------------------------------


def test_admitted_producer_plus_distinct_bearer_reaches_kernel(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    with _client(
        monkeypatch,
        trusted_proxy_enabled=True,
        admitted_uris=[PRODUCER_URI],
        subject_ids=None,  # bearer subject deliberately NOT in the legacy allowlist
    ) as (client, counting):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            action="read:ahu",
            operation_intent="read_only",
        )
    assert resp.status_code == 200
    assert resp.json()["outcome"] == "allow"
    assert counting.call_count == 1


def test_positive_path_bearer_subject_not_in_legacy_allowlist(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    with _client(
        monkeypatch,
        trusted_proxy_enabled=True,
        admitted_uris=[PRODUCER_URI],
        subject_ids="some-other-subject-not-the-bearer",
    ) as (client, counting):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            action="read:ahu",
            operation_intent="read_only",
        )
    assert resp.status_code == 200
    assert counting.call_count == 1


def test_producer_owned_context_accepted_from_admitted_mtls_producer(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[PRODUCER_URI]) as (
        client,
        counting,
    ):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            action="read:ahu",
            location={"site_id": "site-1"},
        )
    assert resp.status_code == 200
    assert counting.call_count == 1


# ---------------------------------------------------------------------------
# Producer admission negative
# ---------------------------------------------------------------------------


def test_unadmitted_uri_cannot_assert_producer_owned_context(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[]) as (client, counting):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            action="read:ahu",
            operation_intent="read_only",
        )
    assert resp.status_code == 400
    assert counting.call_count == 0


def test_unadmitted_producer_without_producer_context_still_evaluates(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    """An unadmitted producer certificate does not, by itself, reject an
    ordinary request that carries no producer-only fields."""
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[]) as (client, counting):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            action="read:ahu",
        )
    assert resp.status_code == 200
    assert counting.call_count == 1


def test_case_mismatch_admission_rejects_producer_context(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[PRODUCER_URI.upper()]) as (
        client,
        counting,
    ):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            action="read:ahu",
            operation_intent="read_only",
        )
    assert resp.status_code == 400
    assert counting.call_count == 0


def test_empty_admission_set_rejects_producer_context(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[]) as (client, counting):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            action="read:ahu",
            operation_intent="read_only",
        )
    assert resp.status_code == 400
    assert counting.call_count == 0


# ---------------------------------------------------------------------------
# Missing assertion: Layer-2 fail-closed trust-boundary failure
# ---------------------------------------------------------------------------
# Per the merged producer-mtls-proxy-trust-boundary.md §11/§18: a missing
# internal certificate assertion on a request that reached basis-gateway
# while trusted-proxy mode is enabled is ALWAYS a fail-closed rejection --
# never an ordinary bearer-only continuation, regardless of whether the
# request carries producer-owned context and regardless of legacy-allowlist
# membership. This is intentionally stronger than the pre-correction
# behavior, which allowed a request with no producer-owned context to
# proceed to kernel evaluation; that behavior no longer exists.


def test_missing_assertion_fails_closed_when_producer_context_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[Any] = []
    with _client(
        monkeypatch,
        trusted_proxy_enabled=True,
        admitted_uris=[PRODUCER_URI],
        audit_events=events,
    ) as (client, counting):
        resp = _post(client, action="read:ahu", operation_intent="read_only")
    assert resp.status_code == 400
    assert counting.call_count == 0
    # Distinguishable from an ordinary composition-layer rejection
    # (UntrustedOperationProducerContextError -> "validation_failed") --
    # this fails at the mTLS trust boundary itself, before composition is
    # ever reached.
    assert resp.json()["error"] == "producer_certificate_rejected"
    assert len(events) == 1
    assert events[0].reason == "producer_mtls_missing_assertion"


def test_missing_assertion_without_producer_context_now_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Corrected behavior (this PR): a missing assertion fails closed even
    when the request carries no producer-owned context at all -- previously
    this would have proceeded to kernel evaluation as an ordinary bearer-only
    caller (MTLS_ASSERTION_ABSENT); that outcome is no longer reachable."""
    events: list[Any] = []
    with _client(
        monkeypatch,
        trusted_proxy_enabled=True,
        admitted_uris=[PRODUCER_URI],
        audit_events=events,
    ) as (client, counting):
        resp = _post(client, action="read:ahu")
    assert resp.status_code == 400
    assert counting.call_count == 0
    assert resp.json()["error"] == "producer_certificate_rejected"
    assert len(events) == 1
    assert events[0].reason == "producer_mtls_missing_assertion"
    # No certificate/token material in the audit detail.
    detail = events[0].detail
    assert "Bearer" not in str(detail)
    assert "BEGIN CERTIFICATE" not in str(detail)


def test_missing_assertion_no_legacy_fallback_without_producer_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mandatory no-fallback regression test (Step 12): the bearer subject
    IS present in OPERATION_PRODUCER_SUBJECT_IDS, but a missing assertion
    still fails closed -- legacy allowlist membership never rescues a
    Layer-2 trust-boundary failure. Zero evaluator invocations proves the
    kernel is never reached."""
    events: list[Any] = []
    with _client(
        monkeypatch,
        trusted_proxy_enabled=True,
        admitted_uris=[PRODUCER_URI],
        subject_ids=BEARER_SUBJECT,  # bearer subject IS legacy-allowlisted
        audit_events=events,
    ) as (client, counting):
        resp = _post(client, action="read:ahu")
    assert resp.status_code == 400
    assert counting.call_count == 0
    assert resp.json()["error"] == "producer_certificate_rejected"
    assert len(events) == 1
    assert events[0].reason == "producer_mtls_missing_assertion"


def test_missing_assertion_no_legacy_fallback_with_producer_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Step 13: missing assertion + legacy-allowlisted bearer + producer-
    owned context fails AT THE mTLS BOUNDARY ITSELF, not merely at the
    later UntrustedOperationProducerContextError composition gate -- proven
    by asserting the response error is "producer_certificate_rejected"
    (the mTLS trust-boundary rejection), never "validation_failed" (the
    composition-layer producer-context rejection), and that the audit
    action is the producer-mTLS trust-failure action, not the composition-
    rejected action."""
    events: list[Any] = []
    with _client(
        monkeypatch,
        trusted_proxy_enabled=True,
        admitted_uris=[PRODUCER_URI],
        subject_ids=BEARER_SUBJECT,  # bearer subject IS legacy-allowlisted
        audit_events=events,
    ) as (client, counting):
        resp = _post(client, action="read:ahu", operation_intent="read_only")
    assert resp.status_code == 400
    assert counting.call_count == 0
    assert resp.json()["error"] == "producer_certificate_rejected"
    assert len(events) == 1
    assert events[0].action == "gateway.operation_aware_producer_mtls_trust_failed"
    assert events[0].reason == "producer_mtls_missing_assertion"


# ---------------------------------------------------------------------------
# Certificate boundary: malformed/duplicate/oversized/zero-or-multi-SAN
# -- fail closed, no kernel invocation
# ---------------------------------------------------------------------------


def test_duplicate_assertion_fails_closed(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[PRODUCER_URI]) as (
        client,
        counting,
    ):
        value = _escape_pem(mtls_fixtures.client_one_uri_san.cert_pem)
        # httpx/requests do not support duplicate header names via a plain
        # dict; pass a list of 2-tuples, which httpx.Headers preserves
        # without collapsing.
        resp = client.post(
            "/v1/evaluate/operation-aware",
            json={"action": "read:ahu"},
            headers=[
                ("Authorization", "Bearer fake"),
                (PRODUCER_CLIENT_CERT_HEADER_NAME, value),
                (PRODUCER_CLIENT_CERT_HEADER_NAME, value),
            ],
        )
    assert resp.status_code == 400
    assert resp.json()["error"] == "producer_certificate_rejected"
    assert counting.call_count == 0


def test_oversized_assertion_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[PRODUCER_URI]) as (
        client,
        counting,
    ):
        resp = client.post(
            "/v1/evaluate/operation-aware",
            json={"action": "read:ahu"},
            headers={
                "Authorization": "Bearer fake",
                PRODUCER_CLIENT_CERT_HEADER_NAME: "%41" * 20_000,
            },
        )
    assert resp.status_code == 400
    assert counting.call_count == 0


def test_malformed_percent_encoding_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[PRODUCER_URI]) as (
        client,
        counting,
    ):
        resp = client.post(
            "/v1/evaluate/operation-aware",
            json={"action": "read:ahu"},
            headers={
                "Authorization": "Bearer fake",
                PRODUCER_CLIENT_CERT_HEADER_NAME: "%zz-malformed",
            },
        )
    assert resp.status_code == 400
    assert counting.call_count == 0


def test_malformed_certificate_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    bogus = quote(b"-----BEGIN CERTIFICATE-----\nnot-real-der-bytes\n-----END CERTIFICATE-----")
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[PRODUCER_URI]) as (
        client,
        counting,
    ):
        resp = client.post(
            "/v1/evaluate/operation-aware",
            json={"action": "read:ahu"},
            headers={"Authorization": "Bearer fake", PRODUCER_CLIENT_CERT_HEADER_NAME: bogus},
        )
    assert resp.status_code == 400
    assert counting.call_count == 0


def test_zero_uri_san_fails_closed(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[PRODUCER_URI]) as (
        client,
        counting,
    ):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_zero_uri_san.cert_pem,
            action="read:ahu",
        )
    assert resp.status_code == 400
    assert counting.call_count == 0


def test_multiple_uri_san_fails_closed(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[MULTI_URI_SAN_A]) as (
        client,
        counting,
    ):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_multi_uri_san.cert_pem,
            action="read:ahu",
        )
    assert resp.status_code == 400
    assert counting.call_count == 0


# ---------------------------------------------------------------------------
# Bearer authentication remains mandatory and independent
# ---------------------------------------------------------------------------


def test_admitted_producer_plus_missing_bearer_rejected(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[PRODUCER_URI]) as (
        client,
        counting,
    ):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            bearer=None,
            action="read:ahu",
        )
    assert resp.status_code == 401
    assert counting.call_count == 0


def test_admitted_producer_plus_invalid_bearer_rejected(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[PRODUCER_URI]) as (
        client,
        counting,
    ):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            bearer="Basic dXNlcjpwYXNz",
            action="read:ahu",
        )
    assert resp.status_code == 401
    assert counting.call_count == 0


def test_admitted_producer_plus_expired_bearer_rejected(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    from basis_gateway.auth.errors import JWTVerificationError

    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[PRODUCER_URI]) as (
        client,
        counting,
    ):
        client.app.state.verifier.set_raise(JWTVerificationError("Token has expired"))
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            action="read:ahu",
        )
    assert resp.status_code == 401
    assert counting.call_count == 0


# ---------------------------------------------------------------------------
# Subject/producer separation regression
# ---------------------------------------------------------------------------


def test_producer_uri_san_never_becomes_subject_id_in_response(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    """The mTLS producer URI must never leak into any subject-shaped field
    -- proven at the HTTP boundary by asserting the response body never
    contains the producer URI string."""
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[PRODUCER_URI]) as (
        client,
        counting,
    ):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            action="read:ahu",
            operation_intent="read_only",
        )
    assert resp.status_code == 200
    assert PRODUCER_URI not in resp.text


def test_caller_cannot_use_request_body_to_substitute_producer_for_subject(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=True, admitted_uris=[PRODUCER_URI]) as (
        client,
        counting,
    ):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            action="read:ahu",
            subject_id=PRODUCER_URI,
        )
    # extra="forbid" on OperationAwareEvaluateRequest rejects subject_id outright.
    assert resp.status_code == 400
    assert counting.call_count == 0


# ---------------------------------------------------------------------------
# Legacy compatibility (trusted-proxy mode disabled)
# ---------------------------------------------------------------------------


def test_legacy_allowlisted_subject_still_works_when_trusted_proxy_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=False, subject_ids=BEARER_SUBJECT) as (
        client,
        counting,
    ):
        resp = _post(client, action="read:ahu", operation_intent="read_only")
    assert resp.status_code == 200
    assert counting.call_count == 1


def test_legacy_non_allowlisted_subject_still_fails_when_trusted_proxy_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(monkeypatch, trusted_proxy_enabled=False, subject_ids="some-other-subject") as (
        client,
        counting,
    ):
        resp = _post(client, action="read:ahu", operation_intent="read_only")
    assert resp.status_code == 400
    assert counting.call_count == 0


def test_certificate_looking_header_ignored_when_trusted_proxy_disabled(
    monkeypatch: pytest.MonkeyPatch, mtls_fixtures: MTLSFixtureSet
) -> None:
    """No certificate parsing occurs merely because the header exists --
    the request behaves exactly as it would without the header at all."""
    with _client(monkeypatch, trusted_proxy_enabled=False, subject_ids=BEARER_SUBJECT) as (
        client,
        counting,
    ):
        resp = _post(
            client,
            producer_cert_pem=mtls_fixtures.client_one_uri_san.cert_pem,
            action="read:ahu",
            operation_intent="read_only",
        )
    assert resp.status_code == 200
    assert counting.call_count == 1


def test_certificate_looking_header_with_garbage_value_ignored_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even a value that would fail certificate parsing causes no error
    when trusted-proxy mode is disabled -- the header is never inspected."""
    with _client(monkeypatch, trusted_proxy_enabled=False, subject_ids=BEARER_SUBJECT) as (
        client,
        counting,
    ):
        resp = client.post(
            "/v1/evaluate/operation-aware",
            json={"action": "read:ahu", "operation_intent": "read_only"},
            headers={
                "Authorization": "Bearer fake",
                PRODUCER_CLIENT_CERT_HEADER_NAME: "%zz-not-even-decodable",
            },
        )
    assert resp.status_code == 200
    assert counting.call_count == 1
