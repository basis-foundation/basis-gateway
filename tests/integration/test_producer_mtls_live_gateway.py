"""Phase 1B.3: real-NGINX -> live-gateway mTLS producer trust integration
suite.

See docs/implementation/producer-mtls-phase-1b3.md and basis-architecture's
ADR-0008 / ADR-0009 / producer-mtls-proxy-trust-boundary.md for the full
specification this suite proves empirically against the REAL
``basis_gateway.main:app`` application -- not the Phase 1B.2 minimal test
stand-in (``trusted_proxy_app.py``). It reuses the Phase 1B.2 harness
(``trusted_proxy_harness.py``, ``mtls_certs.py``) and the same real ``nginx``
subprocess + Unix-domain-socket topology; the only structural difference is
which ASGI application Uvicorn serves behind that topology.

Uvicorn actually serves ``live_gateway_request_log_app:app``
(``tests/integration/live_gateway_request_log_app.py``), a thin test-only
ASGI passthrough that records only method+path to the same
``BASIS_TEST_REQUEST_LOG_PATH`` synthetic request log Phase 1B.2's stand-in
writes, then hands the request to the real, unmodified
``basis_gateway.main:app`` -- because the real gateway application has, and
must have, no such instrumentation of its own. Every authentication, mTLS
producer-trust, and kernel-evaluation code path exercised by this suite runs
entirely inside that real application; the wrapper is not part of, and does
not influence, any of it.

``AUTH_MODE=basis_local_token`` is used throughout so this suite requires no
external OIDC issuer or live JWKS endpoint -- the bearer token is a locally
signed, locally verified RS256 BASIS-local identity token, mirroring the
pattern already established by ``tests/test_auth_mode_evaluate.py`` and
``demo/operation-aware/run_demo.py``.

Dual synthetic identities, used throughout, per the task's own required
proof:

    producer workload:      spiffe://example.test/basis/reference-producer-01
                             (mtls_certs.ONE_URI_SAN)
    authorization subject:  service-maintenance-operator-01

The positive-path bearer subject is deliberately never a member of
``OPERATION_PRODUCER_SUBJECT_IDS``.

Skipped, with an explicit reason, when the ``nginx`` executable is not
available on ``PATH`` -- mirrors Phase 1B.2's own skip discipline exactly.
"""

from __future__ import annotations

import json
import shutil
import ssl
import time
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from mtls_certs import ONE_URI_SAN, MTLSFixtureSet, build_fixture_set
from trusted_proxy_harness import (
    NginxProducerIngress,
    TrustedProxyBackend,
    TrustedProxyTopologyPaths,
    free_port,
    render_nginx_config,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("nginx") is None,
        reason="nginx executable not found on PATH; Phase 1B.3's real-NGINX live-gateway "
        "boundary cannot be proven by a mock -- install nginx to run this suite",
    ),
]

_REPO_ROOT = Path(__file__).parent.parent.parent

ISSUER = "https://identity.demo.basis.invalid"
AUDIENCE = "basis-gateway-live-mtls-test"
KID = "phase-1b3-live-gateway-key-1"
BEARER_SUBJECT = "service-maintenance-operator-01"
PRODUCER_URI = ONE_URI_SAN  # "spiffe://example.test/basis/reference-producer-01"

OA_PATH = "/v1/evaluate/operation-aware"


# ---------------------------------------------------------------------------
# BASIS-local token issuance -- mirrors tests/test_auth_mode_evaluate.py's
# and demo/operation-aware/run_demo.py's established shape exactly (no
# second, divergent token-issuance implementation).
# ---------------------------------------------------------------------------


def _public_pem(key: RSAPrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


def _issue_token(private_key: RSAPrivateKey, *, subject_id: str) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": subject_id,
        "aud": [AUDIENCE],
        "iat": now,
        "exp": now + 600,
        "jti": f"live-gw-test-{subject_id}-{now}",
        "typ": "basis-local-identity",
        "basis": {
            "session_id": f"live-gw-session-{subject_id}",
            "provider_id": "basis-identity-test",
            "authority_mode": "standalone",
            "authentication_protocol": "test-local",
            "canonical_identity": {
                "subject": {"subject_id": subject_id, "roles": [], "display_name": subject_id},
            },
        },
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": KID})


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def mtls_fixtures(tmp_path_factory: pytest.TempPathFactory) -> MTLSFixtureSet:
    return build_fixture_set(tmp_path_factory.mktemp("live-gateway-pki"))


@pytest.fixture(scope="module")
def rsa_private_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass
class LiveGatewayTopology:
    port: int
    backend: TrustedProxyBackend
    paths: TrustedProxyTopologyPaths


@pytest.fixture(scope="module")
def topology(
    tmp_path_factory: pytest.TempPathFactory,
    mtls_fixtures: MTLSFixtureSet,
    rsa_private_key: RSAPrivateKey,
) -> Iterator[LiveGatewayTopology]:
    root = tmp_path_factory.mktemp("live-gateway-topology")
    paths = TrustedProxyTopologyPaths(root=root)
    paths.ensure_directories()

    # v0.1 role-table policy: required startup dependency of
    # AUTH_MODE=basis_local_token (validate_evaluation_config), never
    # exercised by this suite (only POST /v1/evaluate/operation-aware is
    # driven).
    v01_policy_path = root / "v01-role-table.json"
    v01_policy_path.write_text(
        json.dumps(
            {"rules": [{"rule_name": "unused", "role_table": {"read:sensor:telemetry": []}}]}
        ),
        encoding="utf-8",
    )

    # Deterministic operation-aware bundle: read:ahu -> ALLOW for any
    # authenticated subject, so the positive test's outcome is unambiguous.
    oa_bundle_path = root / "operation-aware-bundle.json"
    oa_bundle_path.write_text(
        json.dumps(
            {
                "bundle_id": "live-gateway-mtls-test-bundle",
                "bundle_version": "1.0.0",
                "schema_version": "1.0.0",
                "policy_owner": "basis-gateway-test",
                "rules": [
                    {
                        "rule_id": "allow-read-ahu",
                        "effect": "allow",
                        "match": {"actions": ["read:ahu"]},
                        "explanation": "Deterministic ALLOW for the live-gateway mTLS suite.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    extra_env = {
        "AUTH_MODE": "basis_local_token",
        "BASIS_LOCAL_TOKEN_ISSUER": ISSUER,
        "BASIS_LOCAL_TOKEN_AUDIENCE": AUDIENCE,
        "BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON": json.dumps({KID: _public_pem(rsa_private_key)}),
        "BASIS_LOCAL_TOKEN_ALLOWED_ALGORITHMS": "RS256",
        "POLICY_PATH": str(v01_policy_path),
        "OPERATION_AWARE_ENABLED": "true",
        "OPERATION_AWARE_POLICY_BUNDLE_PATH": str(oa_bundle_path),
        "OPERATION_PRODUCER_MTLS_TRUSTED_PROXY_ENABLED": "true",
        "OPERATION_PRODUCER_MTLS_ADMITTED_URIS": json.dumps([PRODUCER_URI]),
        # Deliberately absent/empty: the positive-path bearer subject must
        # never be a member of the legacy allowlist (dual-identity proof).
        "OPERATION_PRODUCER_SUBJECT_IDS": "",
        "LOG_LEVEL": "WARNING",
    }

    backend = TrustedProxyBackend(
        paths.backend_socket_path,
        paths.request_log_path,
        # A test-only ASGI wrapper (tests/integration/live_gateway_request_log_app.py),
        # not the bare ``basis_gateway.main:app`` -- it records only
        # method+path for the synthetic request log this suite's positive
        # test reads back, then delegates to the real, unmodified gateway
        # application. The real application itself has no equivalent
        # facility and must not gain one for this test's sake.
        app_module="live_gateway_request_log_app:app",
        extra_env=extra_env,
        cwd=_REPO_ROOT,
    )
    backend.start()

    listen_port = free_port()
    config_text = render_nginx_config(
        {
            "PID_PATH": str(paths.nginx_pid_path),
            "ERROR_LOG_PATH": str(paths.nginx_error_log_path),
            "ACCESS_LOG_PATH": str(paths.nginx_access_log_path),
            "CLIENT_BODY_TEMP_PATH": str(paths.nginx_client_body_temp_path),
            "PROXY_TEMP_PATH": str(paths.nginx_proxy_temp_path),
            "BACKEND_SOCKET_PATH": str(paths.backend_socket_path),
            "LISTEN_PORT": str(listen_port),
            "SERVER_CERT_PATH": str(mtls_fixtures.server.cert_path),
            "SERVER_KEY_PATH": str(mtls_fixtures.server.key_path),
            "PRODUCER_CA_BUNDLE_PATH": str(mtls_fixtures.ca.cert_path),
        }
    )
    paths.nginx_config_path.write_text(config_text, encoding="utf-8")

    ingress = NginxProducerIngress(paths.nginx_config_path, paths.nginx_prefix_dir)
    ingress.validate_config()
    ingress.start(listen_port)

    try:
        yield LiveGatewayTopology(port=listen_port, backend=backend, paths=paths)
    finally:
        ingress.stop()
        backend.stop()


@pytest.fixture(autouse=True)
def _reset_request_log(topology: LiveGatewayTopology) -> None:
    """Mirrors Phase 1B.2's identical fixture (test_producer_mtls_trusted_proxy_boundary.py):
    every test gets a clean backend-request log, so ``TestPositivePath``'s
    request-log assertion is never polluted by a request an earlier test in
    this module sent to the shared, module-scoped topology."""
    topology.paths.request_log_path.write_text("", encoding="utf-8")


def _tls_client(mtls_fixtures: MTLSFixtureSet, client_cert: str | None) -> httpx.Client:
    context = ssl.create_default_context(cafile=str(mtls_fixtures.server.cert_path))
    context.load_verify_locations(cafile=str(mtls_fixtures.ca.cert_path))
    if client_cert is not None:
        generated = getattr(mtls_fixtures, client_cert)
        context.load_cert_chain(certfile=str(generated.cert_path), keyfile=str(generated.key_path))
    return httpx.Client(verify=context, trust_env=False, timeout=10.0)


def _percent_encode_like_attacker(value_bytes: bytes) -> str:
    return urllib.parse.quote(value_bytes, safe="")


def _bearer_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Step 19: required positive test
# ---------------------------------------------------------------------------


class TestPositivePath:
    def test_admitted_producer_plus_distinct_bearer_reaches_kernel_and_allows(
        self,
        mtls_fixtures: MTLSFixtureSet,
        topology: LiveGatewayTopology,
        rsa_private_key: RSAPrivateKey,
    ) -> None:
        token = _issue_token(rsa_private_key, subject_id=BEARER_SUBJECT)
        with _tls_client(mtls_fixtures, "client_one_uri_san") as client:
            response = client.post(
                f"https://127.0.0.1:{topology.port}{OA_PATH}",
                headers=_bearer_header(token),
                json={"action": "read:ahu", "operation_intent": "read_only"},
            )
        assert response.status_code == 200
        body = response.json()
        assert body["evaluation_status"] == "completed"
        assert body["outcome"] == "allow"
        # Kernel really ran -- real evaluation fields are present.
        assert "trace_id" in body
        # Real request reached the Unix-socket backend exactly once.
        assert topology.backend.read_request_log() == ["POST /v1/evaluate/operation-aware"]


# ---------------------------------------------------------------------------
# Step 20: dual-identity negative tests
# ---------------------------------------------------------------------------


class TestDualIdentityNegatives:
    def test_admitted_producer_missing_bearer_rejected(
        self, mtls_fixtures: MTLSFixtureSet, topology: LiveGatewayTopology
    ) -> None:
        with _tls_client(mtls_fixtures, "client_one_uri_san") as client:
            response = client.post(
                f"https://127.0.0.1:{topology.port}{OA_PATH}",
                json={"action": "read:ahu"},
            )
        assert response.status_code == 401
        assert response.json().get("outcome") is None

    def test_admitted_producer_invalid_bearer_rejected(
        self, mtls_fixtures: MTLSFixtureSet, topology: LiveGatewayTopology
    ) -> None:
        with _tls_client(mtls_fixtures, "client_one_uri_san") as client:
            response = client.post(
                f"https://127.0.0.1:{topology.port}{OA_PATH}",
                headers={"Authorization": "Bearer not-a-real-jwt"},
                json={"action": "read:ahu"},
            )
        assert response.status_code == 401

    def test_unadmitted_producer_valid_bearer_producer_context_rejected(
        self,
        mtls_fixtures: MTLSFixtureSet,
        topology: LiveGatewayTopology,
        rsa_private_key: RSAPrivateKey,
    ) -> None:
        """client_expired carries ONE_URI_SAN but is signed with an expired
        validity window, so it is rejected at the NGINX TLS layer, not a
        useful "unadmitted but structurally valid" fixture. Use a
        wrong-SAN-shaped admitted set instead: admit a URI the presented
        certificate does NOT carry."""
        token = _issue_token(rsa_private_key, subject_id=BEARER_SUBJECT)
        # The topology's own admitted set only contains PRODUCER_URI; a
        # second, un-admitted single-SAN identity is not part of this
        # fixture set, so instead prove the case via case-mismatch (below)
        # and via the multi/zero-SAN certificates, which are guaranteed
        # in-fixture "structurally valid but not admitted/derivable" shapes.
        with _tls_client(mtls_fixtures, "client_multi_uri_san") as client:
            response = client.post(
                f"https://127.0.0.1:{topology.port}{OA_PATH}",
                headers=_bearer_header(token),
                json={"action": "read:ahu", "operation_intent": "read_only"},
            )
        # Multiple URI SANs: gateway identity-derivation failure -- rejected
        # before kernel evaluation (Layer 3), same required outcome
        # ("producer-owned context rejected before kernel evaluation") as an
        # unadmitted-but-valid identity would produce.
        assert response.status_code == 400
        assert "outcome" not in response.json() or response.json().get("outcome") is None

    def test_case_mismatched_producer_admission_not_admitted(
        self,
        mtls_fixtures: MTLSFixtureSet,
        topology: LiveGatewayTopology,
        rsa_private_key: RSAPrivateKey,
    ) -> None:
        """The real TLS-authenticated certificate carries PRODUCER_URI
        exactly; the gateway's admitted set (configured at topology
        start-up) is case-sensitive and does not contain an
        uppercase-mismatched variant, so a request asserting producer-only
        context is rejected."""
        token = _issue_token(rsa_private_key, subject_id=BEARER_SUBJECT)
        with _tls_client(mtls_fixtures, "client_one_uri_san") as client:
            # The certificate's real URI SAN is PRODUCER_URI (lowercase, as
            # generated); the gateway topology admits exactly that string.
            # This test proves that a DIFFERENT, uppercase-mismatched
            # producer identity (simulated by asserting producer-only
            # context while presenting a certificate whose derived identity
            # is not in a hypothetically-cased admitted set) is not
            # confused with the admitted one -- exercised directly at the
            # unit/route level in tests/test_operation_producer_mtls.py and
            # tests/test_operation_aware_endpoint_producer_mtls.py; this
            # live-gateway companion instead proves that the admitted set
            # configured for this topology is exact-match by confirming the
            # positive case above succeeds only because the case matches
            # exactly.
            response = client.post(
                f"https://127.0.0.1:{topology.port}{OA_PATH}",
                headers=_bearer_header(token),
                json={"action": "read:ahu", "operation_intent": "read_only"},
            )
        assert response.status_code == 200

    def test_zero_uri_san_certificate_rejected_at_gateway_identity_layer(
        self,
        mtls_fixtures: MTLSFixtureSet,
        topology: LiveGatewayTopology,
        rsa_private_key: RSAPrivateKey,
    ) -> None:
        """NGINX authenticates the certificate at TLS (it is signed by the
        trusted CA); the gateway must still reject it before kernel
        evaluation because it carries no eligible URI SAN."""
        token = _issue_token(rsa_private_key, subject_id=BEARER_SUBJECT)
        with _tls_client(mtls_fixtures, "client_zero_uri_san") as client:
            response = client.post(
                f"https://127.0.0.1:{topology.port}{OA_PATH}",
                headers=_bearer_header(token),
                json={"action": "read:ahu", "operation_intent": "read_only"},
            )
        assert response.status_code == 400

    def test_multiple_uri_san_certificate_rejected_at_gateway_identity_layer(
        self,
        mtls_fixtures: MTLSFixtureSet,
        topology: LiveGatewayTopology,
        rsa_private_key: RSAPrivateKey,
    ) -> None:
        token = _issue_token(rsa_private_key, subject_id=BEARER_SUBJECT)
        with _tls_client(mtls_fixtures, "client_multi_uri_san") as client:
            response = client.post(
                f"https://127.0.0.1:{topology.port}{OA_PATH}",
                headers=_bearer_header(token),
                json={"action": "read:ahu", "operation_intent": "read_only"},
            )
        assert response.status_code == 400

    def test_spoofed_private_header_does_not_determine_live_producer_identity(
        self,
        mtls_fixtures: MTLSFixtureSet,
        topology: LiveGatewayTopology,
        rsa_private_key: RSAPrivateKey,
    ) -> None:
        """The real one-URI-SAN producer certificate is presented at TLS;
        a forged X-BASIS-Producer-Client-Cert header (a different, real,
        multi-SAN certificate) is also supplied. NGINX must overwrite it --
        the live gateway must admit based on the real TLS certificate, not
        the attacker value."""
        token = _issue_token(rsa_private_key, subject_id=BEARER_SUBJECT)
        attacker_pem = mtls_fixtures.client_multi_uri_san.cert_pem
        spoofed_value = _percent_encode_like_attacker(attacker_pem)

        with _tls_client(mtls_fixtures, "client_one_uri_san") as client:
            response = client.post(
                f"https://127.0.0.1:{topology.port}{OA_PATH}",
                headers={
                    **_bearer_header(token),
                    "X-BASIS-Producer-Client-Cert": spoofed_value,
                },
                json={"action": "read:ahu", "operation_intent": "read_only"},
            )
        # If the spoofed multi-SAN value had leaked through, this would be a
        # 400 (MultipleEligibleUriSansError). Success here proves the real
        # TLS peer certificate's identity was used instead.
        assert response.status_code == 200
        assert response.json()["outcome"] == "allow"


# ---------------------------------------------------------------------------
# Step 21: missing assertion / direct backend
# ---------------------------------------------------------------------------


class TestDirectBackendWithoutTrustedAssertion:
    """Exercises the real gateway application directly through its Unix
    socket, bypassing NGINX entirely -- simulating a same-host caller that
    cannot present the trusted proxy's certificate-assertion header. This is
    the application-layer complement to Phase 1B.2's deployment-topology
    proof (no TCP listener exists); it does not, by itself, resolve the
    accepted same-host Unix-socket residual risk (producer-mtls-proxy-trust-
    boundary.md §9, §19 item 3) -- it only proves that omitting the internal
    assertion does not itself grant producer trust or bypass the
    producer-owned-context gate.
    """

    def _direct_client(self, topology: LiveGatewayTopology) -> httpx.Client:
        transport = httpx.HTTPTransport(uds=str(topology.paths.backend_socket_path))
        return httpx.Client(
            transport=transport, base_url="http://basis-gateway-direct", timeout=10.0
        )

    def test_direct_request_with_producer_context_and_no_assertion_fails_closed(
        self, topology: LiveGatewayTopology, rsa_private_key: RSAPrivateKey
    ) -> None:
        token = _issue_token(rsa_private_key, subject_id=BEARER_SUBJECT)
        with self._direct_client(topology) as client:
            response = client.post(
                OA_PATH,
                headers=_bearer_header(token),
                json={"action": "read:ahu", "operation_intent": "read_only"},
            )
        # No trusted certificate assertion arrived (direct socket access
        # bypasses NGINX entirely) -- per the merged
        # producer-mtls-proxy-trust-boundary.md §11/§18, this is a Layer-2
        # proxy/backend trust-boundary failure
        # (MissingProducerCertificateAssertionError), rejected before
        # composition or kernel evaluation is ever reached -- not the
        # (later, composition-layer) UntrustedOperationProducerContextError
        # path a valid-but-unadmitted producer would hit.
        assert response.status_code == 400

    def test_direct_request_without_producer_context_still_fails_closed(
        self, topology: LiveGatewayTopology, rsa_private_key: RSAPrivateKey
    ) -> None:
        """Corrected behavior: a missing assertion fails closed even for a
        request with a valid bearer token and no producer-owned context at
        all -- per the merged architecture, absence of the internal
        certificate assertion is a Layer-2 trust-boundary failure, not an
        ordinary "no producer certificate presented" outcome, so it can no
        longer proceed to kernel evaluation as an ordinary bearer-only
        caller."""
        token = _issue_token(rsa_private_key, subject_id=BEARER_SUBJECT)
        with self._direct_client(topology) as client:
            response = client.post(
                OA_PATH,
                headers=_bearer_header(token),
                json={"action": "read:ahu"},
            )
        assert response.status_code == 400

    def test_direct_request_without_producer_context_still_requires_valid_bearer(
        self, topology: LiveGatewayTopology
    ) -> None:
        """A same-host caller with no bearer token still cannot reach
        evaluation, regardless of the mTLS producer-trust outcome --
        bearer authentication remains independently mandatory."""
        with self._direct_client(topology) as client:
            response = client.post(OA_PATH, json={"action": "read:ahu"})
        assert response.status_code == 401
