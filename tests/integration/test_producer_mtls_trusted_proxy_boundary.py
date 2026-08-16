"""Phase 1B.2: real-NGINX trusted mTLS ingress trust-boundary integration
suite.

See docs/implementation/producer-mtls-phase-1b2.md and basis-architecture's
ADR-0009 / producer-mtls-proxy-trust-boundary.md for the full specification
this suite proves empirically. This module launches two real, independent
subprocesses per test-module run -- a real ``nginx`` and a real Uvicorn
backend bound only to a Unix domain socket -- and drives real TLS
handshakes against them using the retained Phase 1A PKI fixtures
(tests/integration/mtls_certs.py). No mocked NGINX, no mocked TLS, no
config-string assertions in place of an executed request.

Skipped, with an explicit reason, when the ``nginx`` executable is not
available on ``PATH`` -- this suite's core security property depends on
real NGINX behavior and cannot be satisfied by a mock (see
docs/implementation/producer-mtls-phase-1b2.md's Stop Conditions).
"""

from __future__ import annotations

import shutil
import ssl
import sys
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
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
        reason="nginx executable not found on PATH; Phase 1B.2's real-NGINX trust "
        "boundary cannot be proven by a mock -- install nginx to run this suite",
    ),
]

_SYNTHETIC_BEARER_VALUE = "Bearer synthetic-test-only-bearer-value-not-a-real-credential"


@dataclass
class TrustedProxyTopology:
    port: int
    backend: TrustedProxyBackend
    paths: TrustedProxyTopologyPaths


@pytest.fixture(scope="module")
def mtls_fixtures(tmp_path_factory: pytest.TempPathFactory) -> MTLSFixtureSet:
    return build_fixture_set(tmp_path_factory.mktemp("trusted-proxy-pki"))


@pytest.fixture(scope="module")
def topology(
    tmp_path_factory: pytest.TempPathFactory, mtls_fixtures: MTLSFixtureSet
) -> Iterator[TrustedProxyTopology]:
    root = tmp_path_factory.mktemp("trusted-proxy-topology")
    paths = TrustedProxyTopologyPaths(root=root)
    paths.ensure_directories()

    backend = TrustedProxyBackend(paths.backend_socket_path, paths.request_log_path)
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
        yield TrustedProxyTopology(port=listen_port, backend=backend, paths=paths)
    finally:
        ingress.stop()
        backend.stop()


@pytest.fixture(autouse=True)
def _reset_request_log(topology: TrustedProxyTopology) -> None:
    """Every test gets a clean backend-request log, so "did the backend
    receive N requests" assertions are never polluted by a previous test."""
    topology.paths.request_log_path.write_text("", encoding="utf-8")


def _client(mtls_fixtures: MTLSFixtureSet, client_cert: str | None) -> httpx.Client:
    """Build an httpx client trusting the reference server certificate,
    optionally presenting a client certificate. Mirrors
    tests/integration/test_producer_mtls_transport.py's equivalent helper
    and the same rationale for building the SSLContext explicitly rather
    than passing httpx's ``verify=<path>``/``cert=<tuple>`` kwargs directly.
    """
    context = ssl.create_default_context(cafile=str(mtls_fixtures.server.cert_path))
    # The reference server certificate's SAN covers 127.0.0.1/localhost
    # only; the CA that issued it is also the CA nginx trusts client certs
    # against (mtls_fixtures.ca), but a client verifying the SERVER
    # certificate must trust that same CA as the server's issuer.
    context.load_verify_locations(cafile=str(mtls_fixtures.ca.cert_path))
    if client_cert is not None:
        generated = getattr(mtls_fixtures, client_cert)
        context.load_cert_chain(certfile=str(generated.cert_path), keyfile=str(generated.key_path))
    return httpx.Client(verify=context, trust_env=False)


def _assert_rejected_by_nginx_mtls_boundary(make_request: Callable[[], httpx.Response]) -> None:
    """Assert *make_request* (a zero-argument callable performing one HTTPS
    request through the reference nginx listener) is rejected by the nginx
    mTLS boundary before proxying to the backend.

    NGINX's client-certificate verification (``ssl_verify_client``) is not
    guaranteed to manifest as one specific client-visible failure mode: it
    may abort the TLS handshake outright (surfaced to httpx as
    ``httpx.TransportError``), or it may complete/abort the connection with
    an HTTP-level error response (nginx's internal ``495``/``496``
    verification-failure statuses, or another 4xx/5xx, depending on nginx
    version and configuration). Neither manifestation is part of this
    document's normative contract -- what this suite must prove is the
    security boundary itself (the request is rejected; the backend never
    sees it), not one particular wire-level presentation of that rejection.
    A 2xx/3xx response is never accepted as a rejection.
    """
    try:
        response = make_request()
    except httpx.TransportError:
        return
    assert response.status_code >= 400, (
        "expected the request to be rejected by the nginx mTLS boundary "
        f"(transport failure or an HTTP error status), but got {response.status_code}"
    )


def _percent_encode_like_attacker(value_bytes: bytes) -> str:
    """Percent-encode arbitrary bytes for use as an ATTACKER-CONTROLLED
    inbound header value in these tests. This is intentionally independent
    of nginx's own ``$ssl_client_escaped_cert`` encoding choices -- it only
    needs to round-trip through
    ``basis_gateway.auth.producer_mtls.decode_producer_certificate_assertion``
    correctly if (and only if) the spoofed value were to leak through,
    which is exactly the negative outcome these tests prove does not
    happen.
    """
    return urllib.parse.quote(value_bytes, safe="")


class TestTLSBoundary:
    """Layer 1 (producer TLS authentication at the ingress) -- proven
    against a real nginx process, not asserted from configuration text."""

    def test_valid_trusted_client_certificate_reaches_backend_and_derives_expected_uri_san(
        self, mtls_fixtures: MTLSFixtureSet, topology: TrustedProxyTopology
    ) -> None:
        with _client(mtls_fixtures, "client_one_uri_san") as client:
            response = client.post(
                f"https://127.0.0.1:{topology.port}/v1/evaluate/operation-aware",
                headers={"Authorization": _SYNTHETIC_BEARER_VALUE},
            )
        assert response.status_code == 200
        body = response.json()
        assert body["assertion_present"] is True
        assert body["assertion_error"] is None
        assert body["producer_uri_san"] == ONE_URI_SAN

        # Exactly one request reached the Unix-socket backend.
        assert topology.backend.read_request_log() == ["POST /v1/evaluate/operation-aware"]

    def test_missing_client_certificate_rejected_before_backend(
        self, mtls_fixtures: MTLSFixtureSet, topology: TrustedProxyTopology
    ) -> None:
        """A request with no client certificate is rejected by the nginx
        mTLS boundary before proxying to the backend -- proven by an empty
        backend request log, independent of whether nginx presents the
        rejection as a transport-level failure or an HTTP error response
        (see ``_assert_rejected_by_nginx_mtls_boundary``)."""
        with _client(mtls_fixtures, None) as client:
            _assert_rejected_by_nginx_mtls_boundary(
                lambda: client.post(
                    f"https://127.0.0.1:{topology.port}/v1/evaluate/operation-aware"
                )
            )
        assert topology.backend.read_request_log() == []

    def test_untrusted_ca_certificate_rejected_before_backend(
        self, mtls_fixtures: MTLSFixtureSet, topology: TrustedProxyTopology
    ) -> None:
        """A certificate signed by an untrusted CA is rejected by the nginx
        mTLS boundary before proxying to the backend -- see
        ``_assert_rejected_by_nginx_mtls_boundary`` for why this does not
        assert one specific client-visible failure mode."""
        with _client(mtls_fixtures, "client_untrusted_ca") as client:
            _assert_rejected_by_nginx_mtls_boundary(
                lambda: client.post(
                    f"https://127.0.0.1:{topology.port}/v1/evaluate/operation-aware"
                )
            )
        assert topology.backend.read_request_log() == []

    def test_expired_certificate_rejected_before_backend(
        self, mtls_fixtures: MTLSFixtureSet, topology: TrustedProxyTopology
    ) -> None:
        """An expired producer certificate is rejected by the nginx mTLS
        boundary before proxying to the backend -- see
        ``_assert_rejected_by_nginx_mtls_boundary`` for why this does not
        assert one specific client-visible failure mode."""
        with _client(mtls_fixtures, "client_expired") as client:
            _assert_rejected_by_nginx_mtls_boundary(
                lambda: client.post(
                    f"https://127.0.0.1:{topology.port}/v1/evaluate/operation-aware"
                )
            )
        assert topology.backend.read_request_log() == []


class TestHeaderSpoofResistance:
    """The single most important test in this suite (Phase 1B.2 Step 10):
    an attacker-supplied copy of the reserved internal header must never
    influence the derived producer identity, proven against a real nginx
    process."""

    def test_attacker_supplied_header_is_overwritten_and_never_influences_identity(
        self, mtls_fixtures: MTLSFixtureSet, topology: TrustedProxyTopology
    ) -> None:
        # The attacker value is a DIFFERENT, real certificate (two URI
        # SANs) -- if it leaked through unmodified, Phase 1B.1's
        # derive_producer_identity would raise
        # MultipleEligibleUriSansError, a clearly distinguishable outcome
        # from the correct single-URI-SAN result below.
        attacker_pem = mtls_fixtures.client_multi_uri_san.cert_pem
        spoofed_header_value = _percent_encode_like_attacker(attacker_pem)

        with _client(mtls_fixtures, "client_one_uri_san") as client:
            response = client.post(
                f"https://127.0.0.1:{topology.port}/v1/evaluate/operation-aware",
                headers={"X-BASIS-Producer-Client-Cert": spoofed_header_value},
            )

        assert response.status_code == 200
        body = response.json()

        # The backend's derived identity is the REAL TLS peer certificate's
        # URI SAN (client_one_uri_san / ONE_URI_SAN) -- never the attacker's
        # multi-SAN certificate, and never an error caused by the attacker's
        # value leaking through.
        assert body["assertion_present"] is True
        assert body["assertion_error"] is None
        assert body["producer_uri_san"] == ONE_URI_SAN

        assert topology.backend.read_request_log() == ["POST /v1/evaluate/operation-aware"]

    def test_attacker_supplied_header_alone_without_any_client_certificate_is_rejected(
        self, mtls_fixtures: MTLSFixtureSet, topology: TrustedProxyTopology
    ) -> None:
        """An attacker with no client certificate at all cannot use the
        header to fake producer status -- ssl_verify_client on; rejects the
        connection at the nginx mTLS boundary (before nginx's own routing,
        and therefore before proxy_set_header, is ever reached), regardless
        of whether that rejection surfaces to the client as a transport
        failure or an HTTP error response (see
        ``_assert_rejected_by_nginx_mtls_boundary``)."""
        spoofed_header_value = _percent_encode_like_attacker(b"not-a-certificate-at-all")
        with _client(mtls_fixtures, None) as client:
            _assert_rejected_by_nginx_mtls_boundary(
                lambda: client.post(
                    f"https://127.0.0.1:{topology.port}/v1/evaluate/operation-aware",
                    headers={"X-BASIS-Producer-Client-Cert": spoofed_header_value},
                )
            )
        assert topology.backend.read_request_log() == []


class TestRouteScopeIsolation:
    """Step 12: the dedicated producer mTLS listener is not a general
    gateway ingress."""

    def test_unrelated_path_is_not_forwarded_to_backend(
        self, mtls_fixtures: MTLSFixtureSet, topology: TrustedProxyTopology
    ) -> None:
        with _client(mtls_fixtures, "client_one_uri_san") as client:
            response = client.get(f"https://127.0.0.1:{topology.port}/unrelated-path")
        assert response.status_code == 404
        assert topology.backend.read_request_log() == []

    def test_unsupported_method_on_operation_aware_route_is_not_forwarded(
        self, mtls_fixtures: MTLSFixtureSet, topology: TrustedProxyTopology
    ) -> None:
        with _client(mtls_fixtures, "client_one_uri_san") as client:
            response = client.get(f"https://127.0.0.1:{topology.port}/v1/evaluate/operation-aware")
        assert response.status_code in (403, 405)
        assert topology.backend.read_request_log() == []


class TestAuthorizationHeaderPreservation:
    """Step 13: nginx forwards Authorization unchanged, independent of the
    certificate-handoff mechanism. Transport-only -- this suite never
    validates the token."""

    def test_synthetic_authorization_header_reaches_backend_unchanged(
        self, mtls_fixtures: MTLSFixtureSet, topology: TrustedProxyTopology
    ) -> None:
        with _client(mtls_fixtures, "client_one_uri_san") as client:
            response = client.post(
                f"https://127.0.0.1:{topology.port}/v1/evaluate/operation-aware",
                headers={"Authorization": _SYNTHETIC_BEARER_VALUE},
            )
        assert response.status_code == 200
        body = response.json()
        assert body["authorization_header"] == _SYNTHETIC_BEARER_VALUE
        # And independently, the certificate identity is still correctly
        # derived on the very same request -- the two facts travel the
        # proxy hop independently of one another.
        assert body["producer_uri_san"] == ONE_URI_SAN


def _process_tcp_listening_inodes(pid: int) -> set[int]:
    """Return the set of socket inodes in LISTEN state that belong to
    process *pid*, via ``/proc`` introspection (Linux-only).

    Cross-references two ``/proc`` facts, each read exactly once: every
    system-wide TCP socket currently in ``LISTEN`` state
    (``/proc/net/tcp[6]``, state ``0A``), and every open file descriptor
    *pid* holds that points at a socket inode (``/proc/<pid>/fd/*`` ->
    ``socket:[<inode>]`` symlinks). The intersection is exactly "does this
    process have a listening TCP socket open" -- a bounded, single-purpose
    check, not general port-scanning infrastructure.
    """
    listen_inodes: set[int] = set()
    for proto_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(proto_file).read_text(encoding="utf-8").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                continue
            state = fields[3]
            if state == "0A":  # TCP_LISTEN
                listen_inodes.add(int(fields[9]))

    proc_fd_inodes: set[int] = set()
    fd_dir = Path(f"/proc/{pid}/fd")
    try:
        fd_entries = list(fd_dir.iterdir())
    except OSError:
        return set()
    for fd_path in fd_entries:
        try:
            target = fd_path.readlink().as_posix()
        except OSError:
            continue
        if target.startswith("socket:["):
            proc_fd_inodes.add(int(target[len("socket:[") : -1]))

    return listen_inodes & proc_fd_inodes


class TestBackendIsolation:
    """Step 11: the reference trusted-proxy backend is not network
    reachable over TCP; the only way to reach it is through nginx's
    Unix-socket upstream connection."""

    def test_backend_process_opens_no_tcp_listener(self, topology: TrustedProxyTopology) -> None:
        if sys.platform != "linux":
            pytest.skip("TCP-listener introspection via /proc is Linux-only")
        assert topology.paths.backend_socket_path.exists()
        listening = _process_tcp_listening_inodes(topology.backend.pid)
        assert listening == set(), (
            "the trusted-proxy backend process has an open TCP listening socket "
            f"(inodes={listening}); it must open only its Unix domain socket"
        )

    def test_backend_reachable_only_through_nginx_not_directly(
        self, mtls_fixtures: MTLSFixtureSet, topology: TrustedProxyTopology
    ) -> None:
        # A direct HTTPS connection to nginx's own listener with a trusted
        # client certificate succeeds (proving the topology is up)...
        with _client(mtls_fixtures, "client_one_uri_san") as client:
            response = client.post(
                f"https://127.0.0.1:{topology.port}/v1/evaluate/operation-aware",
                headers={"Authorization": _SYNTHETIC_BEARER_VALUE},
            )
        assert response.status_code == 200

        # ...and there is no parallel plaintext-HTTP route to the backend
        # process itself: attempting plain HTTP against nginx's own (TLS
        # only) port fails at the transport level, and no other port is
        # published by this topology for the backend.
        with pytest.raises(httpx.TransportError):
            httpx.get(f"http://127.0.0.1:{topology.port}/v1/evaluate/operation-aware", timeout=2)


def test_rendering_helper_rejects_unknown_placeholder(tmp_path: Path) -> None:
    """Guards the harness itself: a mismatched template/substitution-map
    pair must fail loudly rather than silently render a broken/partial
    configuration (belt-and-suspenders for Step 17's determinism
    requirement)."""
    with pytest.raises(ValueError, match="does not reference placeholder"):
        render_nginx_config({"NOT_A_REAL_TOKEN": "x"})
