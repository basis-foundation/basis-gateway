"""Minimal ASGI test backend for the Phase 1B.2 trusted-proxy trust-boundary
integration suite (tests/integration/test_producer_mtls_trusted_proxy_boundary.py).

This is deliberately NOT a production endpoint and has no relationship to
``basis_gateway.main:app`` or the live ``POST /v1/evaluate/operation-aware``
route. It exists solely to prove, against a real NGINX process and a real
Unix-domain-socket backend, that:

  - the internal certificate-assertion retrieval primitive
    (``basis_gateway.auth.producer_mtls_trusted_proxy``) sees exactly the
    value nginx's ``$ssl_client_escaped_cert`` produced -- never a
    caller-supplied value;
  - composed with the already-released Phase 1B.1 pipeline
    (``basis_gateway.auth.producer_mtls``), that value decodes and parses
    to the expected URI SAN;
  - the ``Authorization`` header survives the proxy hop unchanged and
    independently of the certificate assertion.

It never returns raw certificate/PEM content in an HTTP response, and never
performs producer admission, ``OperationProducerTrust`` classification, or
any authorization decision -- all of that remains out of scope for Phase
1B.2 (see docs/implementation/producer-mtls-phase-1b2.md).

Every request this app receives is appended, one line per request, to the
file named by the ``BASIS_TEST_REQUEST_LOG_PATH`` environment variable, as
``"<method> <path>\\n"``. This is a test-only signal that lets the
integration suite assert exactly which requests reached the Unix-socket
backend at all -- for example, to prove a request nginx rejected at the TLS
or route level never reached this process.
"""

from __future__ import annotations

import os
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from basis_gateway.auth.producer_mtls import (
    ProducerCertificateError,
    decode_producer_certificate_assertion,
    derive_producer_identity,
    parse_producer_leaf_certificate,
)
from basis_gateway.auth.producer_mtls_trusted_proxy import (
    TrustedProxyAssertionError,
    retrieve_trusted_producer_certificate_assertion,
)


def _record_request(request: Request) -> None:
    log_path = os.environ.get("BASIS_TEST_REQUEST_LOG_PATH")
    if not log_path:
        return
    with Path(log_path).open("a", encoding="utf-8") as handle:
        handle.write(f"{request.method} {request.url.path}\n")


async def evaluate_operation_aware(request: Request) -> JSONResponse:
    """Test-only stand-in for ``POST /v1/evaluate/operation-aware``.

    Exercises exactly the Phase 1B.2 + Phase 1B.1 composition described in
    this module's docstring and reports the outcome as JSON -- never the
    raw certificate assertion itself.
    """
    _record_request(request)

    assertion_present = False
    assertion_error: str | None = None
    producer_uri_san: str | None = None

    try:
        assertion = retrieve_trusted_producer_certificate_assertion(
            request, trusted_proxy_enabled=True
        )
        if assertion is not None:
            assertion_present = True
            pem_bytes = decode_producer_certificate_assertion(assertion)
            certificate = parse_producer_leaf_certificate(pem_bytes)
            producer_uri_san = derive_producer_identity(certificate)
    except (TrustedProxyAssertionError, ProducerCertificateError) as exc:
        assertion_error = type(exc).__name__

    return JSONResponse(
        {
            "assertion_present": assertion_present,
            "assertion_error": assertion_error,
            "producer_uri_san": producer_uri_san,
            "authorization_header": request.headers.get("authorization"),
        }
    )


async def unrelated_route(request: Request) -> JSONResponse:
    """A route that must never be reachable through the dedicated producer
    mTLS listener (route-scope isolation). Exists only so a test that
    somehow bypasses nginx's own routing has something distinguishable to
    observe; the nginx reference configuration itself returns 404 for any
    path other than the operation-aware route without ever proxying here.
    """
    _record_request(request)
    return JSONResponse(
        {"unexpected": "this route must not be reachable through the producer mTLS listener"}
    )


app = Starlette(
    routes=[
        Route("/v1/evaluate/operation-aware", evaluate_operation_aware, methods=["POST"]),
        Route("/unrelated-path", unrelated_route, methods=["GET", "POST"]),
    ]
)
