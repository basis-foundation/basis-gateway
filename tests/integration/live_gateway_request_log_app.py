"""Test-only ASGI wrapper around the real ``basis_gateway.main:app`` for
Phase 1B.3's real-NGINX live-gateway integration suite
(``tests/integration/test_producer_mtls_live_gateway.py``).

Phase 1B.2's minimal test stand-in backend (``trusted_proxy_app.py``) writes
one ``"<method> <path>\\n"`` line per request it receives to the file named
by the ``BASIS_TEST_REQUEST_LOG_PATH`` environment variable
(``TrustedProxyBackend.read_request_log()`` reads it back) -- a test-only
signal proving exactly which requests reached the Unix-socket backend.

Phase 1B.3 deliberately reuses that same harness (``trusted_proxy_harness.py``)
but points the Unix-socket backend at the REAL ``basis_gateway.main:app``
instead of that stand-in (see this suite's module docstring and
docs/implementation/producer-mtls-phase-1b3.md). The real gateway
application has, and must have, no equivalent facility -- production code
must never write to a test-only request log. This module exists solely to
give ``read_request_log()`` something to read in that topology, without
adding any such instrumentation to ``basis_gateway.main`` or any other
production module.

This wrapper is a plain ASGI passthrough:

  - it records only the HTTP method and path of each HTTP-scope request,
    exactly like ``trusted_proxy_app._record_request`` does;
  - it never reads, logs, or mutates the ``Authorization`` header, the
    ``X-BASIS-Producer-Client-Cert`` header, or the request body;
  - it forwards the ASGI ``scope``/``receive``/``send`` to the real
    application completely unchanged, so the request the real gateway
    receives, and the response it produces, are identical to what they
    would be without this wrapper in front of it;
  - it does not participate in authentication, mTLS producer trust, or any
    authorization decision -- those all remain entirely inside the real
    ``basis_gateway.main:app`` this module imports and delegates to.

Kept strictly under ``tests/`` -- never imported by, or added to, any
``src/basis_gateway`` production module.
"""

from __future__ import annotations

import os
from pathlib import Path

from starlette.types import Receive, Scope, Send

from basis_gateway.main import app as _gateway_app


def _record_request(scope: Scope) -> None:
    """Append ``"<method> <path>\\n"`` to ``BASIS_TEST_REQUEST_LOG_PATH``,
    mirroring ``trusted_proxy_app._record_request`` exactly (same env var,
    same one-line-per-request format) so ``read_request_log()`` behaves
    identically regardless of which backend produced the log."""
    log_path = os.environ.get("BASIS_TEST_REQUEST_LOG_PATH")
    if not log_path:
        return
    method = scope.get("method", "")
    path = scope.get("path", "")
    with Path(log_path).open("a", encoding="utf-8") as handle:
        handle.write(f"{method} {path}\n")


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    """Record method+path for HTTP requests, then hand off to the real
    gateway application unchanged. Non-HTTP scopes (e.g. ``lifespan``) are
    forwarded without recording, so application startup/shutdown behaves
    exactly as it would without this wrapper."""
    if scope["type"] == "http":
        _record_request(scope)
    await _gateway_app(scope, receive, send)
