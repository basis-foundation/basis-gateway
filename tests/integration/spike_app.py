"""Minimal ASGI spike application for the producer-mTLS certificate-exposure
spike (Phase 1A, docs/spikes/producer-mtls-certificate-exposure.md).

This is intentionally NOT a FastAPI/Starlette application and has no
relationship to ``basis_gateway.main:app``. It is a raw ASGI callable so the
spike measures exactly what the ASGI server (Uvicorn) exposes to *any* ASGI
application through the connection ``scope`` — unclouded by anything
FastAPI or Starlette might add or strip on top. It must never be imported by
production code and exists solely to be driven by
``tests/integration/test_producer_mtls_transport.py``.

Every request, regardless of method or path, receives a 200 JSON response
describing exactly what this application instance can observe about the
current connection:

    {
      "scope_keys": [...],        # sorted list of every top-level scope key
                                   # Uvicorn provided for this connection
      "scheme": "https" | "http",
      "has_extensions_key": bool, # is "extensions" present in scope at all?
      "extension_names": [...],   # sorted(scope.get("extensions", {}))
      "tls_extension": {...}|null,# scope["extensions"]["tls"], if present
                                   # (see the ASGI TLS extension spec,
                                   # https://asgi.readthedocs.io/en/latest/specs/tls.html)
      "headers": {...},           # every request header, verbatim, exactly
                                   # as this application received it — used
                                   # to prove whether an arbitrary caller can
                                   # supply cert-looking header values
      "client": [host, port]|null
    }

This handler never reaches into a real transport/SSLObject directly — it
only reports what arrived through the standard ASGI ``scope`` dict, which is
precisely the application-visible boundary Phase 1A investigates. If a
future Uvicorn version (or a patched protocol class) begins populating the
ASGI TLS extension, this same handler will start reporting it without any
change here.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any


async def app(
    scope: dict[str, Any],
    receive: Callable[[], Awaitable[dict[str, Any]]],
    send: Callable[[dict[str, Any]], Awaitable[None]],
) -> None:
    if scope["type"] != "http":
        return

    headers = {
        key.decode("latin-1"): value.decode("latin-1") for key, value in scope.get("headers", [])
    }
    extensions = scope.get("extensions") or {}

    body = json.dumps(
        {
            "scope_keys": sorted(scope.keys()),
            "scheme": scope.get("scheme"),
            "has_extensions_key": "extensions" in scope,
            "extension_names": sorted(extensions.keys()),
            "tls_extension": extensions.get("tls"),
            "headers": headers,
            "client": list(scope["client"]) if scope.get("client") else None,
        }
    ).encode("utf-8")

    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body})
