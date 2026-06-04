"""Correlation ID middleware for basis-gateway.

Assigns a UUIDv4 correlation ID to every incoming request and ensures
``X-Correlation-ID`` is present on every outgoing response.

Design decisions (Phase 7):
- The gateway generates the correlation ID unconditionally.
- Caller-supplied ``X-Correlation-ID`` request headers are ignored.
  External correlation IDs are not trusted as authoritative input.
  This is intentional: accepting caller-supplied correlation IDs would
  allow external parties to influence the audit trail. Any change to
  this policy requires an explicit architecture decision.
- The generated ID is stored at ``request.state.correlation_id`` so that
  route handlers can read it without generating a second UUID.
- The middleware adds ``X-Correlation-ID`` to the response unconditionally,
  covering all response paths including 400, 401, 503, and 500 responses
  that were previously missing the header.

Typing note:
  Starlette does not ship a ``py.typed`` marker in all versions, so its
  modules may be untyped under strict mypy.  ``BaseHTTPMiddleware`` is
  imported with a targeted ``type: ignore[import-untyped]`` to suppress
  the missing-stubs diagnostic without weakening global strictness.
  The ``dispatch`` signature uses ``Any`` for the request and response
  parameters rather than importing ``starlette.requests.Request`` /
  ``starlette.responses.Response`` directly, avoiding additional
  starlette-stub dependencies.

Limitations:
- Unhandled exceptions that escape FastAPI's own exception handling may
  result in a Starlette 500 response constructed outside this middleware's
  dispatch path. In practice, FastAPI catches all exceptions before they
  reach BaseHTTPMiddleware, so this is not expected to occur.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware  # type: ignore[import-not-found, import-untyped]


class CorrelationMiddleware(BaseHTTPMiddleware):  # type: ignore[misc]
    """Attach a UUIDv4 correlation ID to every request and response.

    Sets ``request.state.correlation_id`` before passing the request to
    the next handler, then adds ``X-Correlation-ID`` to the response.
    """

    async def dispatch(
        self,
        request: Any,
        call_next: Callable[..., Any],
    ) -> Any:
        correlation_id = str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
