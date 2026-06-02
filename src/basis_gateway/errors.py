"""Error types and HTTP error response helpers for basis-gateway.

All error responses are sanitized: no stack traces, internal type names,
or kernel internals are exposed to callers.
"""

from __future__ import annotations


class GatewayError(Exception):
    """Base class for all basis-gateway errors."""


class ConfigurationError(GatewayError):
    """Raised when configuration is invalid or incomplete at startup."""
