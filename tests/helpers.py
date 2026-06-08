"""Shared test helper classes for basis-gateway tests.

This module is importable as ``from helpers import ...`` from any test file
because pytest adds the ``tests/`` directory to sys.path when tests/ has no
__init__.py (importmode=prepend, the default).
"""

from __future__ import annotations

from typing import Any


class MockVerifier:
    """Test double for OIDCVerifier. Returns pre-configured claims."""

    def __init__(self, claims: dict[str, Any]) -> None:
        self._claims = claims
        self._should_raise: Exception | None = None

    def set_raise(self, exc: Exception) -> None:
        self._should_raise = exc

    def clear_raise(self) -> None:
        self._should_raise = None

    def verify(self, token: str) -> dict[str, Any]:
        if self._should_raise is not None:
            raise self._should_raise
        return dict(self._claims)
