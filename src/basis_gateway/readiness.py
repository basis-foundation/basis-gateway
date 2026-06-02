"""Readiness state for basis-gateway.

Tracks whether the application is ready to serve requests.
Set to ready after successful startup; cleared on shutdown.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class ReadinessState:
    """Thread-safe container for gateway readiness."""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)
    _ready: bool = field(default=False)
    _reason: str = field(default="application not initialized")

    def mark_ready(self) -> None:
        with self._lock:
            self._ready = True
            self._reason = ""

    def mark_not_ready(self, reason: str = "application not initialized") -> None:
        with self._lock:
            self._ready = False
            self._reason = reason

    @property
    def is_ready(self) -> bool:
        with self._lock:
            return self._ready

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason


# Module-level singleton shared by the FastAPI app and tests.
_state = ReadinessState()


def get_readiness_state() -> ReadinessState:
    """Return the module-level readiness state."""
    return _state


def reset_readiness_state() -> None:
    """Reset module-level state to not-ready. Intended for use in tests only."""
    _state.mark_not_ready()
