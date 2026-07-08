"""Readiness state for basis-gateway.

Tracks whether the application and its required components are ready to
serve requests. All *registered* components must be ready for the overall
state to be ready — a component that was never registered (e.g. an
inactive auth mode's components) does not block readiness.

Components tracked:
  - "configuration_loaded"          — startup config validated successfully
  - "oidc_configured"                — OIDC verifier initialized
                                        (auth_mode="oidc" only; optional when eval disabled)
  - "jwks_available"                 — JWKS endpoint reachable and keys loaded
                                        (auth_mode="oidc" only)
  - "basis_local_token_configured"   — BASIS-local token trust config validated
                                        (auth_mode="basis_local_token" only)
  - "evaluator_initialized"          — EnforcementPoint constructed
  - "policy_loaded"                  — policy file loaded and parsed successfully

Only the components for the currently configured auth_mode are ever
registered, so "oidc_configured"/"jwks_available" never block readiness in
"basis_local_token" mode, and "basis_local_token_configured" never blocks
readiness in "oidc" mode.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class ReadinessState:
    """Thread-safe multi-component readiness tracker."""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)
    _components: dict[str, bool] = field(default_factory=dict)
    _reasons: dict[str, str] = field(default_factory=dict)

    def mark_ready(self, component: str = "app") -> None:
        with self._lock:
            self._components[component] = True
            self._reasons.pop(component, None)

    def mark_not_ready(
        self,
        reason: str = "application not initialized",
        component: str = "app",
    ) -> None:
        with self._lock:
            self._components[component] = False
            self._reasons[component] = reason

    @property
    def is_ready(self) -> bool:
        """True only when all registered components are ready."""
        with self._lock:
            if not self._components:
                return False
            return all(self._components.values())

    @property
    def reason(self) -> str:
        """Human-readable reason string for the first not-ready component."""
        with self._lock:
            for component, ready in self._components.items():
                if not ready:
                    return self._reasons.get(component, f"{component} not ready")
            return ""

    @property
    def all_reasons(self) -> dict[str, str]:
        """Reasons for every not-ready component, keyed by component name.

        Returns an empty dict when the service is fully ready.
        """
        with self._lock:
            return {
                component: self._reasons.get(component, f"{component} not ready")
                for component, ready in self._components.items()
                if not ready
            }

    @property
    def components(self) -> dict[str, bool]:
        """Snapshot of current component readiness states."""
        with self._lock:
            return dict(self._components)


# Module-level singleton shared by the FastAPI app and tests.
_state = ReadinessState()


def get_readiness_state() -> ReadinessState:
    return _state


def reset_readiness_state() -> None:
    """Reset to a clean not-ready state. For tests only."""
    with _state._lock:
        _state._components.clear()
        _state._reasons.clear()
