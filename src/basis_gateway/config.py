"""Configuration loading and validation for basis-gateway.

All configuration is sourced from environment variables.
Missing required variables abort startup with a clear error message.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class AuthMode(str, Enum):
    """Runtime authentication mode: which verifier authenticates Bearer tokens.

    - ``OIDC`` — the pre-existing OIDC/JWT verifier path (default). Selecting
      this mode (or leaving ``AUTH_MODE`` unset) preserves exactly the
      pre-existing behavior of every deployment that predates this enum.
    - ``BASIS_LOCAL_TOKEN`` — verifies signed BASIS-local identity tokens
      issued by ``basis-identity`` (see
      ``basis_gateway.auth.basis_local_token``), instead of contacting an
      external OIDC provider.

    An unrecognized value is rejected by pydantic at ``GatewayConfig``
    construction — there is no silent default and no token-shape sniffing to
    infer a mode at runtime.
    """

    OIDC = "oidc"
    BASIS_LOCAL_TOKEN = "basis_local_token"


class GatewayConfig(BaseSettings):  # type: ignore[misc]
    """Runtime configuration for basis-gateway.

    Loaded from environment variables at startup. Defaults are safe for local
    development. Required variables abort startup if missing.
    """

    model_config = SettingsConfigDict(
        env_prefix="",
        case_sensitive=False,
        populate_by_name=True,
    )

    service_name: str = Field(default="basis-gateway")
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000, ge=1, le=65535)
    log_level: str = Field(default="INFO")
    environment: Literal["local", "development", "staging", "production"] = Field(default="local")

    # Runtime authentication mode. Selects which verifier authenticates
    # Bearer tokens at /v1/evaluate: "oidc" (default, pre-existing behavior)
    # or "basis_local_token". Explicit configuration only — never inferred
    # from a token's shape.
    auth_mode: AuthMode = Field(default=AuthMode.OIDC, alias="AUTH_MODE")

    # OIDC / JWT configuration.
    # Optional in Phase 2: absence does not break /health or the service skeleton.
    # Required when AUTH_MODE=oidc (the default) and evaluation is enabled.
    oidc_issuer: str | None = Field(default=None, alias="OIDC_ISSUER")
    oidc_audience: str | None = Field(default=None, alias="OIDC_AUDIENCE")
    oidc_jwks_uri: str | None = Field(default=None, alias="OIDC_JWKS_URI")
    jwks_cache_ttl_seconds: float = Field(default=300.0, alias="JWKS_CACHE_TTL_SECONDS", gt=0)

    # BASIS-local token trust configuration. Only required when
    # AUTH_MODE=basis_local_token; not required (and not validated) in the
    # default "oidc" mode. See docs/basis-local-token-trust.md for the
    # verifier this configures and basis_gateway.auth.runtime for how it is
    # constructed and wired into request authentication.
    basis_local_token_issuer: str | None = Field(default=None, alias="BASIS_LOCAL_TOKEN_ISSUER")
    # Comma-separated when more than one audience entry is required.
    basis_local_token_audience: str | None = Field(default=None, alias="BASIS_LOCAL_TOKEN_AUDIENCE")
    # A JSON object string mapping key id to PEM-encoded public key, e.g.
    # {"basis-identity-key-1": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}.
    # This is the smallest env-var-friendly shape for multiline PEM values;
    # no file-based key loading or JWKS fetching is supported.
    basis_local_token_public_keys_json: str | None = Field(
        default=None, alias="BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON"
    )
    # Comma-separated algorithm allow-list. "none" and any symmetric "HS*"
    # algorithm are always rejected regardless of this setting.
    basis_local_token_allowed_algorithms: str = Field(
        default="RS256", alias="BASIS_LOCAL_TOKEN_ALLOWED_ALGORITHMS"
    )
    basis_local_token_leeway_seconds: int = Field(
        default=0, alias="BASIS_LOCAL_TOKEN_LEEWAY_SECONDS", ge=0
    )

    # Policy configuration.
    policy_version: str | None = Field(default=None, alias="POLICY_VERSION")

    # Path to the JSON policy file loaded at startup.
    # Optional when evaluation endpoint is disabled.
    # Required when evaluation endpoint is enabled (OIDC_ISSUER set).
    policy_path: str | None = Field(default=None, alias="POLICY_PATH")

    # Audit failure escalation configuration.
    # Number of consecutive audit write failures before readiness degrades.
    # Must be >= 1. Default: 10.
    audit_failure_threshold: int = Field(default=10, alias="AUDIT_FAILURE_THRESHOLD", ge=1)

    # When True, a degraded audit writer causes /v1/evaluate to return 503.
    # When False (default), only /ready is affected by audit degradation.
    audit_fail_closed: bool = Field(default=False, alias="AUDIT_FAIL_CLOSED")

    # When True, the evaluation endpoint is considered enabled and its
    # auth-mode-appropriate configuration + policy are required. Derived at
    # validation time; not a direct env var.
    @property
    def evaluation_enabled(self) -> bool:
        """True when the /v1/evaluate endpoint requires full initialization.

        In "basis_local_token" mode, selecting the mode is itself an
        explicit choice to enable evaluation. In the default "oidc" mode,
        evaluation is enabled only when OIDC_ISSUER is set (unchanged from
        pre-existing behavior).
        """
        if self.auth_mode == AuthMode.BASIS_LOCAL_TOKEN:
            return True
        return self.oidc_issuer is not None

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        upper = v.upper()
        if upper not in _VALID_LOG_LEVELS:
            raise ValueError(
                f"Invalid LOG_LEVEL {v!r}. Must be one of: {', '.join(sorted(_VALID_LOG_LEVELS))}"
            )
        return upper


class EvaluationConfigError(Exception):
    """Raised when evaluation is enabled but required configuration is missing."""


def validate_evaluation_config(config: GatewayConfig) -> None:
    """Raise EvaluationConfigError if evaluation is enabled and config is incomplete.

    Behavior depends on ``config.auth_mode``:

    - ``oidc`` (default): evaluation is considered enabled when OIDC_ISSUER
      is set; POLICY_PATH must also be provided. Unchanged from pre-existing
      behavior. BASIS-local token settings are not required or validated.
    - ``basis_local_token``: selecting this mode is itself an explicit
      choice to enable evaluation, so BASIS_LOCAL_TOKEN_ISSUER,
      BASIS_LOCAL_TOKEN_AUDIENCE, BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON, and
      POLICY_PATH are all required. OIDC settings are not required or
      validated. This function checks presence only — deeper validation
      (rejecting ``alg=none``, symmetric ``HS*`` algorithms, malformed JSON,
      private-key-shaped material, etc.) happens when the trust config is
      actually constructed; see
      ``basis_gateway.auth.runtime.build_basis_local_token_trust_config``.

    Fail early; do not allow partial init.
    """
    if config.auth_mode == AuthMode.BASIS_LOCAL_TOKEN:
        missing = [
            name
            for name, value in (
                ("BASIS_LOCAL_TOKEN_ISSUER", config.basis_local_token_issuer),
                ("BASIS_LOCAL_TOKEN_AUDIENCE", config.basis_local_token_audience),
                (
                    "BASIS_LOCAL_TOKEN_PUBLIC_KEYS_JSON",
                    config.basis_local_token_public_keys_json,
                ),
            )
            if not value
        ]
        if missing:
            raise EvaluationConfigError(
                f"{', '.join(missing)} required when AUTH_MODE=basis_local_token."
            )
        if not config.policy_path:
            raise EvaluationConfigError(
                "POLICY_PATH is required when AUTH_MODE=basis_local_token. "
                "Set POLICY_PATH to the path of your JSON policy file."
            )
        return

    # auth_mode == AuthMode.OIDC (default).
    if config.oidc_issuer is not None and not config.policy_path:
        raise EvaluationConfigError(
            "POLICY_PATH is required when OIDC_ISSUER is configured. "
            "Set POLICY_PATH to the path of your JSON policy file."
        )


def load_config() -> GatewayConfig:
    """Load and validate gateway configuration from environment variables."""
    return GatewayConfig()


def configure_logging(log_level: str) -> None:
    """Configure root logging at the specified level."""
    numeric = getattr(logging, log_level, logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
