"""Configuration loading and validation for basis-gateway.

All configuration is sourced from environment variables.
Missing required variables abort startup with a clear error message.
"""

from __future__ import annotations

import logging
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class GatewayConfig(BaseSettings):
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

    # OIDC / JWT configuration.
    # Optional in Phase 2: absence does not break /health or the service skeleton.
    # Phase 3 will require OIDC_ISSUER when /v1/evaluate is wired in.
    oidc_issuer: str | None = Field(default=None, alias="OIDC_ISSUER")
    oidc_audience: str | None = Field(default=None, alias="OIDC_AUDIENCE")
    oidc_jwks_uri: str | None = Field(default=None, alias="OIDC_JWKS_URI")
    jwks_cache_ttl_seconds: float = Field(default=300.0, alias="JWKS_CACHE_TTL_SECONDS", gt=0)

    # Policy configuration.
    policy_version: str | None = Field(default=None, alias="POLICY_VERSION")

    # Path to the JSON policy file loaded at startup.
    # Optional when evaluation endpoint is disabled.
    # Required when evaluation endpoint is enabled (OIDC_ISSUER set).
    policy_path: str | None = Field(default=None, alias="POLICY_PATH")

    # When True, the evaluation endpoint is considered enabled and OIDC + policy are required.
    # Derived at validation time; not a direct env var.
    @property
    def evaluation_enabled(self) -> bool:
        """True when the /v1/evaluate endpoint requires full initialization."""
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

    Evaluation is considered enabled when OIDC_ISSUER is set. In that case
    POLICY_PATH must also be provided. Fail early; do not allow partial init.
    """
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
