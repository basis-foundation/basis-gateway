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
    )

    service_name: str = Field(default="basis-gateway")
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000, ge=1, le=65535)
    log_level: str = Field(default="INFO")
    environment: Literal["local", "development", "staging", "production"] = Field(default="local")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        upper = v.upper()
        if upper not in _VALID_LOG_LEVELS:
            raise ValueError(
                f"Invalid LOG_LEVEL {v!r}. Must be one of: {', '.join(sorted(_VALID_LOG_LEVELS))}"
            )
        return upper


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
