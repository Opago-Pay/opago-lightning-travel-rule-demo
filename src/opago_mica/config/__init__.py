"""
Configuration Loader

Loads and validates all required environment variables using pydantic-settings.
Provides a typed, immutable config object used throughout the application.

Required environment variables are documented in .env.example.
Call ``load_config()`` once at startup; thereafter use the exported ``config``
singleton or ``get_config()``.
"""

from __future__ import annotations

import logging
import os
from typing import ClassVar, Literal

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from opago_mica.utils.runtime_env import current_app_env

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sub-config models
# ---------------------------------------------------------------------------


class SparkConfig(BaseSettings):
    """Shared Spark / Lightning configuration."""

    model_config = SettingsConfigDict(
        env_prefix="SPARK_",
        populate_by_name=True,
        extra="ignore",
    )

    network: Literal["MAINNET", "REGTEST", "SIGNET"] = "MAINNET"
    node_binary: str = "node"
    bridge_script: str | None = Field(
        default=None,
        validation_alias=AliasChoices("SPARK_BRIDGE_SCRIPT", "BRIDGE_SCRIPT"),
    )


class _SparkWalletConfig(BaseSettings):
    """Role-scoped Spark wallet secrets."""

    model_config = SettingsConfigDict(
        populate_by_name=True,
        extra="ignore",
    )

    mnemonic_env_name: ClassVar[str] = "SPARK_MNEMONIC"

    mnemonic: str | None = None
    master_key: str | None = None

    @field_validator("mnemonic")
    @classmethod
    def _validate_mnemonic(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized_words = value.strip().split()
        if len(normalized_words) not in {12, 24}:
            raise ValueError(f"{cls.mnemonic_env_name} must contain 12 or 24 words")
        if not all(word.isalpha() and word.islower() for word in normalized_words):
            raise ValueError(
                f"{cls.mnemonic_env_name} must contain lowercase alphabetic words "
                "separated by spaces"
            )
        return " ".join(normalized_words)


class SenderSparkConfig(_SparkWalletConfig):
    """Sender wallet secrets."""

    model_config = SettingsConfigDict(
        env_prefix="SENDER_SPARK_",
        populate_by_name=True,
        extra="ignore",
    )

    mnemonic_env_name: ClassVar[str] = "SENDER_SPARK_MNEMONIC"


class ReceiverSparkConfig(_SparkWalletConfig):
    """Receiver wallet secrets."""

    model_config = SettingsConfigDict(
        env_prefix="RECEIVER_SPARK_",
        populate_by_name=True,
        extra="ignore",
    )

    mnemonic_env_name: ClassVar[str] = "RECEIVER_SPARK_MNEMONIC"


class VASPConfig(BaseSettings):
    """VASP identity and UMA protocol configuration."""

    model_config = SettingsConfigDict(
        env_prefix="VASP_",
        populate_by_name=True,
        extra="ignore",
    )

    domain: str = Field(
        ...,
        min_length=3,
        description="VASP domain is required (e.g. vasp.example.com)",
    )

    #: PEM-encoded PKCS#8 EC P-256 private key for JWS signing.
    signing_key_pem: str = Field(
        validation_alias=AliasChoices("UMA_SIGNING_KEY", "VASP_SIGNING_KEY_PEM"),
    )

    #: PEM-encoded PKCS#8 EC P-256 private key for JWE encryption (ECDH-ES).
    encryption_key_pem: str = Field(
        validation_alias=AliasChoices("UMA_ENCRYPTION_KEY", "VASP_ENCRYPTION_KEY_PEM"),
    )

    #: UMA protocol version (default: '1.0').
    uma_version: str = Field(default="1.0", alias="UMA_VERSION")

    #: Travel rule threshold in EUR (default: 1000 per EU TFR 2023/1113).
    travel_rule_threshold_eur: float = Field(
        default=1000.0,
        ge=0,
        alias="TRAVEL_RULE_THRESHOLD_EUR",
    )

    #: LEI of this VASP (optional but recommended for B2B).
    lei_code: str | None = Field(default=None, min_length=20, max_length=20)

    #: Legal name of this VASP.
    legal_name: str | None = None

    #: ISO 3166-1 alpha-2 jurisdiction of this VASP.
    jurisdiction: str = Field(default="DE", min_length=2, max_length=2)

    @field_validator("signing_key_pem", "encryption_key_pem", mode="before")
    @classmethod
    def _validate_pem(cls, v: str) -> str:
        if v and not v.startswith("-----BEGIN PRIVATE KEY-----"):
            raise ValueError(
                "Must be a PEM-encoded PKCS#8 key starting with "
                "'-----BEGIN PRIVATE KEY-----'"
            )
        return v


class ServerConfig(BaseSettings):
    """HTTP server configuration."""

    model_config = SettingsConfigDict(
        populate_by_name=True,
        extra="ignore",
    )

    port: int = Field(default=3000, ge=1, le=65535, alias="PORT")
    host: str = Field(default="0.0.0.0", alias="HOST")
    #: Base URL of this service (used for self-referential URLs in UMA responses).
    base_url: str | None = Field(default=None, alias="BASE_URL")

    @field_validator("base_url", mode="before")
    @classmethod
    def _validate_base_url(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        # Must start with http:// or https://
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError(
                f"base_url must be a valid URL starting with http:// or https://, got: '{v}'"
            )
        return v


class EIDASConfig(BaseSettings):
    """eIDAS wallet integration configuration."""

    model_config = SettingsConfigDict(
        env_prefix="EIDAS_",
        populate_by_name=True,
        extra="ignore",
    )

    enabled: bool = False
    issuer_url: str | None = None
    wallet_id: str | None = None

    @model_validator(mode="after")
    def _require_issuer_url_when_enabled(self) -> EIDASConfig:
        if self.enabled and self.issuer_url is None:
            raise ValueError("EIDAS_ISSUER_URL is required when EIDAS_ENABLED=true")
        return self


class ObservabilityConfig(BaseSettings):
    """Observability / logging configuration."""

    model_config = SettingsConfigDict(
        populate_by_name=True,
        extra="ignore",
    )

    log_level: Literal["error", "warn", "info", "http", "verbose", "debug", "silly"] = Field(
        default="info",
        alias="LOG_LEVEL",
    )

    #: Whether to emit structured JSON logs (default: True in production).
    json_logs: bool = Field(
        default_factory=lambda: current_app_env() == "production",
        alias="JSON_LOGS",
    )

    #: Optional OpenTelemetry collector endpoint.
    otel_endpoint: str | None = Field(default=None, alias="OTEL_ENDPOINT")


class DatabaseConfig(BaseSettings):
    """Database / persistence configuration (for audit logs and compliance reports)."""

    model_config = SettingsConfigDict(
        populate_by_name=True,
        extra="ignore",
    )

    #: SQLite file path (default) or PostgreSQL connection string.
    url: str = Field(default="sqlite:./data/opago-mica.db", alias="DATABASE_URL")

    #: Max DB connections (for PG).
    max_connections: int = Field(default=5, gt=0, alias="DATABASE_MAX_CONNECTIONS")


class AppConfig(BaseSettings):
    """Full application configuration."""

    model_config = SettingsConfigDict(
        populate_by_name=True,
        extra="ignore",
    )

    node_env: Literal["development", "test", "production"] = Field(
        default="development",
        alias="APP_ENV",
    )

    spark: SparkConfig = Field(default_factory=SparkConfig)
    sender_spark: SenderSparkConfig = Field(default_factory=SenderSparkConfig)
    receiver_spark: ReceiverSparkConfig = Field(default_factory=ReceiverSparkConfig)
    vasp: VASPConfig = Field(default_factory=lambda: VASPConfig(domain="localhost"))
    server: ServerConfig = Field(default_factory=ServerConfig)
    eidas: EIDASConfig = Field(default_factory=EIDASConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

_config: AppConfig | None = None


def load_config() -> AppConfig:
    """
    Loads, validates, and returns the application configuration.

    On first call, validates all environment variables and raises a
    descriptive error if any required variable is missing or invalid.

    Subsequent calls return the cached singleton.

    Raises:
        ValidationError: if environment variables fail validation.
    """
    global _config, config
    if _config is not None:
        config = _config
        return _config

    from pydantic import ValidationError

    try:
        spark = SparkConfig()
        sender_spark = SenderSparkConfig()
        receiver_spark = ReceiverSparkConfig()
        vasp_domain = os.environ.get("VASP_DOMAIN", "")
        vasp = VASPConfig(domain=vasp_domain)
        server = ServerConfig()
        eidas = EIDASConfig()
        observability = ObservabilityConfig()
        database = DatabaseConfig()

        _config = AppConfig(
            node_env=current_app_env(),  # type: ignore[arg-type]
            spark=spark,
            sender_spark=sender_spark,
            receiver_spark=receiver_spark,
            vasp=vasp,
            server=server,
            eidas=eidas,
            observability=observability,
            database=database,
        )
    except (ValidationError, Exception) as exc:
        message = f"Configuration validation failed:\n{exc}"
        _log.error(message)
        raise

    _log.info(
        "Configuration loaded",
        extra={
            "node_env": _config.node_env,
            "vasp_domain": _config.vasp.domain,
            "spark_network": _config.spark.network,
            "travel_rule_threshold_eur": _config.vasp.travel_rule_threshold_eur,
            "eidas_enabled": _config.eidas.enabled,
        },
    )

    config = _config
    return _config


def get_config() -> AppConfig:
    """
    Returns the cached configuration.
    Raises ``RuntimeError`` if ``load_config()`` has not been called yet.
    """
    if _config is None:
        raise RuntimeError("Config not loaded. Call load_config() at application startup.")
    return _config


def reset_config() -> None:
    """Resets the cached config (used in tests)."""
    global _config, config
    _config = None
    config = None


# ---------------------------------------------------------------------------
# Optional module-level singleton
# ---------------------------------------------------------------------------

#: Optional module-level config reference.
#:
#: The package no longer validates configuration at import time because helper
#: scripts and utility imports may run before the full environment is prepared.
#: Call ``load_config()`` explicitly during application startup.
config: AppConfig | None = None
