"""
Structured Logger

Configures a structlog logger with:
- JSON output for production (machine-parseable, log aggregation-friendly)
- Pretty-print colorised output for local development
- Log levels controlled by LOG_LEVEL environment variable
- Standard metadata fields: service, version, environment
- Sensitive field redaction
- Audit logger with compliance event helper

Usage::

    from opago_mica.utils.logger import logger, create_component_logger
    logger.info("Payment initiated", transaction_id=txn_id, amount=amount)
    logger.error("Signature verification failed", error=str(err))
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import UTC
from typing import Any

import structlog

from opago_mica.utils.runtime_env import current_app_env

# ---------------------------------------------------------------------------
# Determine environment
# ---------------------------------------------------------------------------

_APP_ENV: str = current_app_env()
_LOG_LEVEL_STR: str = os.environ.get(
    "LOG_LEVEL", "info" if _APP_ENV == "production" else "debug"
)
_SERVICE_NAME: str = os.environ.get("SERVICE_NAME", "opago-mica")
_LEGACY_PACKAGE_VERSION_ENV = "npm_package_version"
_SERVICE_VERSION: str = (
    os.environ.get("NPM_PACKAGE_VERSION")
    or os.environ.get(_LEGACY_PACKAGE_VERSION_ENV)
    or "0.1.0"
)

# Map log-level strings (including Winston-compatible names) to Python stdlib levels.
_LEVEL_MAP: dict[str, int] = {
    "error": logging.ERROR,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "info": logging.INFO,
    "http": logging.INFO,
    "verbose": logging.DEBUG,
    "debug": logging.DEBUG,
    "silly": logging.DEBUG,
}
_LOG_LEVEL: int = _LEVEL_MAP.get(_LOG_LEVEL_STR.lower(), logging.DEBUG)

# ---------------------------------------------------------------------------
# Sensitive field redaction
# ---------------------------------------------------------------------------

SENSITIVE_FIELDS: frozenset[str] = frozenset(
    [
        "password",
        "private_key",
        "privateKey",
        "signing_key",
        "signingKey",
        "encryption_key",
        "encryptionKey",
        "secret",
        "token",
        "access_token",
        "accessToken",
        "refresh_token",
        "refreshToken",
        "api_key",
        "apiKey",
        "jwe",
        "encrypted_travel_rule_info",
        "encryptedTravelRuleInfo",
    ]
)

_REDACTED = "[REDACTED]"


def _redact_sensitive(
    logger: Any,  # noqa: ANN401
    method: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """
    structlog processor that redacts sensitive fields before logging.
    Applies to top-level keys and one level of nested objects.
    """
    for key in list(event_dict.keys()):
        if key in SENSITIVE_FIELDS:
            event_dict[key] = _REDACTED
        else:
            value = event_dict[key]
            if isinstance(value, dict):
                for nested_key in list(value.keys()):
                    if nested_key in SENSITIVE_FIELDS:
                        value[nested_key] = _REDACTED
    return event_dict


# ---------------------------------------------------------------------------
# Add standard service metadata
# ---------------------------------------------------------------------------


def _add_service_meta(
    logger: Any,  # noqa: ANN401
    method: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """Adds standard metadata fields to every log entry."""
    event_dict.setdefault("service", _SERVICE_NAME)
    event_dict.setdefault("version", _SERVICE_VERSION)
    event_dict.setdefault("environment", _APP_ENV)
    return event_dict


# ---------------------------------------------------------------------------
# Error serialisation
# ---------------------------------------------------------------------------


def _serialize_errors(
    logger: Any,  # noqa: ANN401
    method: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """Serialises Exception objects so that message and stack are captured."""
    err = event_dict.get("error")
    if isinstance(err, BaseException):
        import traceback

        event_dict["error"] = {
            "message": str(err),
            "name": type(err).__name__,
            "stack": "".join(traceback.format_exception(type(err), err, err.__traceback__)),
        }
    return event_dict


# ---------------------------------------------------------------------------
# Shared processor chain
# ---------------------------------------------------------------------------

_shared_processors: list[Any] = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    structlog.processors.TimeStamper(fmt="iso"),
    _add_service_meta,
    _serialize_errors,
    _redact_sensitive,
]

# ---------------------------------------------------------------------------
# Configure structlog
# ---------------------------------------------------------------------------

_is_production = _APP_ENV == "production"

structlog.configure(
    processors=[
        *_shared_processors,
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

# Configure stdlib root logger
_root_handler = logging.StreamHandler(stream=sys.stderr)
_root_handler.setFormatter(
    structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer()
            if _is_production
            else structlog.dev.ConsoleRenderer(colors=True),
        ],
        foreign_pre_chain=_shared_processors,
    )
)

logging.basicConfig(
    level=_LOG_LEVEL,
    handlers=[_root_handler],
    force=True,
)

# ---------------------------------------------------------------------------
# Logger instances
# ---------------------------------------------------------------------------

#: Root application logger.
logger: structlog.stdlib.BoundLogger = structlog.get_logger(_SERVICE_NAME)

# ---------------------------------------------------------------------------
# Child logger factory
# ---------------------------------------------------------------------------


def create_logger(
    component: str,
    **extra: Any,
) -> structlog.stdlib.BoundLogger:
    """
    Creates a child logger pre-scoped with a component name and optional
    extra metadata.

    Alias for :func:`create_component_logger` — used by pre-existing modules.

    Example::

        log = create_logger("UMAMiCAProtocol", vasp_domain=vasp_domain)
        log.info("Pay request created", transaction_id=txn_id)
    """
    return structlog.get_logger(_SERVICE_NAME).bind(component=component, **extra)


def create_component_logger(
    component: str,
    **extra: Any,
) -> structlog.stdlib.BoundLogger:
    """
    Creates a child logger pre-scoped with a component name and optional
    extra metadata.

    Example::

        log = create_component_logger("UMAMiCAProtocol", vasp_domain=vasp_domain)
        log.info("Pay request created", transaction_id=txn_id)
    """
    return structlog.get_logger(_SERVICE_NAME).bind(component=component, **extra)


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

#: Dedicated audit logger for compliance events.
#: In production these events should be forwarded to an immutable audit
#: log store (e.g. AWS CloudTrail, Azure Monitor, Splunk).
audit_logger: structlog.stdlib.BoundLogger = structlog.get_logger(_SERVICE_NAME).bind(
    log_type="audit"
)


def log_audit_event(event: str, **data: Any) -> None:
    """
    Log a compliance audit event with structured fields.

    Args:
        event: Human-readable event name (e.g. 'travel_rule_exchange_completed').
        **data: Arbitrary key-value metadata to include in the log entry.
    """
    from datetime import datetime

    audit_logger.info(
        event,
        audit_timestamp=datetime.now(tz=UTC).isoformat(),
        **data,
    )
