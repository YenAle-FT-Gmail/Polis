# polis/node/polis_node/config/logging.py
"""
Polis structured logging configuration.

Configures structlog with a processor chain that filters sensitive
fields from log output (Invariant 18: secrets are never logged).
"""

from __future__ import annotations

from typing import Any

import structlog


# Fields that must NEVER appear in log output
SENSITIVE_FIELDS: frozenset[str] = frozenset({
    "signing_key_private",
    "recovery_key_private",
    "recovery_mnemonic",
    "mnemonic",
    "private_key",
    "secret",
    "password",
    "token",
    "encrypted_key",
    "wrapped_key",
    "aes_key",
    "wrap_nonce",
    "recipient_private_key_hex",
})


def filter_sensitive_fields(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Structlog processor that redacts sensitive fields.

    Any key matching a known sensitive field name is replaced with
    ``"[REDACTED]"`` before the log event is emitted.

    Args:
        logger: The logger instance.
        method_name: The log method being called.
        event_dict: The event dictionary (mutated in place).

    Returns:
        The sanitized event dictionary.
    """
    for key in list(event_dict.keys()):
        if key.lower() in SENSITIVE_FIELDS:
            event_dict[key] = "[REDACTED]"
    return event_dict


def configure_logging(log_level: str = "INFO") -> None:
    """Configure structlog with the Polis processor chain.

    Args:
        log_level: The minimum log level to emit.
    """
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            filter_sensitive_fields,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            structlog.get_level_from_name(log_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
