# tests/test_logging_config.py
"""Tests for Polis structured logging configuration."""

from __future__ import annotations

import structlog

from polis_node.config.logging import (
    SENSITIVE_FIELDS,
    configure_logging,
    filter_sensitive_fields,
)


class TestFilterSensitiveFields:
    """Unit tests for the sensitive-field redaction processor."""

    def test_redacts_known_fields(self) -> None:
        event = {
            "event": "identity.created",
            "signing_key_private": b"secret-bytes",
            "mnemonic": "word1 word2 word3",
            "did": "did:polis:abc",
        }
        result = filter_sensitive_fields(None, "info", event)
        assert result["signing_key_private"] == "[REDACTED]"
        assert result["mnemonic"] == "[REDACTED]"
        assert result["did"] == "did:polis:abc"  # not sensitive

    def test_leaves_non_sensitive_fields(self) -> None:
        event = {"event": "record.stored", "cid": "Qm123", "author_did": "did:polis:x"}
        result = filter_sensitive_fields(None, "info", event)
        assert result == event

    def test_case_insensitive_field_match(self) -> None:
        event = {"Private_Key": "leak", "event": "test"}
        result = filter_sensitive_fields(None, "info", event)
        assert result["Private_Key"] == "[REDACTED]"

    def test_all_sensitive_fields_covered(self) -> None:
        """Ensure the sensitive set has key crypto-related field names."""
        expected_subsets = {
            "signing_key_private",
            "recovery_key_private",
            "recovery_mnemonic",
            "private_key",
            "secret",
            "password",
            "aes_key",
        }
        assert expected_subsets.issubset(SENSITIVE_FIELDS)


class TestConfigureLogging:
    """Tests for configure_logging()."""

    def test_configure_logging_info(self) -> None:
        """configure_logging should not raise for valid levels."""
        configure_logging("INFO")
        log = structlog.get_logger("test")
        assert log is not None

    def test_configure_logging_debug(self) -> None:
        configure_logging("DEBUG")

    def test_configure_logging_unknown_defaults_to_info(self) -> None:
        configure_logging("BANANA")  # should fallback without error
