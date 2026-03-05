# polis/node/tests/test_config.py
"""
Tests for the Polis Node configuration module.

Covers:
- Default settings values
- Environment variable loading
- Peer list parsing
- Frozen dataclass immutability
"""

import os
from unittest.mock import patch

import pytest

from polis_node.config.settings import (
    DEFAULT_DATA_DIR,
    DEFAULT_HOST,
    DEFAULT_LOG_LEVEL,
    DEFAULT_PORT,
    DEFAULT_STORAGE_BACKEND,
    PolisNodeSettings,
)


class TestDefaultSettings:
    """Tests for default PolisNodeSettings values."""

    def test_default_node_id(self) -> None:
        """Default node_id is 'polis-node'."""
        settings = PolisNodeSettings()
        assert settings.node_id == "polis-node"

    def test_default_host(self) -> None:
        """Default host is 0.0.0.0."""
        settings = PolisNodeSettings()
        assert settings.host == DEFAULT_HOST

    def test_default_port(self) -> None:
        """Default port is 8000."""
        settings = PolisNodeSettings()
        assert settings.port == DEFAULT_PORT

    def test_default_storage_backend(self) -> None:
        """Default storage backend is 'local'."""
        settings = PolisNodeSettings()
        assert settings.storage_backend == DEFAULT_STORAGE_BACKEND

    def test_default_data_dir(self) -> None:
        """Default data dir is /tmp/polis/data."""
        settings = PolisNodeSettings()
        assert settings.data_dir == DEFAULT_DATA_DIR

    def test_default_peers_empty(self) -> None:
        """Default peers list is empty."""
        settings = PolisNodeSettings()
        assert settings.peers == []

    def test_default_log_level(self) -> None:
        """Default log level is INFO."""
        settings = PolisNodeSettings()
        assert settings.log_level == DEFAULT_LOG_LEVEL


class TestFromEnv:
    """Tests for loading settings from environment variables."""

    def test_from_env_with_defaults(self) -> None:
        """from_env returns defaults when no env vars are set."""
        env_vars = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("POLIS_")
        }
        with patch.dict(os.environ, env_vars, clear=True):
            settings = PolisNodeSettings.from_env()
            assert settings.node_id == "polis-node"
            assert settings.port == DEFAULT_PORT

    def test_from_env_custom_values(self) -> None:
        """from_env reads custom values from environment variables."""
        custom_env = {
            "POLIS_NODE_ID": "test-node-1",
            "POLIS_HOST": "127.0.0.1",
            "POLIS_PORT": "9000",
            "POLIS_STORAGE_BACKEND": "ipfs",
            "POLIS_DATA_DIR": "/custom/data",
            "POLIS_LOG_LEVEL": "DEBUG",
        }
        with patch.dict(os.environ, custom_env, clear=False):
            settings = PolisNodeSettings.from_env()
            assert settings.node_id == "test-node-1"
            assert settings.host == "127.0.0.1"
            assert settings.port == 9000
            assert settings.storage_backend == "ipfs"
            assert settings.data_dir == "/custom/data"
            assert settings.log_level == "DEBUG"

    def test_from_env_peers_parsing(self) -> None:
        """from_env correctly parses comma-separated peers."""
        with patch.dict(os.environ, {"POLIS_PEERS": "node-a:8001,node-b:8002, node-c:8003 "}):
            settings = PolisNodeSettings.from_env()
            assert settings.peers == ["node-a:8001", "node-b:8002", "node-c:8003"]

    def test_from_env_empty_peers(self) -> None:
        """from_env handles empty POLIS_PEERS correctly."""
        with patch.dict(os.environ, {"POLIS_PEERS": ""}):
            settings = PolisNodeSettings.from_env()
            assert settings.peers == []


class TestFrozenDataclass:
    """Tests that PolisNodeSettings is properly frozen."""

    def test_cannot_modify_node_id(self) -> None:
        """Attempting to modify a frozen field raises FrozenInstanceError."""
        settings = PolisNodeSettings()
        with pytest.raises(AttributeError):
            settings.node_id = "modified"  # type: ignore[misc]

    def test_cannot_modify_port(self) -> None:
        """Attempting to modify port raises FrozenInstanceError."""
        settings = PolisNodeSettings()
        with pytest.raises(AttributeError):
            settings.port = 9999  # type: ignore[misc]
