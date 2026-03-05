# polis/node/polis_node/config/settings.py
"""
Polis Node configuration.

All configuration is sourced from environment variables.
No secrets are ever hardcoded or committed to source control.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_HOST: str = "0.0.0.0"
"""Default bind host for the Polis node API."""

DEFAULT_PORT: int = 8000
"""Default port for the Polis node API."""

DEFAULT_STORAGE_BACKEND: str = "local"
"""Default storage backend. One of: local, ipfs, arweave."""

DEFAULT_LOG_LEVEL: str = "INFO"
"""Default structured logging level."""

DEFAULT_DATA_DIR: str = "/tmp/polis/data"
"""Default directory for local storage backend data."""


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolisNodeSettings:
    """Immutable configuration for a Polis node.

    All values are sourced from environment variables at startup.
    Defaults are provided for development convenience but should be
    overridden in production.

    Attributes:
        node_id: Unique identifier for this node instance.
        host: Bind address for the API server.
        port: Port number for the API server.
        storage_backend: Storage backend type (local | ipfs | arweave).
        data_dir: Local filesystem path for node data.
        peers: Comma-separated list of peer addresses.
        log_level: Structured logging level (DEBUG, INFO, WARNING, ERROR).
        ipfs_api_url: URL of the local IPFS HTTP API (if using IPFS backend).
        arweave_gateway_url: URL of the Arweave gateway (if using Arweave backend).
    """

    node_id: str = "polis-node"
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    storage_backend: str = DEFAULT_STORAGE_BACKEND
    data_dir: str = DEFAULT_DATA_DIR
    peers: list[str] = field(default_factory=list)
    log_level: str = DEFAULT_LOG_LEVEL
    ipfs_api_url: str = "http://localhost:5001"
    arweave_gateway_url: str = "https://arweave.net"

    @classmethod
    def from_env(cls) -> PolisNodeSettings:
        """Load settings from environment variables.

        Environment variables:
            POLIS_NODE_ID: Node identifier.
            POLIS_HOST: Bind host.
            POLIS_PORT: Bind port.
            POLIS_STORAGE_BACKEND: Storage backend type.
            POLIS_DATA_DIR: Local data directory.
            POLIS_PEERS: Comma-separated peer addresses.
            POLIS_LOG_LEVEL: Logging level.
            POLIS_IPFS_API_URL: IPFS daemon API URL.
            POLIS_ARWEAVE_GATEWAY_URL: Arweave gateway URL.

        Returns:
            A PolisNodeSettings instance populated from the environment.
        """
        peers_raw = os.environ.get("POLIS_PEERS", "")
        peers = [p.strip() for p in peers_raw.split(",") if p.strip()]

        return cls(
            node_id=os.environ.get("POLIS_NODE_ID", "polis-node"),
            host=os.environ.get("POLIS_HOST", DEFAULT_HOST),
            port=int(os.environ.get("POLIS_PORT", str(DEFAULT_PORT))),
            storage_backend=os.environ.get("POLIS_STORAGE_BACKEND", DEFAULT_STORAGE_BACKEND),
            data_dir=os.environ.get("POLIS_DATA_DIR", DEFAULT_DATA_DIR),
            peers=peers,
            log_level=os.environ.get("POLIS_LOG_LEVEL", DEFAULT_LOG_LEVEL),
            ipfs_api_url=os.environ.get("POLIS_IPFS_API_URL", "http://localhost:5001"),
            arweave_gateway_url=os.environ.get(
                "POLIS_ARWEAVE_GATEWAY_URL", "https://arweave.net"
            ),
        )
