# polis/node/polis_node/network/peer.py
"""
Polis Peer Manager.

Manages the peer list with health monitoring, reconnection logic,
and basic peer scoring.  Moves networking logic out of ad-hoc route
code into a dedicated component.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class PeerStatus(str, Enum):
    """Connection states for a peer."""
    CONNECTED = "connected"
    UNREACHABLE = "unreachable"
    CONFIGURED = "configured"
    REMOVED = "removed"


@dataclass
class PeerInfo:
    """Tracked information about a single peer.

    Attributes:
        address: host:port of the peer.
        status: Current connection state.
        last_seen: Monotonic timestamp of last successful contact.
        failures: Consecutive failure count.
        node_id: Reported node_id of the remote node (if known).
    """
    address: str
    status: PeerStatus = PeerStatus.CONFIGURED
    last_seen: float = 0.0
    failures: int = 0
    node_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Peer Manager
# ---------------------------------------------------------------------------


class PeerManager:
    """Manages an ordered list of peers with health tracking.

    Attributes:
        peers: Dict of address -> PeerInfo.
        scheme: HTTP scheme to use for peer communication.
        max_failures: After this many consecutive failures a peer is
            marked as unreachable (but not removed).
    """

    def __init__(
        self,
        *,
        dev_mode: bool = False,
        max_failures: int = 5,
    ) -> None:
        self.peers: dict[str, PeerInfo] = {}
        self.scheme = "http" if dev_mode else "https"
        self.max_failures = max_failures

    # -- Mutation ----------------------------------------------------------

    def add(self, address: str) -> PeerInfo:
        """Add a peer (idempotent)."""
        if address not in self.peers:
            self.peers[address] = PeerInfo(address=address)
        return self.peers[address]

    def remove(self, address: str) -> None:
        """Remove a peer entirely."""
        self.peers.pop(address, None)

    def mark_success(self, address: str, *, node_id: str | None = None) -> None:
        """Record a successful interaction with a peer."""
        peer = self.peers.get(address)
        if peer:
            peer.status = PeerStatus.CONNECTED
            peer.last_seen = time.monotonic()
            peer.failures = 0
            if node_id:
                peer.node_id = node_id

    def mark_failure(self, address: str) -> None:
        """Record a failed interaction with a peer."""
        peer = self.peers.get(address)
        if peer:
            peer.failures += 1
            if peer.failures >= self.max_failures:
                peer.status = PeerStatus.UNREACHABLE

    # -- Queries -----------------------------------------------------------

    @property
    def connected(self) -> list[PeerInfo]:
        """Return all currently-connected peers."""
        return [p for p in self.peers.values() if p.status == PeerStatus.CONNECTED]

    @property
    def addresses(self) -> list[str]:
        """Return all peer addresses (for propagation loops)."""
        return list(self.peers.keys())

    def get(self, address: str) -> PeerInfo | None:
        return self.peers.get(address)

    # -- Health probes -----------------------------------------------------

    async def probe(self, address: str) -> bool:
        """Probe a peer's ``/node/status`` endpoint.

        Returns:
            True if the peer responded 200.
        """
        url = f"{self.scheme}://{address}/node/status"
        try:
            async with httpx.AsyncClient(verify=self.scheme == "https", timeout=5.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    self.mark_success(address, node_id=data.get("node_id"))
                    return True
        except Exception as exc:
            logger.debug("peer.probe_failed", address=address, error=str(exc))
        self.mark_failure(address)
        return False

    async def probe_all(self) -> dict[str, bool]:
        """Probe all known peers concurrently.

        Returns:
            Dict of address -> reachable (bool).
        """
        tasks = {addr: self.probe(addr) for addr in list(self.peers)}
        results: dict[str, bool] = {}
        for addr, coro in tasks.items():
            results[addr] = await coro
        return results
