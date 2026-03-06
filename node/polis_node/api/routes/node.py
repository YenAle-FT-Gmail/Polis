# polis/node/polis_node/api/routes/node.py
"""
Polis API — Node management routes.

Endpoints for node health, peer management, and status reporting.
"""

from __future__ import annotations

import hashlib
import time
from typing import Optional

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from polis_node.api.dependencies import get_node_state
from polis_node.api.state import NodeState


logger = structlog.get_logger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Inter-node request signing (Invariant 21)
# ---------------------------------------------------------------------------


def _sign_inter_node_request(
    state: NodeState, method: str, url: str
) -> dict[str, str]:
    """Create signed headers for an inter-node request.

    Signs a timestamp + method + URL with the first registered node
    identity (or returns empty headers if no identity is available).

    Args:
        state: The node state containing identities.
        method: HTTP method (GET, POST, etc.).
        url: The target URL.

    Returns:
        Dict of headers including X-Polis-Node-DID, X-Polis-Timestamp,
        and X-Polis-Signature.
    """
    if not state.identities:
        return {}

    # Use the first registered identity as the node identity
    node_identity = next(iter(state.identities.values()))
    ts = str(int(time.time()))
    message = f"{method}|{url}|{ts}".encode("utf-8")
    signature = node_identity.sign(message)

    return {
        "X-Polis-Node-DID": node_identity.did,
        "X-Polis-Timestamp": ts,
        "X-Polis-Signature": signature.hex(),
    }


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class NodeStatusResponse(BaseModel):
    """Response for node health check.

    Attributes:
        node_id: This node's identifier.
        status: Node status (healthy, degraded, idle).
        storage_backend: Active storage backend type.
        identity_count: Number of registered identities.
        record_count: Number of stored attribution records.
        peer_count: Number of connected peers.
        uptime_seconds: Seconds since the node started.
    """

    node_id: str
    status: str
    storage_backend: str
    identity_count: int
    record_count: int
    peer_count: int
    uptime_seconds: float = 0.0


class PeerInfo(BaseModel):
    """Information about a connected peer.

    Attributes:
        address: The peer's network address.
        status: Connection status.
    """

    address: str
    status: str = "configured"


class ConnectPeerRequest(BaseModel):
    """Request to connect to a new peer.

    Attributes:
        address: The peer's network address (host:port).
    """

    address: str = Field(description="Peer address in host:port format")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=NodeStatusResponse,
    summary="Node health and status",
    description="Returns node health, peer count, and storage statistics.",
)
async def node_status(
    state: NodeState = Depends(get_node_state),
) -> NodeStatusResponse:
    """Get the current node status.

    Args:
        state: Injected node state.

    Returns:
        Node status including identity count, record count, and peer info.
    """
    health = state.get_health_status()
    return NodeStatusResponse(
        node_id=state.settings.node_id,
        status=health["status"],
        storage_backend=state.settings.storage_backend,
        identity_count=health["identity_count"],
        record_count=health["record_count"],
        peer_count=health["peer_count"],
        uptime_seconds=health["uptime_seconds"],
    )


@router.get(
    "/peers",
    summary="List connected peers",
    description="Returns the list of configured peer addresses.",
)
async def list_peers(
    state: NodeState = Depends(get_node_state),
) -> list[PeerInfo]:
    """List all configured peers.

    Args:
        state: Injected node state.

    Returns:
        List of peer information objects.
    """
    return [
        PeerInfo(address=peer, status="configured")
        for peer in state.peers
    ]


@router.post(
    "/peers/connect",
    summary="Connect to a peer",
    description="Add a new peer and attempt to verify connectivity.",
)
async def connect_peer(
    request: ConnectPeerRequest,
    state: NodeState = Depends(get_node_state),
) -> dict:
    """Connect to a new peer node.

    Adds the peer to the configured peer list and attempts to verify
    connectivity by querying the peer's status endpoint.

    Args:
        request: The peer connection parameters.
        state: Injected node state.

    Returns:
        Connection status.
    """
    address = request.address

    if address in state.peers:
        return {
            "status": "already_connected",
            "address": address,
        }

    # Attempt to reach the peer
    # Use HTTPS in production (Invariant 20: TLS 1.3 minimum)
    # Configurable scheme for development environments
    scheme = "https" if not state.settings.node_id.startswith("dev-") else "http"
    peer_url = f"{scheme}://{address}/node/status"
    try:
        async with httpx.AsyncClient(verify=scheme == "https") as client:
            # Sign the request with this node's identity (Invariant 21)
            headers = _sign_inter_node_request(state, "GET", peer_url)
            response = await client.get(peer_url, timeout=5.0, headers=headers)
            if response.status_code == 200:
                state.peers.append(address)
                logger.info("api.peer.connected", address=address)
                return {
                    "status": "connected",
                    "address": address,
                    "peer_info": response.json(),
                }
    except httpx.HTTPError as exc:
        logger.warning("api.peer.connection_failed", address=address, error=str(exc))

    # Even if unreachable, add to peer list for future retry
    state.peers.append(address)
    return {
        "status": "added_unreachable",
        "address": address,
        "message": f"Peer {address} added but currently unreachable.",
    }
