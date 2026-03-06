# polis/node/polis_node/network/__init__.py
"""
Polis Network Module.

Handles peer-to-peer communication, record propagation, identity
resolution across nodes, and transport security.

Components:
- ``peer.PeerManager``: Peer list management with health monitoring.

See specs/network/polis-network-spec.md for the full specification.
"""

from polis_node.network.peer import PeerInfo, PeerManager, PeerStatus

__all__ = ["PeerInfo", "PeerManager", "PeerStatus"]
