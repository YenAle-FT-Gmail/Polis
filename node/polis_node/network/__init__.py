# polis/node/polis_node/network/__init__.py
"""
Polis Network Module.

Handles peer-to-peer communication, record propagation, identity
resolution across nodes, and transport security.

See specs/network/polis-network-spec.md for the full specification.

In v0.1, networking is handled directly by the API routes and
NodeState.propagate_record(). This module will be expanded in v0.2
with dedicated peer management and gossip protocols.
"""
