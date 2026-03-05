# polis/node/polis_node/api/dependencies.py
"""
Polis API dependency injection.

FastAPI dependency functions for accessing shared node state from routes.
"""

from __future__ import annotations

from fastapi import Request

from polis_node.api.state import NodeState


def get_node_state(request: Request) -> NodeState:
    """Extract the NodeState from the FastAPI application state.

    Args:
        request: The incoming FastAPI request.

    Returns:
        The shared NodeState instance.
    """
    return request.app.state.node_state  # type: ignore[no-any-return]
