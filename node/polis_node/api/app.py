# polis/node/polis_node/api/app.py
"""
Polis Node API — FastAPI application.

Unified internal API that exposes identity management, attribution record
operations, and node status. This is what clients and other nodes talk to.
"""

from __future__ import annotations

import structlog
from fastapi import FastAPI
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from polis_node.api.routes import identity, records, node
from polis_node.api.state import NodeState
from polis_node.config.settings import PolisNodeSettings


logger = structlog.get_logger(__name__)


def create_app(settings: PolisNodeSettings | None = None) -> FastAPI:
    """Create and configure the Polis Node FastAPI application.

    Args:
        settings: Node configuration. If None, loaded from environment.

    Returns:
        A configured FastAPI application instance.
    """
    if settings is None:
        settings = PolisNodeSettings.from_env()

    state = NodeState(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        """Application lifespan — initialize and cleanup resources."""
        logger.info(
            "polis_node.starting",
            node_id=settings.node_id,
            storage_backend=settings.storage_backend,
            peers=settings.peers,
        )
        await state.initialize()
        yield
        logger.info("polis_node.shutting_down", node_id=settings.node_id)

    app = FastAPI(
        title="Polis Node",
        version="0.1.0",
        description="Polis decentralized protocol node API",
        lifespan=lifespan,
    )

    # Attach node state to app for access in routes
    app.state.node_state = state  # type: ignore[attr-defined]

    # Register routers
    app.include_router(identity.router, prefix="/identity", tags=["identity"])
    app.include_router(records.router, prefix="/records", tags=["records"])
    app.include_router(node.router, prefix="/node", tags=["node"])

    return app
