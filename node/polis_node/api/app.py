# polis/node/polis_node/api/app.py
"""
Polis Node API — FastAPI application.

Unified internal API that exposes identity management, attribution record
operations, and node status. This is what clients and other nodes talk to.
"""

from __future__ import annotations

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from polis_node.api.routes import identity, records, node
from polis_node.api.state import NodeState
from polis_node.config.logging import configure_logging
from polis_node.config.settings import PolisNodeSettings


logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Security-headers middleware
# ---------------------------------------------------------------------------

async def _security_headers_middleware(request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
    """Add standard security headers to every response."""
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if not request.url.path.startswith("/docs"):
        response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


# ---------------------------------------------------------------------------
# Rate-limiter (in-memory token-bucket)
# ---------------------------------------------------------------------------

import time
from collections import defaultdict

_RATE_BUCKETS: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT: int = 60          # requests per window
_RATE_WINDOW: float = 60.0     # seconds

async def _rate_limit_middleware(request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
    """Simple sliding-window rate limiter keyed on client IP."""
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    bucket = _RATE_BUCKETS[client_ip]
    # Prune old entries
    _RATE_BUCKETS[client_ip] = [ts for ts in bucket if now - ts < _RATE_WINDOW]
    bucket = _RATE_BUCKETS[client_ip]
    if len(bucket) >= _RATE_LIMIT:
        return Response(
            content='{"error":"rate_limit_exceeded","message":"Too many requests"}',
            status_code=429,
            media_type="application/json",
            headers={"Retry-After": str(int(_RATE_WINDOW))},
        )
    bucket.append(now)
    return await call_next(request)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(settings: PolisNodeSettings | None = None) -> FastAPI:
    """Create and configure the Polis Node FastAPI application.

    Args:
        settings: Node configuration. If None, loaded from environment.

    Returns:
        A configured FastAPI application instance.
    """
    if settings is None:
        settings = PolisNodeSettings.from_env()

    # Initialise structured logging (with sensitive-field redaction)
    configure_logging(settings.log_level)

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
        # Graceful shutdown: persist identities & records
        await state.shutdown()
        logger.info("polis_node.shutting_down", node_id=settings.node_id)

    app = FastAPI(
        title="Polis Node",
        version="0.1.0",
        description="Polis decentralized protocol node API",
        lifespan=lifespan,
    )

    # --- Middleware stack (outermost → innermost) ---
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    # Security headers
    app.middleware("http")(_security_headers_middleware)
    # Rate limiting
    app.middleware("http")(_rate_limit_middleware)

    # Attach node state to app for access in routes
    app.state.node_state = state  # type: ignore[attr-defined]

    # Register routers
    app.include_router(identity.router, prefix="/identity", tags=["identity"])
    app.include_router(records.router, prefix="/records", tags=["records"])
    app.include_router(node.router, prefix="/node", tags=["node"])

    return app
