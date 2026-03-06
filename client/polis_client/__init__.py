# polis/client/polis_client/__init__.py
"""
Polis Client SDK.

Async-first Python client for the Polis decentralised protocol.

Usage::

    from polis_client import PolisClient

    async with PolisClient("http://localhost:8000") as client:
        identity = await client.create_identity()
        record   = await client.create_record(b"hello", identity["did"])
"""

from polis_client.client import PolisClient
from polis_client.models import (
    IdentityResponse,
    RecordResponse,
    NodeStatusResponse,
    PaginatedRecords,
)

__all__ = [
    "PolisClient",
    "IdentityResponse",
    "RecordResponse",
    "NodeStatusResponse",
    "PaginatedRecords",
]
