# polis/client/polis_client/models.py
"""
Pydantic models for the Polis Client SDK.

Mirror the node API's request/response schemas so callers get
type-safe, validated objects.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


class IdentityResponse(BaseModel):
    """Response from ``POST /identity/create``.

    Attributes:
        did: The newly created DID.
        did_document: Full W3C DID Document.
        recovery_mnemonic: BIP-39 mnemonic for the recovery key (store offline!).
    """
    did: str
    did_document: dict[str, Any]
    recovery_mnemonic: str


class RecordResponse(BaseModel):
    """Response from ``POST /records/create``.

    Attributes:
        cid: Content identifier of the record.
        record: Full attribution record dict.
    """
    cid: str
    record: dict[str, Any]


class NodeStatusResponse(BaseModel):
    """Response from ``GET /node/status``."""
    node_id: str
    status: str
    storage_backend: str
    identity_count: int
    record_count: int
    peer_count: int
    uptime_seconds: float = 0.0


class PaginatedRecords(BaseModel):
    """Paginated list of records from ``GET /records/by-author/{did}``."""
    records: list[dict[str, Any]]
    offset: int
    limit: int
    total: int


class GrantAccessResponse(BaseModel):
    """Response from ``POST /records/{cid}/grant``."""
    token_id: str
    expires_at: str
    wrapped_key: str
    wrap_nonce: str
    record_nonce: str
    record_salt: str


class PeerConnectResponse(BaseModel):
    """Response from ``POST /node/peers/connect``."""
    status: str
    address: str
    peer_info: Optional[dict[str, Any]] = None
    message: Optional[str] = None
