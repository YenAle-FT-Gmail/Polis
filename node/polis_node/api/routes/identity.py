# polis/node/polis_node/api/routes/identity.py
"""
Polis API — Identity routes.

Endpoints for creating, resolving, and managing Polis identities.
"""

from __future__ import annotations

from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from polis_node.api.dependencies import get_node_state
from polis_node.api.state import NodeState
from polis_node.identity.did import PolisIdentity


logger = structlog.get_logger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class CreateIdentityRequest(BaseModel):
    """Request body for creating a new Polis identity.

    Attributes:
        storage_endpoint: Optional URI for the user's primary data store.
    """

    storage_endpoint: Optional[str] = Field(
        default=None,
        description="URI of the user's primary data store",
    )


class CreateIdentityResponse(BaseModel):
    """Response for identity creation.

    Attributes:
        did: The newly created DID.
        recovery_mnemonic: BIP-39 mnemonic for the recovery key.
            MUST be saved securely offline by the user.
            This value is returned ONCE at creation time and is never
            stored or retrievable again.  The API response includes a
            ``X-Polis-Recovery-Warning`` header to reinforce this.
        did_document: The DID Document (JSON-LD).
    """

    did: str
    recovery_mnemonic: str
    did_document: dict


class RotateKeyRequest(BaseModel):
    """Request body for signing key rotation.

    In v0.1, no additional parameters are needed — a new key is
    generated automatically.
    """

    pass


class RotateKeyResponse(BaseModel):
    """Response for key rotation.

    Attributes:
        did: The DID (unchanged after rotation).
        updated_at: New timestamp after rotation.
        did_document: Updated DID Document.
    """

    did: str
    updated_at: str
    did_document: dict


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/create",
    response_model=CreateIdentityResponse,
    summary="Create a new Polis identity",
    description="Generate a new DID with signing and recovery keypairs.",
)
async def create_identity(
    request: CreateIdentityRequest,
    state: NodeState = Depends(get_node_state),
) -> JSONResponse:
    """Create a new Polis identity.

    Generates an Ed25519 signing keypair and recovery keypair.
    The recovery mnemonic MUST be saved securely offline.
    It is returned exactly once and never stored on any node.

    Args:
        request: The creation parameters.
        state: Injected node state.

    Returns:
        JSONResponse containing the new DID, recovery mnemonic (one-time),
        and DID Document.  Includes ``X-Polis-Recovery-Warning`` header.
    """
    identity = PolisIdentity.create(storage_endpoint=request.storage_endpoint)
    recovery_mnemonic = identity.serialize_recovery_key_to_mnemonic()

    state.register_identity(identity)

    # Log identity creation WITHOUT any key material (Invariant 18)
    logger.info("api.identity.created", did=identity.did)

    body = CreateIdentityResponse(
        did=identity.did,
        recovery_mnemonic=recovery_mnemonic,
        did_document=identity.to_did_document(),
    ).model_dump()

    return JSONResponse(
        content=body,
        headers={
            "X-Polis-Recovery-Warning": (
                "The recovery_mnemonic in this response is shown ONCE. "
                "Save it securely offline. It will never be returned again."
            ),
            "Cache-Control": "no-store",
        },
    )


@router.get(
    "/{did}",
    summary="Resolve a DID Document",
    description="Look up the DID Document for a given Polis DID.",
)
async def resolve_identity(
    did: str,
    state: NodeState = Depends(get_node_state),
) -> dict:
    """Resolve a DID to its DID Document.

    Args:
        did: The Polis DID to resolve.
        state: Injected node state.

    Returns:
        The DID Document.

    Raises:
        HTTPException: 404 if the DID is not found.
    """
    doc = state.resolver.resolve(did)
    if doc is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "did_not_found",
                "message": f"DID not found: {did}. The identity may not be registered on this node.",
                "did": did,
            },
        )
    return doc


@router.post(
    "/{did}/rotate-key",
    response_model=RotateKeyResponse,
    summary="Rotate the signing key",
    description="Generate a new signing keypair while preserving the DID.",
)
async def rotate_key(
    did: str,
    state: NodeState = Depends(get_node_state),
) -> RotateKeyResponse:
    """Rotate the signing key for an identity.

    The DID does not change. A new signing keypair is generated and
    the DID Document is updated.

    Args:
        did: The DID whose signing key to rotate.
        state: Injected node state.

    Returns:
        The updated DID and DID Document.

    Raises:
        HTTPException: 404 if the identity is not found on this node.
    """
    identity = state.get_identity(did)
    if identity is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "identity_not_found",
                "message": (
                    f"Identity not found on this node: {did}. "
                    "Key rotation can only be performed on locally managed identities."
                ),
                "did": did,
            },
        )

    rotated = identity.rotate_signing_key()
    state.identities[did] = rotated
    state.resolver.update(rotated)

    logger.info("api.identity.key_rotated", did=did)

    return RotateKeyResponse(
        did=rotated.did,
        updated_at=rotated.updated_at,
        did_document=rotated.to_did_document(),
    )
