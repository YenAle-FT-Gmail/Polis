# polis/node/polis_node/api/routes/records.py
"""
Polis API — Attribution Record routes.

Endpoints for creating, retrieving, and managing attribution records.
"""

from __future__ import annotations

import base64
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from polis_node.api.dependencies import get_node_state
from polis_node.api.state import NodeState
from polis_node.attribution.record import (
    VALID_VISIBILITIES,
    VISIBILITY_PRIVATE,
    VISIBILITY_PUBLIC,
    VISIBILITY_SELECTIVE,
    AttributionRecord,
)


logger = structlog.get_logger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class CreateRecordRequest(BaseModel):
    """Request body for creating a new attribution record.

    Attributes:
        payload: Base64-encoded payload data.
        author_did: The DID of the record's author.
        record_type: Namespaced record type (default: polis.content.post).
        visibility: Record visibility level.
    """

    payload: str = Field(description="Base64-encoded payload data")
    author_did: str = Field(description="The author's Polis DID")
    record_type: str = Field(default="polis.content.post", description="Namespaced record type")
    visibility: str = Field(default="public", description="Record visibility: public, private, or selective")


class IngestRecordRequest(BaseModel):
    """Request body for ingesting an externally-created attribution record.

    Used for inter-node record propagation.  The receiving node
    independently verifies the signature before storing (Invariant 22).

    Attributes:
        record: Serialized attribution record dict.
        data: Base64-encoded storable data (plaintext or ciphertext).
    """

    record: dict = Field(description="Full serialized attribution record")
    data: str = Field(description="Base64-encoded storable payload/ciphertext")


class CreateRecordResponse(BaseModel):
    """Response for record creation.

    Attributes:
        cid: Content identifier of the record.
        record: The full attribution record.
    """

    cid: str
    record: dict


class GrantAccessRequest(BaseModel):
    """Request body for granting access to a selective record.

    Attributes:
        recipient_did: DID of the identity to grant access to.
        expiry_seconds: How long the access grant is valid (default: 3600).
    """

    recipient_did: str
    expiry_seconds: int = Field(default=3600, gt=0)


class GrantAccessResponse(BaseModel):
    """Response for access grant.

    Attributes:
        token_id: The permission token identifier.
        expires_at: ISO 8601 expiry timestamp.
        wrapped_key: Base64-encoded wrapped AES key for the recipient.
        wrap_nonce: Base64-encoded wrap nonce.
        record_nonce: Hex-encoded record encryption nonce.
        record_salt: Hex-encoded record encryption salt.
    """

    token_id: str
    expires_at: str
    wrapped_key: str
    wrap_nonce: str
    record_nonce: str
    record_salt: str


class RevokeAccessRequest(BaseModel):
    """Request body for revoking access.

    Attributes:
        token_id: The permission token to revoke.
    """

    token_id: str


class AccessRecordRequest(BaseModel):
    """Request body for presenting a permission token to access content.

    Attributes:
        token_id: The permission token ID.
        recipient_did: The recipient's DID (must match the token).
        wrapped_key: Hex-encoded wrapped AES key from the PermissionToken.
        wrap_nonce: Hex-encoded wrap nonce from the PermissionToken.
        record_nonce: Hex-encoded record encryption nonce.
        record_salt: Hex-encoded record encryption salt.
        recipient_private_key_hex: Hex-encoded recipient private key seed
            (NOTE: in production, decryption would happen client-side;
            this is for the v0.1 PoC demonstration only).
        grantor_public_key_hex: Hex-encoded grantor public key.
    """

    token_id: str
    recipient_did: str
    wrapped_key: str = Field(description="Hex-encoded wrapped AES key")
    wrap_nonce: str = Field(description="Hex-encoded wrap nonce")
    record_nonce: str = Field(description="Hex-encoded record nonce")
    record_salt: str = Field(description="Hex-encoded record salt")
    recipient_private_key_hex: str = Field(
        description="Hex-encoded recipient Ed25519 private key (PoC only)"
    )
    grantor_public_key_hex: str = Field(
        description="Hex-encoded grantor Ed25519 public key"
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/create",
    response_model=CreateRecordResponse,
    summary="Create an attribution record",
    description="Create a new signed attribution record for a payload.",
)
async def create_record(
    request: CreateRecordRequest,
    state: NodeState = Depends(get_node_state),
) -> CreateRecordResponse:
    """Create a new attribution record.

    The payload is signed by the author's identity. For private/selective
    records, the payload is encrypted before CID computation.

    Args:
        request: The record creation parameters.
        state: Injected node state.

    Returns:
        The CID and full attribution record.

    Raises:
        HTTPException: 404 if the author identity is not found.
        HTTPException: 400 if the parameters are invalid.
    """

    identity = state.get_identity(request.author_did)
    if identity is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "author_not_found",
                "message": (
                    f"Author identity not found: {request.author_did}. "
                    "The identity must be created on this node first."
                ),
                "did": request.author_did,
            },
        )

    try:
        payload = base64.b64decode(request.payload)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_payload",
                "message": "Payload must be valid base64-encoded data.",
            },
        )

    try:
        record, storable_data = AttributionRecord.create(
            payload=payload,
            author=identity,
            record_type=request.record_type,
            visibility=request.visibility,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_parameters",
                "message": str(exc),
            },
        )

    # Verify the record signature before storing (invariant: no unsigned records stored)
    if not record.verify(state.resolver):
        raise HTTPException(
            status_code=500,
            detail={
                "error": "signature_verification_failed",
                "message": "Internal error: record signature verification failed after signing.",
            },
        )

    # Store the storable_data (ciphertext for encrypted records, plaintext for public)
    # This ensures the CID matches the stored bytes (Invariant 11)
    await state.store_record(record, storable_data)

    # Propagate to peers (best-effort, non-blocking for caller)
    propagation_results = await state.propagate_record(record, storable_data)

    logger.info(
        "api.record.created",
        cid=record.cid,
        author_did=record.author_did,
        record_type=record.record_type,
        propagated_to=len([v for v in propagation_results.values() if v == "ok"]),
    )

    return CreateRecordResponse(
        cid=record.cid,
        record=record.to_dict(),
    )


@router.get(
    "/{cid}",
    summary="Retrieve a record by CID",
    description="Look up an attribution record by its content identifier.",
)
async def get_record(
    cid: str,
    state: NodeState = Depends(get_node_state),
) -> dict:
    """Retrieve an attribution record by CID.

    Args:
        cid: The content identifier.
        state: Injected node state.

    Returns:
        The attribution record as a dict.

    Raises:
        HTTPException: 404 if the record is not found.
    """
    record = state.get_record(cid)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "record_not_found",
                "message": f"Record not found: {cid}",
                "cid": cid,
            },
        )
    return record.to_dict()


@router.get(
    "/by-author/{did}",
    summary="List records by author",
    description="Retrieve all attribution records by a specific author DID.",
)
async def get_records_by_author(
    did: str,
    state: NodeState = Depends(get_node_state),
) -> list[dict]:
    """List all records by a specific author DID.

    Args:
        did: The author's DID.
        state: Injected node state.

    Returns:
        A list of attribution records as dicts.
    """
    records = state.get_records_by_author(did)
    return [r.to_dict() for r in records]


@router.post(
    "/{cid}/grant",
    response_model=GrantAccessResponse,
    summary="Grant access to a record",
    description="Grant a recipient access to a selective-visibility record.",
)
async def grant_access(
    cid: str,
    request: GrantAccessRequest,
    state: NodeState = Depends(get_node_state),
) -> GrantAccessResponse:
    """Grant access to a selective-visibility record.

    Args:
        cid: The record's CID.
        request: The grant parameters.
        state: Injected node state.

    Returns:
        The permission token ID and expiry.

    Raises:
        HTTPException: 404 if the record is not found.
        HTTPException: 400 if the record does not support access grants.
    """
    record = state.get_record(cid)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "record_not_found",
                "message": f"Record not found: {cid}",
                "cid": cid,
            },
        )

    identity = state.get_identity(record.author_did)
    if identity is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "author_not_found",
                "message": f"Author identity not available on this node: {record.author_did}",
            },
        )

    try:
        # Resolve recipient's public key for key wrapping
        recipient_pub = state.resolver.get_signing_public_key(request.recipient_did)
        if recipient_pub is None:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "recipient_not_found",
                    "message": (
                        f"Recipient DID not found: {request.recipient_did}. "
                        "The recipient's identity must be resolvable on this node."
                    ),
                },
            )

        token = record.grant_access(
            recipient_did=request.recipient_did,
            author=identity,
            expiry_seconds=request.expiry_seconds,
            recipient_public_key=recipient_pub,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "grant_failed",
                "message": str(exc),
            },
        )

    logger.info(
        "api.record.access_granted",
        cid=cid,
        recipient_did=request.recipient_did,
    )

    return GrantAccessResponse(
        token_id=token.token_id,
        expires_at=token.expires_at,
        wrapped_key=base64.b64encode(token.wrapped_key).decode(),
        wrap_nonce=base64.b64encode(token.wrap_nonce).decode(),
        record_nonce=token.record_nonce.hex(),
        record_salt=token.record_salt.hex(),
    )


@router.post(
    "/{cid}/revoke",
    summary="Revoke access to a record",
    description="Revoke a previously granted permission token.",
)
async def revoke_access(
    cid: str,
    request: RevokeAccessRequest,
    state: NodeState = Depends(get_node_state),
) -> dict:
    """Revoke a permission token.

    Args:
        cid: The record's CID.
        request: The revocation parameters.
        state: Injected node state.

    Returns:
        Confirmation of revocation.

    Raises:
        HTTPException: 404 if the record is not found.
        HTTPException: 400 if the token ID is invalid.
    """
    record = state.get_record(cid)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "record_not_found",
                "message": f"Record not found: {cid}",
                "cid": cid,
            },
        )

    # In v0.1, we simply remove the token from the record's list
    if request.token_id in record.permission_tokens:
        record.permission_tokens.remove(request.token_id)
        logger.info("api.record.access_revoked", cid=cid, token_id=request.token_id)
        return {"status": "revoked", "token_id": request.token_id}
    else:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "token_not_found",
                "message": f"Permission token {request.token_id} not found on record {cid}.",
            },
        )


@router.post(
    "/ingest",
    summary="Ingest an external attribution record",
    description=(
        "Accept a record from another node. The signature is independently "
        "verified before storage (Invariant 22: no node trusts another "
        "node's verification)."
    ),
)
async def ingest_record(
    request: IngestRecordRequest,
    state: NodeState = Depends(get_node_state),
) -> dict:
    """Ingest an externally-created attribution record.

    This endpoint is used for inter-node record propagation.
    The receiving node re-verifies the signature independently
    before storing (Invariant 8, 22).

    Args:
        request: The ingest request containing the record and data.
        state: Injected node state.

    Returns:
        Confirmation of successful ingest.

    Raises:
        HTTPException: 400 if the record is invalid or signature fails.
    """

    try:
        record = AttributionRecord.from_dict(request.record)
    except (KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_record",
                "message": f"Cannot deserialize record: {exc}",
            },
        )

    # Invariant 8 / 22: independently verify signature
    try:
        valid = record.verify(state.resolver)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unresolvable_author",
                "message": str(exc),
            },
        )

    if not valid:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_signature",
                "message": (
                    "Record signature verification failed. "
                    "The record may have been tampered with or signed by "
                    "an unknown key."
                ),
            },
        )

    try:
        storable_data = base64.b64decode(request.data)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_data",
                "message": "data must be valid base64-encoded bytes.",
            },
        )

    # Verify CID matches the provided data
    from polis_node.storage.interface import StorageBackend

    expected_cid = StorageBackend.compute_cid(storable_data)
    if expected_cid != record.cid:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "cid_mismatch",
                "message": (
                    f"CID mismatch: record claims {record.cid} but "
                    f"data hashes to {expected_cid}."
                ),
            },
        )

    # Check for duplicates
    if state.get_record(record.cid) is not None:
        return {"status": "already_exists", "cid": record.cid}

    await state.store_record(record, storable_data)

    logger.info(
        "api.record.ingested",
        cid=record.cid,
        author_did=record.author_did,
    )

    return {"status": "ingested", "cid": record.cid}


@router.post(
    "/{cid}/access",
    summary="Present a permission token to access content",
    description=(
        "Decrypt and return the content of a selective-visibility record "
        "using a valid permission token."
    ),
)
async def access_record(
    cid: str,
    request: AccessRecordRequest,
    state: NodeState = Depends(get_node_state),
) -> dict:
    """Present a permission token to decrypt selective-visibility content.

    In v0.1, this endpoint accepts the recipient's private key for
    server-side decryption as a PoC.  In production, decryption would
    occur client-side.

    Args:
        cid: The record's CID.
        request: The access request with token details.
        state: Injected node state.

    Returns:
        The decrypted payload (base64-encoded).

    Raises:
        HTTPException: 404 if the record is not found.
        HTTPException: 403 if the token is invalid or revoked.
        HTTPException: 400 if decryption fails.
    """
    from polis_node.attribution.record import (
        _unwrap_key_for_recipient,
        _derive_encryption_key,
        HKDF_INFO_PRIVATE,
    )

    record = state.get_record(cid)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "record_not_found", "message": f"Record not found: {cid}"},
        )

    if request.token_id not in record.permission_tokens:
        raise HTTPException(
            status_code=403,
            detail={"error": "invalid_token", "message": "Token is not valid for this record."},
        )

    # Unwrap the AES key
    try:
        aes_key = _unwrap_key_for_recipient(
            wrapped_key=bytes.fromhex(request.wrapped_key),
            wrap_nonce=bytes.fromhex(request.wrap_nonce),
            recipient_private=bytes.fromhex(request.recipient_private_key_hex),
            grantor_public=bytes.fromhex(request.grantor_public_key_hex),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "key_unwrap_failed", "message": f"Failed to unwrap key: {exc}"},
        )

    # Decrypt the ciphertext
    ciphertext = state.record_data.get(cid)
    if ciphertext is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "data_not_found", "message": "Record data not available on this node."},
        )

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = bytes.fromhex(request.record_nonce)
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "decryption_failed", "message": f"Failed to decrypt content: {exc}"},
        )

    logger.info("api.record.accessed", cid=cid, recipient_did=request.recipient_did)

    return {
        "cid": cid,
        "payload": base64.b64encode(plaintext).decode("ascii"),
    }
