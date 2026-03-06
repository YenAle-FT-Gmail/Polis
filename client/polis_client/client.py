# polis/client/polis_client/client.py
"""
Polis Client — async HTTP wrapper around the Polis node API.

Provides typed methods for every API endpoint, with automatic
retry/backoff and connection pooling via ``httpx.AsyncClient``.
"""

from __future__ import annotations

import base64
from types import TracebackType
from typing import Any, Optional, Type

import httpx

from polis_client.models import (
    GrantAccessResponse,
    IdentityResponse,
    NodeStatusResponse,
    PaginatedRecords,
    PeerConnectResponse,
    RecordResponse,
)


class PolisClientError(Exception):
    """Raised when the Polis node returns a non-2xx response."""

    def __init__(self, status_code: int, detail: Any) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class PolisClient:
    """Async client for a Polis node.

    Usage::

        async with PolisClient("http://localhost:8000") as c:
            ident = await c.create_identity()

    Args:
        base_url: Root URL of the Polis node (e.g. ``http://localhost:8000``).
        timeout: Request timeout in seconds.
        max_retries: Number of retries on transient errors.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        transport = httpx.AsyncHTTPTransport(retries=max_retries)
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
        )

    # -- Context manager ---------------------------------------------------

    async def __aenter__(self) -> "PolisClient":
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    # -- Helpers -----------------------------------------------------------

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Issue an HTTP request and return the parsed JSON body.

        Raises:
            PolisClientError: On non-2xx responses.
        """
        resp = await self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise PolisClientError(resp.status_code, detail)
        return resp.json()

    # -- Identity ----------------------------------------------------------

    async def create_identity(
        self, *, storage_endpoint: Optional[str] = None
    ) -> IdentityResponse:
        """Create a new Polis identity.

        Args:
            storage_endpoint: Optional storage URI for the DID Document.

        Returns:
            IdentityResponse with the DID and recovery mnemonic.
        """
        body: dict[str, Any] = {}
        if storage_endpoint:
            body["storage_endpoint"] = storage_endpoint
        data = await self._request("POST", "/identity/create", json=body)
        return IdentityResponse(**data)

    async def get_identity(self, did: str) -> dict[str, Any]:
        """Resolve a DID to its DID Document.

        Args:
            did: The Polis DID to resolve.

        Returns:
            The DID Document dict.
        """
        return await self._request("GET", f"/identity/{did}")

    async def rotate_key(self, did: str) -> dict[str, Any]:
        """Rotate the signing key for an identity.

        Args:
            did: The DID whose key to rotate.

        Returns:
            Updated DID Document.
        """
        return await self._request("POST", f"/identity/{did}/rotate-key")

    # -- Records -----------------------------------------------------------

    async def create_record(
        self,
        payload: bytes,
        author_did: str,
        *,
        record_type: str = "polis.content.post",
        visibility: str = "public",
    ) -> RecordResponse:
        """Create a new attribution record.

        Args:
            payload: Raw payload bytes (will be base64-encoded).
            author_did: The author's DID.
            record_type: Namespaced record type.
            visibility: "public", "private", or "selective".

        Returns:
            RecordResponse with CID and full record.
        """
        data = await self._request(
            "POST",
            "/records/create",
            json={
                "payload": base64.b64encode(payload).decode(),
                "author_did": author_did,
                "record_type": record_type,
                "visibility": visibility,
            },
        )
        return RecordResponse(**data)

    async def get_record(self, cid: str) -> dict[str, Any]:
        """Retrieve a record by CID.

        Args:
            cid: The record's content identifier.

        Returns:
            The attribution record dict.
        """
        return await self._request("GET", f"/records/{cid}")

    async def list_records_by_author(
        self, did: str, *, offset: int = 0, limit: int = 50
    ) -> PaginatedRecords:
        """List records by author DID (paginated).

        Args:
            did: The author's DID.
            offset: Records to skip.
            limit: Max records to return.

        Returns:
            PaginatedRecords.
        """
        data = await self._request(
            "GET",
            f"/records/by-author/{did}",
            params={"offset": offset, "limit": limit},
        )
        return PaginatedRecords(**data)

    async def grant_access(
        self,
        cid: str,
        recipient_did: str,
        *,
        expiry_seconds: int = 3600,
    ) -> GrantAccessResponse:
        """Grant access to a selective-visibility record.

        Args:
            cid: The record's CID.
            recipient_did: The recipient's DID.
            expiry_seconds: Token lifetime.

        Returns:
            GrantAccessResponse with the wrapped key material.
        """
        data = await self._request(
            "POST",
            f"/records/{cid}/grant",
            json={"recipient_did": recipient_did, "expiry_seconds": expiry_seconds},
        )
        return GrantAccessResponse(**data)

    async def revoke_access(self, cid: str, token_id: str) -> dict[str, Any]:
        """Revoke an access token.

        Args:
            cid: The record's CID.
            token_id: Token to revoke.

        Returns:
            Confirmation dict.
        """
        return await self._request(
            "POST",
            f"/records/{cid}/revoke",
            json={"token_id": token_id},
        )

    # -- Node management ---------------------------------------------------

    async def node_status(self) -> NodeStatusResponse:
        """Get node health status."""
        data = await self._request("GET", "/node/status")
        return NodeStatusResponse(**data)

    async def list_peers(self) -> list[dict[str, Any]]:
        """List the node's peers."""
        return await self._request("GET", "/node/peers")

    async def connect_peer(self, address: str) -> PeerConnectResponse:
        """Connect to a new peer.

        Args:
            address: Peer address (host:port).

        Returns:
            PeerConnectResponse.
        """
        data = await self._request(
            "POST", "/node/peers/connect", json={"address": address}
        )
        return PeerConnectResponse(**data)
