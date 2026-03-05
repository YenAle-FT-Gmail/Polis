# polis/node/polis_node/storage/arweave.py
"""
Polis Arweave Storage Backend.

Interfaces with the Arweave gateway for permanent storage.
Not fully implemented in v0.1 — use LocalStorageBackend for development.
"""

from __future__ import annotations

import httpx

from polis_node.storage.interface import IntegrityError, StorageBackend, StorageError


class ArweaveBackend(StorageBackend):
    """Arweave storage backend for permanent, immutable data storage.

    Communicates with the Arweave network via a gateway URL.
    Requires a funded Arweave wallet for write operations in production.

    Attributes:
        gateway_url: Base URL of the Arweave gateway.
    """

    def __init__(self, gateway_url: str = "https://arweave.net") -> None:
        """Initialize the Arweave backend.

        Args:
            gateway_url: Base URL of the Arweave gateway.
        """
        self.gateway_url = gateway_url.rstrip("/")

    async def put(self, data: bytes) -> str:
        """Store data on Arweave.

        In v0.1, this is a stub that computes and returns the CID.
        Full Arweave transaction submission will be implemented in a
        future version.

        Args:
            data: The raw bytes to store.

        Returns:
            The CID of the data.

        Raises:
            StorageError: If the operation fails.
            NotImplementedError: Full Arweave uploads not yet implemented.
        """
        raise NotImplementedError(
            "Arweave uploads are not yet implemented in v0.1. "
            "Use LocalStorageBackend or IPFSBackend instead."
        )

    async def get(self, cid: str) -> bytes:
        """Retrieve data from Arweave by transaction ID / CID.

        Args:
            cid: The content identifier or Arweave transaction ID.

        Returns:
            The raw bytes.

        Raises:
            KeyError: If the transaction is not found.
            StorageError: If the gateway is unreachable.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.gateway_url}/{cid}",
                    timeout=30.0,
                )
                if response.status_code == 404:
                    raise KeyError(f"CID/transaction not found on Arweave: {cid}")
                response.raise_for_status()
                data = response.content
        except httpx.HTTPError as exc:
            raise StorageError(
                f"Failed to retrieve {cid} from Arweave gateway: {exc}"
            ) from exc

        # Invariant 25: verify integrity on retrieval
        if not self.verify_integrity(cid, data):
            raise IntegrityError(
                f"Data integrity check failed for CID {cid}. "
                f"Retrieved data from Arweave does not match expected CID."
            )

        return data

    async def pin(self, cid: str) -> bool:
        """Pin is a no-op for Arweave — data is permanent by design.

        Args:
            cid: The content identifier.

        Returns:
            True (Arweave data is permanently stored).
        """
        return True

    async def is_available(self, cid: str) -> bool:
        """Check if data is available on Arweave.

        Args:
            cid: The content identifier to check.

        Returns:
            True if the data is retrievable, False otherwise.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.head(
                    f"{self.gateway_url}/{cid}",
                    timeout=10.0,
                )
                return response.status_code == 200
        except httpx.HTTPError:
            return False
