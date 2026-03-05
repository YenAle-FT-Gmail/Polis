# polis/node/polis_node/storage/ipfs.py
"""
Polis IPFS Storage Backend.

Interfaces with a local IPFS daemon via its HTTP API.
Not fully implemented in v0.1 — use LocalStorageBackend for development.
"""

from __future__ import annotations

from typing import Optional

import httpx

from polis_node.storage.interface import IntegrityError, StorageBackend, StorageError


class IPFSBackend(StorageBackend):
    """IPFS storage backend that communicates with a local IPFS daemon.

    Requires a running IPFS daemon with the HTTP API enabled.
    Default API endpoint: http://localhost:5001

    Attributes:
        api_url: Base URL of the IPFS HTTP API.
    """

    def __init__(self, api_url: str = "http://localhost:5001") -> None:
        """Initialize the IPFS backend.

        Args:
            api_url: Base URL of the IPFS HTTP API.
        """
        self.api_url = api_url.rstrip("/")

    async def put(self, data: bytes) -> str:
        """Store data via the IPFS HTTP API.

        Args:
            data: The raw bytes to store.

        Returns:
            The CID of the stored data.

        Raises:
            StorageError: If the IPFS daemon is unreachable or the
                operation fails.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.api_url}/api/v0/add",
                    files={"file": ("data", data)},
                    timeout=30.0,
                )
                response.raise_for_status()
                result = response.json()
                # IPFS returns the CID in the "Hash" field
                return result["Hash"]
        except httpx.HTTPError as exc:
            raise StorageError(
                f"Failed to store data via IPFS API at {self.api_url}: {exc}"
            ) from exc

    async def get(self, cid: str) -> bytes:
        """Retrieve data from IPFS by CID.

        Args:
            cid: The content identifier to retrieve.

        Returns:
            The raw bytes associated with the CID.

        Raises:
            KeyError: If the CID is not found.
            StorageError: If the IPFS daemon is unreachable.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.api_url}/api/v0/cat",
                    params={"arg": cid},
                    timeout=30.0,
                )
                if response.status_code == 404:
                    raise KeyError(f"CID not found in IPFS: {cid}")
                response.raise_for_status()
                data = response.content
        except httpx.HTTPError as exc:
            raise StorageError(
                f"Failed to retrieve CID {cid} from IPFS API: {exc}"
            ) from exc

        # Invariant 25: verify integrity on retrieval
        if not self.verify_integrity(cid, data):
            raise IntegrityError(
                f"Data integrity check failed for CID {cid}. "
                f"Retrieved data from IPFS does not match expected CID."
            )

        return data

    async def pin(self, cid: str) -> bool:
        """Pin a CID on the local IPFS node.

        Args:
            cid: The content identifier to pin.

        Returns:
            True if pinning succeeded.

        Raises:
            StorageError: If the pin operation fails.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.api_url}/api/v0/pin/add",
                    params={"arg": cid},
                    timeout=60.0,
                )
                response.raise_for_status()
                return True
        except httpx.HTTPError as exc:
            raise StorageError(
                f"Failed to pin CID {cid} on IPFS: {exc}"
            ) from exc

    async def is_available(self, cid: str) -> bool:
        """Check if a CID is available on IPFS.

        Args:
            cid: The content identifier to check.

        Returns:
            True if the data is available, False otherwise.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.api_url}/api/v0/cat",
                    params={"arg": cid},
                    timeout=10.0,
                )
                return response.status_code == 200
        except httpx.HTTPError:
            return False
