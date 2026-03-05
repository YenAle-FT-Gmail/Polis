# polis/node/polis_node/storage/local.py
"""
Polis Local Storage Backend.

Filesystem-based storage for development and testing. Data is stored
as individual files named by their CID in a configurable directory.
Integrity is verified on every retrieval.
"""

from __future__ import annotations

import os
from pathlib import Path

import aiofiles
import aiofiles.os

from polis_node.storage.interface import IntegrityError, StorageBackend, StorageError


class LocalStorageBackend(StorageBackend):
    """Filesystem-based storage backend.

    Stores content-addressed data as individual files in a directory.
    Filenames are the CID of the content. Data integrity is verified
    on every retrieval by recomputing the CID.

    Attributes:
        data_dir: Path to the directory where data is stored.
    """

    def __init__(self, data_dir: str) -> None:
        """Initialize the local storage backend.

        Args:
            data_dir: Filesystem path for data storage. Created if it
                does not exist.
        """
        self.data_dir = Path(data_dir)

    async def _ensure_dir(self) -> None:
        """Ensure the data directory exists."""
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _path_for_cid(self, cid: str) -> Path:
        """Return the filesystem path for a given CID.

        Args:
            cid: The content identifier.

        Returns:
            Path object pointing to the file.
        """
        return self.data_dir / cid

    async def put(self, data: bytes) -> str:
        """Store data to the local filesystem and return its CID.

        Args:
            data: The raw bytes to store.

        Returns:
            The CID (SHA-256 multihash hex) of the stored data.

        Raises:
            StorageError: If the file cannot be written.
        """
        await self._ensure_dir()
        cid = self.compute_cid(data)
        path = self._path_for_cid(cid)

        try:
            async with aiofiles.open(path, "wb") as f:
                await f.write(data)
        except OSError as exc:
            raise StorageError(
                f"Failed to write data for CID {cid} to {path}: {exc}"
            ) from exc

        return cid

    async def get(self, cid: str) -> bytes:
        """Retrieve data by CID from the local filesystem.

        Integrity is verified by recomputing the CID of the retrieved data.

        Args:
            cid: The content identifier to retrieve.

        Returns:
            The raw bytes associated with the CID.

        Raises:
            KeyError: If the CID is not found on disk.
            IntegrityError: If the retrieved data does not match the CID.
            StorageError: If the file cannot be read.
        """
        path = self._path_for_cid(cid)

        try:
            await aiofiles.os.stat(str(path))
        except FileNotFoundError:
            raise KeyError(
                f"CID not found in local storage: {cid}. "
                f"Expected file at {path}"
            )

        try:
            async with aiofiles.open(path, "rb") as f:
                data = await f.read()
        except OSError as exc:
            raise StorageError(
                f"Failed to read data for CID {cid} from {path}: {exc}"
            ) from exc

        if not self.verify_integrity(cid, data):
            raise IntegrityError(
                f"Data integrity check failed for CID {cid}. "
                f"Retrieved data does not match expected content identifier."
            )

        return data

    async def pin(self, cid: str) -> bool:
        """Pin data in local storage (no-op for filesystem — data persists).

        Args:
            cid: The content identifier to pin.

        Returns:
            True if the CID exists in storage, False otherwise.
        """
        return await self.is_available(cid)

    async def is_available(self, cid: str) -> bool:
        """Check if a CID is available in local storage.

        Args:
            cid: The content identifier to check.

        Returns:
            True if the file exists, False otherwise.
        """
        path = self._path_for_cid(cid)
        try:
            await aiofiles.os.stat(str(path))
            return True
        except FileNotFoundError:
            return False

    async def delete(self, cid: str) -> bool:
        """Delete data by CID from local storage.

        Args:
            cid: The content identifier to delete.

        Returns:
            True if the file was deleted, False if it didn't exist.
        """
        path = self._path_for_cid(cid)
        try:
            await aiofiles.os.remove(str(path))
            return True
        except FileNotFoundError:
            return False

    async def list_cids(self) -> list[str]:
        """List all CIDs stored locally.

        Returns:
            A list of CID strings.
        """
        await self._ensure_dir()
        entries = await aiofiles.os.listdir(str(self.data_dir))
        return [e for e in entries if (self.data_dir / e).is_file()]
