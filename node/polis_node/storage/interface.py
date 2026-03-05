# polis/node/polis_node/storage/interface.py
"""
Polis Storage Backend Interface.

Abstract base class for all storage backends. Storage backends are
interchangeable — the CID of a record is the same regardless of which
backend stores the data. Data integrity is verified on retrieval.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod


class StorageBackend(ABC):
    """Abstract interface for Polis storage backends.

    All storage backends must implement put, get, pin, and is_available.
    CIDs are computed identically regardless of backend.

    The interface is async by default — all I/O operations are async.
    """

    @abstractmethod
    async def put(self, data: bytes) -> str:
        """Store data and return its content identifier (CID).

        Args:
            data: The raw bytes to store.

        Returns:
            The CID (SHA-256 multihash hex) of the stored data.

        Raises:
            StorageError: If the data could not be stored.
        """
        ...

    @abstractmethod
    async def get(self, cid: str) -> bytes:
        """Retrieve data by its content identifier.

        Data integrity is verified on retrieval — the retrieved data
        must match the requested CID.

        Args:
            cid: The content identifier to retrieve.

        Returns:
            The raw bytes associated with the CID.

        Raises:
            StorageError: If the data could not be retrieved.
            IntegrityError: If the retrieved data does not match the CID.
            KeyError: If the CID is not found.
        """
        ...

    @abstractmethod
    async def pin(self, cid: str) -> bool:
        """Ensure data persists on this node / backend.

        Args:
            cid: The content identifier to pin.

        Returns:
            True if pinning succeeded, False otherwise.
        """
        ...

    @abstractmethod
    async def is_available(self, cid: str) -> bool:
        """Check if data is available for the given CID.

        Args:
            cid: The content identifier to check.

        Returns:
            True if the data is available, False otherwise.
        """
        ...

    @staticmethod
    def compute_cid(data: bytes) -> str:
        """Compute the CID for arbitrary data using CIDv1 / SHA-256 multihash.

        Format: ``<version><codec><hash-fn><hash-len><hash-digest>``  (all hex)

        - Version ``01`` = CIDv1
        - Codec ``55`` = raw binary
        - Hash function ``12`` = SHA-256  (multihash table)
        - Hash length ``20`` = 32 bytes (0x20)
        - Digest = hex-encoded SHA-256

        This is a static utility — all backends use the same CID scheme.

        Args:
            data: The raw bytes to hash.

        Returns:
            Hex-encoded CIDv1 multihash string.
        """
        digest = hashlib.sha256(data).hexdigest()
        # CIDv1 prefix: version=01, codec=55(raw), hash-fn=12(sha256), len=20(32 bytes)
        return f"01551220{digest}"

    @staticmethod
    def verify_integrity(cid: str, data: bytes) -> bool:
        """Verify that data matches its expected CID.

        Args:
            cid: The expected content identifier.
            data: The data to verify.

        Returns:
            True if the data matches the CID, False otherwise.
        """
        return StorageBackend.compute_cid(data) == cid


class StorageError(Exception):
    """Raised when a storage operation fails."""
    pass


class IntegrityError(StorageError):
    """Raised when retrieved data does not match its expected CID."""
    pass
