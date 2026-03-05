# polis/node/tests/test_storage.py
"""
Tests for the Polis Storage layer.

Covers:
- LocalStorageBackend: put, get, pin, is_available, integrity verification
- CID computation and determinism
- Integrity error detection (tampered data)
- Missing CID handling
"""

from __future__ import annotations

import os
import tempfile

import pytest

from polis_node.storage.interface import IntegrityError, StorageBackend
from polis_node.storage.local import LocalStorageBackend


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def storage_dir() -> str:
    """Create a temporary directory for local storage tests."""
    with tempfile.TemporaryDirectory(prefix="polis_test_") as tmpdir:
        yield tmpdir


@pytest.fixture
def backend(storage_dir: str) -> LocalStorageBackend:
    """Create a LocalStorageBackend for testing."""
    return LocalStorageBackend(storage_dir)


# ---------------------------------------------------------------------------
# CID Computation
# ---------------------------------------------------------------------------


class TestCIDComputation:
    """Tests for content identifier computation."""

    def test_cid_deterministic(self) -> None:
        """Same data always produces the same CID."""
        data = b"deterministic content"
        cid_a = StorageBackend.compute_cid(data)
        cid_b = StorageBackend.compute_cid(data)
        assert cid_a == cid_b

    def test_cid_different_for_different_data(self) -> None:
        """Different data produces different CIDs."""
        cid_a = StorageBackend.compute_cid(b"data a")
        cid_b = StorageBackend.compute_cid(b"data b")
        assert cid_a != cid_b

    def test_cid_has_multihash_prefix(self) -> None:
        """CID starts with CIDv1 multihash prefix 01551220."""
        cid = StorageBackend.compute_cid(b"test")
        assert cid.startswith("01551220")

    def test_verify_integrity_valid(self) -> None:
        """Integrity verification passes for correct data."""
        data = b"valid data"
        cid = StorageBackend.compute_cid(data)
        assert StorageBackend.verify_integrity(cid, data) is True

    def test_verify_integrity_tampered(self) -> None:
        """Integrity verification fails for tampered data."""
        data = b"original data"
        cid = StorageBackend.compute_cid(data)
        assert StorageBackend.verify_integrity(cid, b"tampered data") is False


# ---------------------------------------------------------------------------
# LocalStorageBackend
# ---------------------------------------------------------------------------


class TestLocalStorageBackend:
    """Tests for the filesystem-based local storage backend."""

    @pytest.mark.asyncio
    async def test_put_returns_cid(self, backend: LocalStorageBackend) -> None:
        """put() returns a valid CID."""
        data = b"Hello, Polis!"
        cid = await backend.put(data)
        assert cid.startswith("01551220")

    @pytest.mark.asyncio
    async def test_put_get_round_trip(self, backend: LocalStorageBackend) -> None:
        """Data stored with put() is retrieved unchanged with get()."""
        data = b"round trip content"
        cid = await backend.put(data)
        retrieved = await backend.get(cid)
        assert retrieved == data

    @pytest.mark.asyncio
    async def test_get_nonexistent_raises_keyerror(
        self, backend: LocalStorageBackend
    ) -> None:
        """Getting a non-existent CID raises KeyError."""
        with pytest.raises(KeyError, match="CID not found"):
            await backend.get("01551220" + "0" * 64)

    @pytest.mark.asyncio
    async def test_is_available_true(self, backend: LocalStorageBackend) -> None:
        """is_available returns True for stored data."""
        cid = await backend.put(b"available data")
        assert await backend.is_available(cid) is True

    @pytest.mark.asyncio
    async def test_is_available_false(self, backend: LocalStorageBackend) -> None:
        """is_available returns False for non-existent CID."""
        assert await backend.is_available("01551220" + "f" * 64) is False

    @pytest.mark.asyncio
    async def test_pin_existing(self, backend: LocalStorageBackend) -> None:
        """pin() returns True for existing data."""
        cid = await backend.put(b"pin me")
        assert await backend.pin(cid) is True

    @pytest.mark.asyncio
    async def test_pin_nonexistent(self, backend: LocalStorageBackend) -> None:
        """pin() returns False for non-existent CID."""
        assert await backend.pin("01551220" + "0" * 64) is False

    @pytest.mark.asyncio
    async def test_delete_existing(self, backend: LocalStorageBackend) -> None:
        """delete() removes data and returns True."""
        cid = await backend.put(b"delete me")
        assert await backend.delete(cid) is True
        assert await backend.is_available(cid) is False

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, backend: LocalStorageBackend) -> None:
        """delete() returns False for non-existent CID."""
        assert await backend.delete("01551220" + "0" * 64) is False

    @pytest.mark.asyncio
    async def test_list_cids(self, backend: LocalStorageBackend) -> None:
        """list_cids() returns all stored CIDs."""
        cid_a = await backend.put(b"data a")
        cid_b = await backend.put(b"data b")
        cids = await backend.list_cids()
        assert cid_a in cids
        assert cid_b in cids

    @pytest.mark.asyncio
    async def test_integrity_check_on_get(
        self, backend: LocalStorageBackend, storage_dir: str
    ) -> None:
        """get() detects tampered data by verifying CID integrity."""
        data = b"original data"
        cid = await backend.put(data)

        # Tamper with the stored file directly
        filepath = os.path.join(storage_dir, cid)
        with open(filepath, "wb") as f:
            f.write(b"tampered data")

        with pytest.raises(IntegrityError, match="integrity check failed"):
            await backend.get(cid)

    @pytest.mark.asyncio
    async def test_multiple_puts_same_data(
        self, backend: LocalStorageBackend
    ) -> None:
        """Storing the same data twice returns the same CID (idempotent)."""
        data = b"duplicate content"
        cid_a = await backend.put(data)
        cid_b = await backend.put(data)
        assert cid_a == cid_b

    @pytest.mark.asyncio
    async def test_large_payload(self, backend: LocalStorageBackend) -> None:
        """Backend handles large payloads (1MB)."""
        data = b"x" * (1024 * 1024)  # 1MB
        cid = await backend.put(data)
        retrieved = await backend.get(cid)
        assert retrieved == data

    @pytest.mark.asyncio
    async def test_empty_payload(self, backend: LocalStorageBackend) -> None:
        """Backend handles empty payloads."""
        cid = await backend.put(b"")
        retrieved = await backend.get(cid)
        assert retrieved == b""

    @pytest.mark.asyncio
    async def test_creates_directory_if_missing(self) -> None:
        """Backend creates the data directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as parent:
            path = os.path.join(parent, "nonexistent", "subdir")
            backend = LocalStorageBackend(path)
            cid = await backend.put(b"auto create dir")
            assert await backend.is_available(cid)
