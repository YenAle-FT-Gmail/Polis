# polis/node/tests/test_persistence.py
"""Tests for identity persistence (encrypted file-based storage)."""

from __future__ import annotations

import os
import tempfile

import pytest

from polis_node.identity.did import PolisIdentity
from polis_node.identity.persistence import load_identity, save_identity


class TestIdentityPersistence:
    """Tests for save_identity / load_identity round-trip."""

    def test_save_load_round_trip(self) -> None:
        """Saved identity can be loaded with the same passphrase."""
        identity = PolisIdentity.create()
        passphrase = "test-passphrase-42"

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "identity.enc")
            save_identity(identity, path, passphrase)
            loaded = load_identity(path, passphrase)

        assert loaded.did == identity.did
        assert loaded.signing_key_public == identity.signing_key_public
        assert loaded.signing_key_private == identity.signing_key_private
        assert loaded.recovery_key_public == identity.recovery_key_public
        assert loaded.recovery_key_private == identity.recovery_key_private
        assert loaded.created_at == identity.created_at

    def test_wrong_passphrase_raises(self) -> None:
        """Loading with wrong passphrase raises ValueError."""
        identity = PolisIdentity.create()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "identity.enc")
            save_identity(identity, path, "correct")
            with pytest.raises(ValueError, match="Wrong passphrase"):
                load_identity(path, "incorrect")

    def test_empty_passphrase_raises(self) -> None:
        """Empty passphrase is rejected on save."""
        identity = PolisIdentity.create()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "identity.enc")
            with pytest.raises(ValueError, match="must not be empty"):
                save_identity(identity, path, "")

    def test_file_not_found_raises(self) -> None:
        """Loading from a non-existent path raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_identity("/nonexistent/path/identity.enc", "pass")

    def test_loaded_identity_can_sign(self) -> None:
        """A loaded identity can sign and verify correctly."""
        identity = PolisIdentity.create()
        passphrase = "sign-test-pass"

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "identity.enc")
            save_identity(identity, path, passphrase)
            loaded = load_identity(path, passphrase)

        payload = b"verify me after loading"
        sig = loaded.sign(payload)
        assert loaded.verify(payload, sig) is True

    def test_storage_endpoint_persisted(self) -> None:
        """Storage endpoint is preserved through save/load."""
        identity = PolisIdentity.create(storage_endpoint="https://example.com/store")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "identity.enc")
            save_identity(identity, path, "pass")
            loaded = load_identity(path, "pass")

        assert loaded.storage_endpoint == "https://example.com/store"

    def test_creates_parent_dirs(self) -> None:
        """save_identity creates parent directories if needed."""
        identity = PolisIdentity.create()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "nested", "deep", "identity.enc")
            save_identity(identity, path, "pass")
            loaded = load_identity(path, "pass")
            assert loaded.did == identity.did
