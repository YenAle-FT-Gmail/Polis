# polis/node/tests/test_identity.py
"""
Tests for the Polis DID identity primitive.

Covers:
- DID generation and determinism
- DID document structure (W3C DID Core compliance)
- Signing and verification
- Key rotation with DID preservation
- Recovery key mnemonic serialization and recovery
- DID resolver operations
"""

import hashlib

import base58
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mnemonic import Mnemonic

from polis_node.identity.did import (
    BIP39_LANGUAGE,
    DID_DOCUMENT_CONTEXT,
    POLIS_DID_PREFIX,
    DIDResolver,
    PolisIdentity,
    _compute_fingerprint,
    _make_did,
    _mnemonic_to_private_key,
    _private_key_to_mnemonic,
)


# ---------------------------------------------------------------------------
# DID Generation
# ---------------------------------------------------------------------------


class TestDIDGeneration:
    """Tests for DID creation and deterministic derivation."""

    def test_create_identity_returns_valid_did(self) -> None:
        """A newly created identity has a DID starting with the Polis prefix."""
        identity = PolisIdentity.create()
        assert identity.did.startswith(POLIS_DID_PREFIX)

    def test_did_is_deterministic_from_public_key(self) -> None:
        """The same public key always produces the same DID fingerprint."""
        identity = PolisIdentity.create()
        recomputed_did = _make_did(identity.signing_key_public)
        assert identity.did == recomputed_did

    def test_fingerprint_uses_sha256(self) -> None:
        """The fingerprint is a Base58btc-encoded SHA-256 of the public key."""
        identity = PolisIdentity.create()
        expected_digest = hashlib.sha256(identity.signing_key_public).digest()
        expected_fingerprint = base58.b58encode(expected_digest).decode("ascii")
        assert identity.did == f"{POLIS_DID_PREFIX}{expected_fingerprint}"

    def test_two_identities_have_different_dids(self) -> None:
        """Two independently created identities have distinct DIDs."""
        id_a = PolisIdentity.create()
        id_b = PolisIdentity.create()
        assert id_a.did != id_b.did

    def test_identity_has_timestamps(self) -> None:
        """Created identity has ISO 8601 timestamps."""
        identity = PolisIdentity.create()
        assert identity.created_at != ""
        assert identity.updated_at != ""
        # Should parse as ISO 8601 — Python's fromisoformat handles this
        from datetime import datetime
        datetime.fromisoformat(identity.created_at)
        datetime.fromisoformat(identity.updated_at)

    def test_key_sizes(self) -> None:
        """Ed25519 keys are 32 bytes."""
        identity = PolisIdentity.create()
        assert len(identity.signing_key_public) == 32
        assert len(identity.signing_key_private) == 32
        assert len(identity.recovery_key_public) == 32
        assert len(identity.recovery_key_private) == 32

    def test_signing_and_recovery_keys_are_different(self) -> None:
        """Signing and recovery keypairs are independently generated."""
        identity = PolisIdentity.create()
        assert identity.signing_key_public != identity.recovery_key_public
        assert identity.signing_key_private != identity.recovery_key_private


# ---------------------------------------------------------------------------
# DID Document
# ---------------------------------------------------------------------------


class TestDIDDocument:
    """Tests for DID Document generation (W3C DID Core compliance)."""

    def test_document_has_context(self) -> None:
        """DID Document includes required JSON-LD @context."""
        identity = PolisIdentity.create()
        doc = identity.to_did_document()
        assert doc["@context"] == list(DID_DOCUMENT_CONTEXT)

    def test_document_id_matches_did(self) -> None:
        """DID Document id field matches the identity's DID."""
        identity = PolisIdentity.create()
        doc = identity.to_did_document()
        assert doc["id"] == identity.did

    def test_document_has_verification_methods(self) -> None:
        """DID Document contains both signing and recovery verification methods."""
        identity = PolisIdentity.create()
        doc = identity.to_did_document()
        methods = doc["verificationMethod"]
        assert len(methods) == 2

        signing_method = methods[0]
        assert signing_method["id"] == f"{identity.did}#signing-key"
        assert signing_method["type"] == "Ed25519VerificationKey2020"
        assert signing_method["controller"] == identity.did

        recovery_method = methods[1]
        assert recovery_method["id"] == f"{identity.did}#recovery-key"

    def test_document_has_authentication(self) -> None:
        """DID Document references signing key for authentication."""
        identity = PolisIdentity.create()
        doc = identity.to_did_document()
        assert f"{identity.did}#signing-key" in doc["authentication"]

    def test_document_includes_storage_endpoint(self) -> None:
        """DID Document includes storage service if endpoint is set."""
        identity = PolisIdentity.create(storage_endpoint="https://storage.example.com")
        doc = identity.to_did_document()
        assert "service" in doc
        service = doc["service"][0]
        assert service["type"] == "PolisStorageEndpoint"
        assert service["serviceEndpoint"] == "https://storage.example.com"

    def test_document_no_private_keys(self) -> None:
        """DID Document never contains private key material."""
        identity = PolisIdentity.create()
        doc = identity.to_did_document()
        doc_str = str(doc)
        # Private key bytes should not appear in the document
        priv_signing_b58 = base58.b58encode(identity.signing_key_private).decode()
        priv_recovery_b58 = base58.b58encode(identity.recovery_key_private).decode()
        assert priv_signing_b58 not in doc_str
        assert priv_recovery_b58 not in doc_str

    def test_document_timestamps(self) -> None:
        """DID Document has created and updated timestamps."""
        identity = PolisIdentity.create()
        doc = identity.to_did_document()
        assert doc["created"] == identity.created_at
        assert doc["updated"] == identity.updated_at


# ---------------------------------------------------------------------------
# Signing and Verification
# ---------------------------------------------------------------------------


class TestSigningVerification:
    """Tests for Ed25519 signing and verification."""

    def test_sign_and_verify(self) -> None:
        """A signature produced by sign() is verified by verify()."""
        identity = PolisIdentity.create()
        payload = b"Hello, Polis!"
        signature = identity.sign(payload)
        assert identity.verify(payload, signature) is True

    def test_verify_wrong_payload(self) -> None:
        """Verification fails when the payload doesn't match the signature."""
        identity = PolisIdentity.create()
        signature = identity.sign(b"original payload")
        assert identity.verify(b"tampered payload", signature) is False

    def test_verify_wrong_signature(self) -> None:
        """Verification fails with an invalid signature."""
        identity = PolisIdentity.create()
        payload = b"test payload"
        bad_signature = b"\x00" * 64
        assert identity.verify(payload, bad_signature) is False

    def test_verify_cross_identity(self) -> None:
        """Signature from one identity cannot be verified by another."""
        id_a = PolisIdentity.create()
        id_b = PolisIdentity.create()
        payload = b"cross-identity test"
        signature = id_a.sign(payload)
        assert id_b.verify(payload, signature) is False

    def test_signature_is_64_bytes(self) -> None:
        """Ed25519 signatures are exactly 64 bytes."""
        identity = PolisIdentity.create()
        signature = identity.sign(b"test")
        assert len(signature) == 64


# ---------------------------------------------------------------------------
# Key Rotation
# ---------------------------------------------------------------------------


class TestKeyRotation:
    """Tests for signing key rotation with DID preservation."""

    def test_rotation_preserves_did(self) -> None:
        """Key rotation must preserve the DID — the identifier never changes."""
        identity = PolisIdentity.create()
        original_did = identity.did
        rotated = identity.rotate_signing_key()
        assert rotated.did == original_did

    def test_rotation_changes_signing_key(self) -> None:
        """After rotation, the signing key is different."""
        identity = PolisIdentity.create()
        original_signing_pub = identity.signing_key_public
        rotated = identity.rotate_signing_key()
        assert rotated.signing_key_public != original_signing_pub

    def test_rotation_preserves_recovery_key(self) -> None:
        """Key rotation does not change the recovery key."""
        identity = PolisIdentity.create()
        rotated = identity.rotate_signing_key()
        assert rotated.recovery_key_public == identity.recovery_key_public
        assert rotated.recovery_key_private == identity.recovery_key_private

    def test_rotation_updates_timestamp(self) -> None:
        """Key rotation updates the updated_at timestamp."""
        identity = PolisIdentity.create()
        rotated = identity.rotate_signing_key()
        assert rotated.updated_at >= identity.updated_at
        assert rotated.created_at == identity.created_at

    def test_rotation_with_specific_key(self) -> None:
        """Rotation accepts a specific new key."""
        identity = PolisIdentity.create()
        new_key = Ed25519PrivateKey.generate()
        rotated = identity.rotate_signing_key(new_key)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        expected_pub = new_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert rotated.signing_key_public == expected_pub

    def test_old_signatures_fail_after_rotation(self) -> None:
        """Signatures from the old signing key fail verification with the new key."""
        identity = PolisIdentity.create()
        payload = b"before rotation"
        signature = identity.sign(payload)
        rotated = identity.rotate_signing_key()
        assert rotated.verify(payload, signature) is False


# ---------------------------------------------------------------------------
# Mnemonic Recovery
# ---------------------------------------------------------------------------


class TestMnemonicRecovery:
    """Tests for BIP-39 mnemonic serialization of recovery keys."""

    def test_mnemonic_is_24_words(self) -> None:
        """Recovery key mnemonic is 24 words (256 bits)."""
        identity = PolisIdentity.create()
        mnemonic = identity.serialize_recovery_key_to_mnemonic()
        words = mnemonic.split()
        assert len(words) == 24

    def test_mnemonic_is_valid_bip39(self) -> None:
        """Generated mnemonic passes BIP-39 validation."""
        identity = PolisIdentity.create()
        mnemonic_str = identity.serialize_recovery_key_to_mnemonic()
        m = Mnemonic(BIP39_LANGUAGE)
        assert m.check(mnemonic_str) is True

    def test_mnemonic_round_trip(self) -> None:
        """A mnemonic can be converted back to the original private key."""
        identity = PolisIdentity.create()
        mnemonic_str = identity.serialize_recovery_key_to_mnemonic()

        recovered_key = _mnemonic_to_private_key(mnemonic_str)
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )
        recovered_bytes = recovered_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        assert recovered_bytes == identity.recovery_key_private

    def test_invalid_mnemonic_raises(self) -> None:
        """An invalid mnemonic raises ValueError."""
        with pytest.raises(ValueError, match="Invalid BIP-39 mnemonic"):
            _mnemonic_to_private_key("invalid mnemonic phrase that is not valid")

    def test_wrong_key_size_raises(self) -> None:
        """A non-32-byte value raises ValueError for mnemonic encoding."""
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            _private_key_to_mnemonic(b"too short")


# ---------------------------------------------------------------------------
# DID Resolver
# ---------------------------------------------------------------------------


class TestDIDResolver:
    """Tests for the local DID resolver."""

    def test_register_and_resolve(self) -> None:
        """Registered identities can be resolved by DID."""
        resolver = DIDResolver()
        identity = PolisIdentity.create()
        resolver.register(identity)
        doc = resolver.resolve(identity.did)
        assert doc is not None
        assert doc["id"] == identity.did

    def test_resolve_unknown_did(self) -> None:
        """Resolving an unregistered DID returns None."""
        resolver = DIDResolver()
        assert resolver.resolve("did:polis:nonexistent") is None

    def test_get_signing_public_key(self) -> None:
        """Signing public key can be extracted from a resolved DID."""
        resolver = DIDResolver()
        identity = PolisIdentity.create()
        resolver.register(identity)
        key = resolver.get_signing_public_key(identity.did)
        assert key == identity.signing_key_public

    def test_update_after_rotation(self) -> None:
        """DID document is updated after key rotation."""
        resolver = DIDResolver()
        identity = PolisIdentity.create()
        resolver.register(identity)

        rotated = identity.rotate_signing_key()
        resolver.update(rotated)

        key = resolver.get_signing_public_key(rotated.did)
        assert key == rotated.signing_key_public
        assert key != identity.signing_key_public

    def test_update_unregistered_raises(self) -> None:
        """Updating an unregistered DID raises KeyError."""
        resolver = DIDResolver()
        identity = PolisIdentity.create()
        with pytest.raises(KeyError, match="Cannot update unregistered DID"):
            resolver.update(identity)

    def test_get_key_unknown_did(self) -> None:
        """Getting a signing key for an unknown DID returns None."""
        resolver = DIDResolver()
        assert resolver.get_signing_public_key("did:polis:unknown") is None


# ---------------------------------------------------------------------------
# Identity Recovery from Mnemonic (I12)
# ---------------------------------------------------------------------------


class TestRecoverFromMnemonic:
    """Tests for full identity recovery using BIP-39 mnemonic."""

    def test_recover_from_mnemonic_restores_recovery_key(self) -> None:
        """Recovery from mnemonic restores the original recovery public key."""
        identity = PolisIdentity.create()
        mnemonic = identity.serialize_recovery_key_to_mnemonic()

        recovered = PolisIdentity.recover_from_mnemonic(
            mnemonic_phrase=mnemonic,
            signing_key_private=identity.signing_key_private,
            did=identity.did,
            created_at=identity.created_at,
        )
        assert recovered.did == identity.did
        assert recovered.recovery_key_public == identity.recovery_key_public
        assert recovered.recovery_key_private == identity.recovery_key_private

    def test_recovered_identity_can_sign(self) -> None:
        """A recovered identity can sign and verify."""
        identity = PolisIdentity.create()
        mnemonic = identity.serialize_recovery_key_to_mnemonic()

        recovered = PolisIdentity.recover_from_mnemonic(
            mnemonic_phrase=mnemonic,
            signing_key_private=identity.signing_key_private,
            did=identity.did,
            created_at=identity.created_at,
        )
        payload = b"test after recovery"
        sig = recovered.sign(payload)
        assert recovered.verify(payload, sig) is True

    def test_recover_preserves_did(self) -> None:
        """Recovered DID matches the original."""
        identity = PolisIdentity.create()
        mnemonic = identity.serialize_recovery_key_to_mnemonic()

        recovered = PolisIdentity.recover_from_mnemonic(
            mnemonic_phrase=mnemonic,
            signing_key_private=identity.signing_key_private,
            did=identity.did,
            created_at=identity.created_at,
        )
        assert recovered.did == identity.did
        assert recovered.created_at == identity.created_at

    def test_recover_with_invalid_mnemonic_raises(self) -> None:
        """Invalid mnemonic raises ValueError during recovery."""
        identity = PolisIdentity.create()
        with pytest.raises(ValueError, match="Invalid BIP-39"):
            PolisIdentity.recover_from_mnemonic(
                mnemonic_phrase="not a valid mnemonic phrase at all",
                signing_key_private=identity.signing_key_private,
                did=identity.did,
                created_at=identity.created_at,
            )

    def test_recover_with_storage_endpoint(self) -> None:
        """Recovery preserves optional storage endpoint."""
        identity = PolisIdentity.create(storage_endpoint="https://example.com")
        mnemonic = identity.serialize_recovery_key_to_mnemonic()

        recovered = PolisIdentity.recover_from_mnemonic(
            mnemonic_phrase=mnemonic,
            signing_key_private=identity.signing_key_private,
            did=identity.did,
            created_at=identity.created_at,
            storage_endpoint="https://example.com",
        )
        assert recovered.storage_endpoint == "https://example.com"
