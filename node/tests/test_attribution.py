# polis/node/tests/test_attribution.py
"""
Tests for the Polis Attribution Record.

Covers:
- Record creation (public, private, selective)
- Canonical serialization
- Signature verification
- Content addressing (CID)
- Encryption for private records
- Permission tokens (grant, revoke, expiry)
- Adversarial: tampered payload, forged signature
"""

import hashlib
import time
from datetime import datetime, timezone

import pytest
from cryptography.exceptions import InvalidTag

from polis_node.attribution.record import (
    POLIS_VERSION,
    VISIBILITY_PRIVATE,
    VISIBILITY_PUBLIC,
    VISIBILITY_SELECTIVE,
    AttributionRecord,
    PermissionToken,
    _compute_cid,
    _compute_payload_hash,
    _decrypt_payload,
    _encrypt_payload,
)
from polis_node.identity.did import DIDResolver, PolisIdentity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def identity() -> PolisIdentity:
    """Create a fresh PolisIdentity for testing."""
    return PolisIdentity.create()


@pytest.fixture
def resolver(identity: PolisIdentity) -> DIDResolver:
    """Create a DID resolver with the test identity registered."""
    r = DIDResolver()
    r.register(identity)
    return r


# ---------------------------------------------------------------------------
# Record Creation
# ---------------------------------------------------------------------------


class TestRecordCreation:
    """Tests for creating attribution records."""

    def test_create_public_record(self, identity: PolisIdentity) -> None:
        """A public record is created with valid fields."""
        payload = b"Hello, Polis!"
        record, _ = AttributionRecord.create(payload, identity)
        assert record.polis_version == POLIS_VERSION
        assert record.record_type == "polis.content.post"
        assert record.author_did == identity.did
        assert record.visibility == VISIBILITY_PUBLIC
        assert record.signature != ""
        assert record.payload_hash == _compute_payload_hash(payload)

    def test_cid_matches_payload(self, identity: PolisIdentity) -> None:
        """CID is derived from the payload for public records."""
        payload = b"test content"
        record, _ = AttributionRecord.create(payload, identity)
        expected_cid = _compute_cid(payload)
        assert record.cid == expected_cid

    def test_timestamp_is_utc_iso8601(self, identity: PolisIdentity) -> None:
        """Record timestamp is valid ISO 8601 UTC."""
        record, _ = AttributionRecord.create(b"test", identity)
        dt = datetime.fromisoformat(record.timestamp)
        assert dt.tzinfo is not None  # timezone-aware

    def test_invalid_visibility_raises(self, identity: PolisIdentity) -> None:
        """Invalid visibility value raises ValueError."""
        with pytest.raises(ValueError, match="Invalid visibility"):
            AttributionRecord.create(b"test", identity, visibility="invalid")

    def test_invalid_record_type_raises(self, identity: PolisIdentity) -> None:
        """Record type without polis. prefix raises ValueError."""
        with pytest.raises(ValueError, match="namespaced"):
            AttributionRecord.create(b"test", identity, record_type="bad.type")

    def test_custom_record_type(self, identity: PolisIdentity) -> None:
        """Custom record types with polis. prefix are accepted."""
        record, _ = AttributionRecord.create(
            b"test", identity, record_type="polis.social.comment"
        )
        assert record.record_type == "polis.social.comment"


# ---------------------------------------------------------------------------
# Canonical Serialization
# ---------------------------------------------------------------------------


class TestCanonicalSerialization:
    """Tests for RFC 8785 canonical JSON serialization."""

    def test_canonical_bytes_deterministic(self, identity: PolisIdentity) -> None:
        """Canonical bytes are deterministic for the same record."""
        record, _ = AttributionRecord.create(b"test", identity)
        assert record.canonical_bytes() == record.canonical_bytes()

    def test_canonical_excludes_signature(self, identity: PolisIdentity) -> None:
        """Canonical form does not include the signature field."""
        record, _ = AttributionRecord.create(b"test", identity)
        canonical = record.canonical_bytes()
        assert b"signature" not in canonical

    def test_canonical_keys_sorted(self, identity: PolisIdentity) -> None:
        """Canonical JSON has keys sorted lexicographically."""
        import json
        record, _ = AttributionRecord.create(b"test", identity)
        canonical = record.canonical_bytes()
        parsed = json.loads(canonical)
        keys = list(parsed.keys())
        assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# Signature Verification
# ---------------------------------------------------------------------------


class TestSignatureVerification:
    """Tests for Ed25519 signature verification of records."""

    def test_verify_valid_record(
        self, identity: PolisIdentity, resolver: DIDResolver
    ) -> None:
        """A correctly signed record passes verification."""
        record, _ = AttributionRecord.create(b"test", identity)
        assert record.verify(resolver) is True

    def test_verify_tampered_payload_hash(
        self, identity: PolisIdentity, resolver: DIDResolver
    ) -> None:
        """Tampered payload hash fails verification."""
        record, _ = AttributionRecord.create(b"test", identity)
        record.payload_hash = "0" * 64  # tamper with the hash
        assert record.verify(resolver) is False

    def test_verify_tampered_cid(
        self, identity: PolisIdentity, resolver: DIDResolver
    ) -> None:
        """Tampered CID fails verification."""
        record, _ = AttributionRecord.create(b"test", identity)
        record.cid = "01551220" + "0" * 64  # tamper with the CID
        assert record.verify(resolver) is False

    def test_verify_forged_signature(
        self, identity: PolisIdentity, resolver: DIDResolver
    ) -> None:
        """A completely forged signature fails verification."""
        record, _ = AttributionRecord.create(b"test", identity)
        record.signature = "00" * 64  # forge the signature
        assert record.verify(resolver) is False

    def test_verify_unknown_author(self, identity: PolisIdentity) -> None:
        """Verification raises ValueError for an unresolvable author DID."""
        record, _ = AttributionRecord.create(b"test", identity)
        empty_resolver = DIDResolver()
        with pytest.raises(ValueError, match="cannot resolve signing key"):
            record.verify(empty_resolver)

    def test_verify_cross_identity(self, identity: PolisIdentity) -> None:
        """Record signed by one identity fails verification against another."""
        record, _ = AttributionRecord.create(b"test", identity)
        other = PolisIdentity.create()
        resolver = DIDResolver()
        resolver.register(other)
        # Re-set author_did to the other identity to simulate cross-verification
        record.author_did = other.did
        assert record.verify(resolver) is False


# ---------------------------------------------------------------------------
# Encryption (Private Records)
# ---------------------------------------------------------------------------


class TestPrivateRecords:
    """Tests for private record encryption."""

    def test_private_record_has_encryption_metadata(
        self, identity: PolisIdentity
    ) -> None:
        """Private records include encryption metadata."""
        record, _ = AttributionRecord.create(
            b"secret", identity, visibility=VISIBILITY_PRIVATE
        )
        assert record.encryption_metadata is not None
        assert "nonce" in record.encryption_metadata
        assert "salt" in record.encryption_metadata

    def test_private_cid_differs_from_public(
        self, identity: PolisIdentity
    ) -> None:
        """Private record CID is computed over ciphertext, not plaintext."""
        payload = b"same payload"
        public_record, _ = AttributionRecord.create(payload, identity, visibility=VISIBILITY_PUBLIC)
        private_record, _ = AttributionRecord.create(payload, identity, visibility=VISIBILITY_PRIVATE)
        assert public_record.cid != private_record.cid

    def test_encrypt_decrypt_round_trip(self, identity: PolisIdentity) -> None:
        """Encrypted payload can be decrypted with the correct key."""
        payload = b"confidential data"
        ciphertext, nonce, salt = _encrypt_payload(payload, identity.signing_key_private)
        decrypted = _decrypt_payload(ciphertext, nonce, salt, identity.signing_key_private)
        assert decrypted == payload

    def test_decrypt_wrong_key_fails(self, identity: PolisIdentity) -> None:
        """Decryption with the wrong key raises InvalidTag."""
        payload = b"secret"
        ciphertext, nonce, salt = _encrypt_payload(payload, identity.signing_key_private)
        other = PolisIdentity.create()
        with pytest.raises(InvalidTag):
            _decrypt_payload(ciphertext, nonce, salt, other.signing_key_private)


# ---------------------------------------------------------------------------
# Permission Tokens (Selective Visibility)
# ---------------------------------------------------------------------------


class TestPermissionTokens:
    """Tests for selective-visibility permission tokens."""

    def test_grant_access_creates_token(self, identity: PolisIdentity) -> None:
        """Granting access to a selective record creates a permission token."""
        record, _ = AttributionRecord.create(
            b"selective data", identity, visibility=VISIBILITY_SELECTIVE
        )
        recipient = PolisIdentity.create()
        token = record.grant_access(
            recipient.did, identity, expiry_seconds=3600,
            recipient_public_key=recipient.signing_key_public,
        )
        assert token.recipient_did == recipient.did
        assert token.record_cid == record.cid
        assert token.is_valid() is True
        assert token.token_id in record.permission_tokens

    def test_grant_on_public_raises(self, identity: PolisIdentity) -> None:
        """Granting access on a public record raises ValueError."""
        record, _ = AttributionRecord.create(b"public", identity, visibility=VISIBILITY_PUBLIC)
        with pytest.raises(ValueError, match="Only 'selective'"):
            record.grant_access(
                "did:polis:someone", identity,
                recipient_public_key=identity.signing_key_public,
            )

    def test_revoke_access(self, identity: PolisIdentity) -> None:
        """Revoking a token marks it as revoked and removes from record."""
        record, _ = AttributionRecord.create(
            b"selective data", identity, visibility=VISIBILITY_SELECTIVE
        )
        recipient = PolisIdentity.create()
        token = record.grant_access(
            recipient.did, identity,
            recipient_public_key=recipient.signing_key_public,
        )

        record.revoke_access(token)
        assert token.revoked is True
        assert token.is_valid() is False
        assert token.token_id not in record.permission_tokens

    def test_revoke_wrong_record_raises(self, identity: PolisIdentity) -> None:
        """Revoking a token for the wrong record raises ValueError."""
        record_a, _ = AttributionRecord.create(
            b"data a", identity, visibility=VISIBILITY_SELECTIVE
        )
        record_b, _ = AttributionRecord.create(
            b"data b", identity, visibility=VISIBILITY_SELECTIVE
        )
        token = record_a.grant_access(
            "did:polis:someone", identity,
            recipient_public_key=identity.signing_key_public,
        )
        with pytest.raises(ValueError, match="does not belong"):
            record_b.revoke_access(token)

    def test_expired_token_is_invalid(self, identity: PolisIdentity) -> None:
        """An expired permission token reports as invalid."""
        record, _ = AttributionRecord.create(
            b"data", identity, visibility=VISIBILITY_SELECTIVE
        )
        # Create a token that expires immediately
        someone = PolisIdentity.create()
        token = record.grant_access(
            someone.did, identity, expiry_seconds=0,
            recipient_public_key=someone.signing_key_public,
        )
        # Token should be expired (or about to expire)
        import time
        time.sleep(0.1)
        assert token.is_valid() is False


# ---------------------------------------------------------------------------
# Serialization Round-Trip
# ---------------------------------------------------------------------------


class TestRecordSerialization:
    """Tests for record dict serialization."""

    def test_to_dict_round_trip(self, identity: PolisIdentity) -> None:
        """A record can be serialized and deserialized."""
        record, _ = AttributionRecord.create(b"round trip", identity)
        data = record.to_dict()
        restored = AttributionRecord.from_dict(data)
        assert restored.cid == record.cid
        assert restored.author_did == record.author_did
        assert restored.signature == record.signature
        assert restored.visibility == record.visibility

    def test_to_dict_private_includes_metadata(
        self, identity: PolisIdentity
    ) -> None:
        """Private record dict includes encryption metadata."""
        record, _ = AttributionRecord.create(
            b"private", identity, visibility=VISIBILITY_PRIVATE
        )
        data = record.to_dict()
        assert "encryption_metadata" in data


# ---------------------------------------------------------------------------
# Content Addressing
# ---------------------------------------------------------------------------


class TestContentAddressing:
    """Tests for CID computation."""

    def test_cid_deterministic(self) -> None:
        """Same data always produces the same CID."""
        data = b"deterministic content"
        assert _compute_cid(data) == _compute_cid(data)

    def test_cid_different_for_different_data(self) -> None:
        """Different data produces different CIDs."""
        assert _compute_cid(b"data a") != _compute_cid(b"data b")

    def test_cid_has_multihash_prefix(self) -> None:
        """CID starts with CIDv1 multihash prefix 01551220."""
        cid = _compute_cid(b"test")
        assert cid.startswith("01551220")

    def test_payload_hash_matches_sha256(self) -> None:
        """Payload hash is standard SHA-256 hex digest."""
        data = b"test data"
        expected = hashlib.sha256(data).hexdigest()
        assert _compute_payload_hash(data) == expected
