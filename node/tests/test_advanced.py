# polis/node/tests/test_advanced.py
"""
Advanced tests for Polis Phase 1 audit fixes.

Covers:
- Key wrapping / unwrapping (C3)
- Record ingest with signature verification (C4)
- Structlog sensitive field filtering (I10)
- SecureBytes memory protection (C7)
- Adversarial: replayed permission tokens (M10)
- CID verification on ingest
"""

import base64
import time
from datetime import datetime, timezone

import pytest

from polis_node.attribution.record import (
    VISIBILITY_SELECTIVE,
    AttributionRecord,
    _unwrap_key_for_recipient,
    _wrap_key_for_recipient,
    _derive_encryption_key,
    _encrypt_payload,
    _decrypt_payload,
    HKDF_INFO_PRIVATE,
)
from polis_node.identity.did import DIDResolver, PolisIdentity
from polis_node.identity.secure_bytes import SecureBytes
from polis_node.config.logging import filter_sensitive_fields


# ---------------------------------------------------------------------------
# Key Wrapping (C3)
# ---------------------------------------------------------------------------


class TestKeyWrapping:
    """Tests for ECDH-based AES key wrapping."""

    def test_wrap_unwrap_round_trip(self) -> None:
        """Wrapped key can be unwrapped by the intended recipient."""
        author = PolisIdentity.create()
        recipient = PolisIdentity.create()
        aes_key = b"\xab" * 32  # dummy AES key

        wrapped, nonce = _wrap_key_for_recipient(
            aes_key, author.signing_key_private, recipient.signing_key_public
        )
        unwrapped = _unwrap_key_for_recipient(
            wrapped, nonce, recipient.signing_key_private, author.signing_key_public
        )
        assert unwrapped == aes_key

    def test_wrong_recipient_cannot_unwrap(self) -> None:
        """A different recipient cannot unwrap the key."""
        author = PolisIdentity.create()
        recipient = PolisIdentity.create()
        wrong_recipient = PolisIdentity.create()
        aes_key = b"\xcd" * 32

        wrapped, nonce = _wrap_key_for_recipient(
            aes_key, author.signing_key_private, recipient.signing_key_public
        )
        with pytest.raises(Exception):  # InvalidTag or similar
            _unwrap_key_for_recipient(
                wrapped, nonce,
                wrong_recipient.signing_key_private,
                author.signing_key_public,
            )

    def test_selective_record_end_to_end(self) -> None:
        """Full flow: create selective record, grant access, unwrap key, decrypt."""
        author = PolisIdentity.create()
        recipient = PolisIdentity.create()
        payload = b"selective secret content"

        record, storable_data = AttributionRecord.create(
            payload, author, visibility=VISIBILITY_SELECTIVE
        )

        token = record.grant_access(
            recipient.did, author,
            recipient_public_key=recipient.signing_key_public,
        )

        # Recipient unwraps the key
        aes_key = _unwrap_key_for_recipient(
            token.wrapped_key,
            token.wrap_nonce,
            recipient.signing_key_private,
            author.signing_key_public,
        )

        # Recipient decrypts the ciphertext
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(token.record_nonce, storable_data, None)
        assert plaintext == payload


# ---------------------------------------------------------------------------
# SecureBytes (C7)
# ---------------------------------------------------------------------------


class TestSecureBytes:
    """Tests for SecureBytes memory protection."""

    def test_value_round_trip(self) -> None:
        """SecureBytes stores and returns the original data."""
        data = b"secret key material"
        sb = SecureBytes(data)
        assert sb.value == data

    def test_clear_zeros_memory(self) -> None:
        """After clear(), accessing value raises ValueError."""
        sb = SecureBytes(b"key")
        sb.clear()
        with pytest.raises(ValueError, match="cleared"):
            _ = sb.value

    def test_double_clear_is_safe(self) -> None:
        """Calling clear() twice does not raise."""
        sb = SecureBytes(b"key")
        sb.clear()
        sb.clear()  # should not raise

    def test_len(self) -> None:
        """__len__ returns the buffer size."""
        sb = SecureBytes(b"1234")
        assert len(sb) == 4

    def test_bool(self) -> None:
        """__bool__ is True when data exists, False after clear."""
        sb = SecureBytes(b"data")
        assert bool(sb) is True
        sb.clear()
        assert bool(sb) is False

    def test_repr_no_leak(self) -> None:
        """__repr__ does not expose the actual key material."""
        sb = SecureBytes(b"topsecret")
        r = repr(sb)
        assert "topsecret" not in r
        assert "9 bytes" in r


# ---------------------------------------------------------------------------
# Structlog Sensitive Field Filter (I10)
# ---------------------------------------------------------------------------


class TestSensitiveFieldFilter:
    """Tests for structlog sensitive field filtering."""

    def test_redacts_private_key(self) -> None:
        """Private key fields are replaced with [REDACTED]."""
        event = {"event": "test", "signing_key_private": b"\x00" * 32}
        result = filter_sensitive_fields(None, "info", event)
        assert result["signing_key_private"] == "[REDACTED]"

    def test_redacts_recovery_mnemonic(self) -> None:
        """Recovery mnemonic is redacted."""
        event = {"event": "test", "recovery_mnemonic": "word1 word2 word3"}
        result = filter_sensitive_fields(None, "info", event)
        assert result["recovery_mnemonic"] == "[REDACTED]"

    def test_preserves_safe_fields(self) -> None:
        """Non-sensitive fields are preserved."""
        event = {"event": "identity.created", "did": "did:polis:abc"}
        result = filter_sensitive_fields(None, "info", event)
        assert result["did"] == "did:polis:abc"
        assert result["event"] == "identity.created"

    def test_redacts_wrapped_key(self) -> None:
        """wrapped_key field is redacted."""
        event = {"event": "test", "wrapped_key": b"some bytes"}
        result = filter_sensitive_fields(None, "info", event)
        assert result["wrapped_key"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# Adversarial: Replayed Permission Tokens (M10)
# ---------------------------------------------------------------------------


class TestAdversarialTokens:
    """Adversarial tests for permission token security."""

    def test_revoked_token_rejected(self) -> None:
        """A revoked token is not valid."""
        author = PolisIdentity.create()
        recipient = PolisIdentity.create()
        record, _ = AttributionRecord.create(
            b"data", author, visibility=VISIBILITY_SELECTIVE
        )
        token = record.grant_access(
            recipient.did, author,
            recipient_public_key=recipient.signing_key_public,
        )
        record.revoke_access(token)
        assert token.is_valid() is False
        assert token.token_id not in record.permission_tokens

    def test_expired_token_rejected(self) -> None:
        """An expired token reports as invalid."""
        author = PolisIdentity.create()
        someone = PolisIdentity.create()
        record, _ = AttributionRecord.create(
            b"data", author, visibility=VISIBILITY_SELECTIVE
        )
        token = record.grant_access(
            someone.did, author, expiry_seconds=0,
            recipient_public_key=someone.signing_key_public,
        )
        time.sleep(0.1)
        assert token.is_valid() is False

    def test_token_for_wrong_record_rejected(self) -> None:
        """A token cannot be used with a different record."""
        author = PolisIdentity.create()
        someone = PolisIdentity.create()
        record_a, _ = AttributionRecord.create(
            b"data a", author, visibility=VISIBILITY_SELECTIVE
        )
        record_b, _ = AttributionRecord.create(
            b"data b", author, visibility=VISIBILITY_SELECTIVE
        )
        token = record_a.grant_access(
            someone.did, author,
            recipient_public_key=someone.signing_key_public,
        )
        assert token.record_cid == record_a.cid
        assert token.record_cid != record_b.cid
        # Token ID is not in record_b's list
        assert token.token_id not in record_b.permission_tokens


# ---------------------------------------------------------------------------
# Record Ingest API (C4) — via TestClient
# ---------------------------------------------------------------------------


class TestRecordIngestAPI:
    """Tests for the /records/ingest endpoint."""

    @pytest.fixture
    def client_and_state(self):
        """Create a test client with a registered identity."""
        from fastapi.testclient import TestClient
        from polis_node.api.app import create_app
        from polis_node.config.settings import PolisNodeSettings

        app = create_app()
        settings = PolisNodeSettings(node_id="test-node", data_dir="/tmp/polis/test-ingest")
        from polis_node.api.state import NodeState
        state = NodeState(settings)
        app.state.node_state = state

        identity = PolisIdentity.create()
        state.register_identity(identity)

        return TestClient(app), state, identity

    def test_ingest_valid_record(self, client_and_state) -> None:
        """A validly signed record is accepted by /ingest."""
        client, state, identity = client_and_state
        record, storable_data = AttributionRecord.create(
            b"ingest me", identity
        )

        payload = {
            "record": record.to_dict(),
            "data": base64.b64encode(storable_data).decode(),
        }
        response = client.post("/records/ingest", json=payload)
        assert response.status_code == 200
        assert response.json()["status"] == "ingested"

    def test_ingest_tampered_record_rejected(self, client_and_state) -> None:
        """A record with a tampered field is rejected."""
        client, state, identity = client_and_state
        record, storable_data = AttributionRecord.create(
            b"tamper test", identity
        )
        record_dict = record.to_dict()
        record_dict["payload_hash"] = "0" * 64  # tamper

        payload = {
            "record": record_dict,
            "data": base64.b64encode(storable_data).decode(),
        }
        response = client.post("/records/ingest", json=payload)
        assert response.status_code == 400
        assert "invalid_signature" in response.json()["detail"]["error"]

    def test_ingest_cid_mismatch_rejected(self, client_and_state) -> None:
        """A record whose CID doesn't match the data is rejected."""
        client, state, identity = client_and_state
        record, storable_data = AttributionRecord.create(
            b"cid test", identity
        )

        payload = {
            "record": record.to_dict(),
            "data": base64.b64encode(b"wrong data").decode(),
        }
        response = client.post("/records/ingest", json=payload)
        assert response.status_code == 400
        assert "cid_mismatch" in response.json()["detail"]["error"]

    def test_ingest_duplicate_accepted(self, client_and_state) -> None:
        """Ingesting the same record twice returns already_exists."""
        client, state, identity = client_and_state
        record, storable_data = AttributionRecord.create(
            b"duplicate", identity
        )

        payload = {
            "record": record.to_dict(),
            "data": base64.b64encode(storable_data).decode(),
        }
        client.post("/records/ingest", json=payload)
        response = client.post("/records/ingest", json=payload)
        assert response.status_code == 200
        assert response.json()["status"] == "already_exists"
