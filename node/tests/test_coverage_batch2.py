# polis/node/tests/test_coverage_batch2.py
"""
Batch 2 coverage tests: records.py uncovered lines.

Covers:
- grant_access: author not on node, recipient not found, ValueError
- revoke_access: full endpoint (revoke + token_not_found)
- ingest: unresolvable author, invalid base64 data
- /access endpoint: full flow (token present → decrypt → return)
- create_record: signature verification failure (mocked)
"""

from __future__ import annotations

import base64
import json
from unittest.mock import patch, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from polis_node.api.app import create_app
from polis_node.api.state import NodeState
from polis_node.attribution.record import (
    VISIBILITY_SELECTIVE,
    AttributionRecord,
    _unwrap_key_for_recipient,
)
from polis_node.config.settings import PolisNodeSettings
from polis_node.identity.did import PolisIdentity
from polis_node.storage.interface import StorageBackend


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def setup(tmp_path):
    """Create app + client + state with a registered identity."""
    settings = PolisNodeSettings(
        node_id="dev-test",
        data_dir=str(tmp_path),
        peers=[],
    )
    app = create_app(settings)
    state = NodeState(settings)
    app.state.node_state = state

    author = PolisIdentity.create()
    state.register_identity(author)

    client = TestClient(app)
    return client, state, author


# ---------------------------------------------------------------------------
# grant_access — author not on node (line 340, 351)
# ---------------------------------------------------------------------------


class TestGrantAccessErrors:
    """Cover grant_access error paths in records.py."""

    def test_grant_record_not_found(self, setup) -> None:
        client, state, author = setup
        resp = client.post(
            "/records/fakecid/grant",
            json={"recipient_did": "did:polis:someone", "expiry_seconds": 60},
        )
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "record_not_found"

    def test_grant_author_not_on_node(self, setup) -> None:
        """Author identity not available on this node (line 351)."""
        client, state, author = setup

        # Create a record then remove the author from state
        payload = base64.b64encode(b"test").decode()
        create_resp = client.post(
            "/records/create",
            json={"payload": payload, "author_did": author.did, "visibility": "selective"},
        )
        cid = create_resp.json()["cid"]

        # Remove author from identities (but leave in resolver so record is resolvable)
        del state.identities[author.did]

        resp = client.post(
            f"/records/{cid}/grant",
            json={"recipient_did": "did:polis:someone", "expiry_seconds": 60},
        )
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "author_not_found"

    def test_grant_recipient_not_found(self, setup) -> None:
        """Recipient DID not resolvable (line 363)."""
        client, state, author = setup

        payload = base64.b64encode(b"test").decode()
        create_resp = client.post(
            "/records/create",
            json={"payload": payload, "author_did": author.did, "visibility": "selective"},
        )
        cid = create_resp.json()["cid"]

        # Recipient DID is not registered
        resp = client.post(
            f"/records/{cid}/grant",
            json={"recipient_did": "did:polis:unknown_recipient", "expiry_seconds": 60},
        )
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "recipient_not_found"

    def test_grant_value_error(self, setup) -> None:
        """Grant on a non-selective record triggers ValueError (line 380-381)."""
        client, state, author = setup

        # Create a PUBLIC record
        payload = base64.b64encode(b"test").decode()
        create_resp = client.post(
            "/records/create",
            json={"payload": payload, "author_did": author.did, "visibility": "public"},
        )
        cid = create_resp.json()["cid"]

        recipient = PolisIdentity.create()
        state.register_identity(recipient)

        resp = client.post(
            f"/records/{cid}/grant",
            json={"recipient_did": recipient.did, "expiry_seconds": 60},
        )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "grant_failed"


# ---------------------------------------------------------------------------
# revoke_access — full endpoint (lines 429-446)
# ---------------------------------------------------------------------------


class TestRevokeAccess:
    """Cover the revoke_access endpoint."""

    def test_revoke_record_not_found(self, setup) -> None:
        client, state, author = setup
        resp = client.post(
            "/records/fakecid/revoke",
            json={"token_id": "tok123"},
        )
        assert resp.status_code == 404

    def test_revoke_token_not_found(self, setup) -> None:
        client, state, author = setup

        payload = base64.b64encode(b"test").decode()
        create_resp = client.post(
            "/records/create",
            json={"payload": payload, "author_did": author.did},
        )
        cid = create_resp.json()["cid"]

        resp = client.post(
            f"/records/{cid}/revoke",
            json={"token_id": "nonexistent_token"},
        )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "token_not_found"

    def test_revoke_success(self, setup) -> None:
        client, state, author = setup

        # Create a selective record and grant access
        payload = base64.b64encode(b"secret").decode()
        create_resp = client.post(
            "/records/create",
            json={"payload": payload, "author_did": author.did, "visibility": "selective"},
        )
        cid = create_resp.json()["cid"]

        recipient = PolisIdentity.create()
        state.register_identity(recipient)

        grant_resp = client.post(
            f"/records/{cid}/grant",
            json={"recipient_did": recipient.did, "expiry_seconds": 3600},
        )
        assert grant_resp.status_code == 200
        token_id = grant_resp.json()["token_id"]

        # Revoke it
        revoke_resp = client.post(
            f"/records/{cid}/revoke",
            json={"token_id": token_id},
        )
        assert revoke_resp.status_code == 200
        assert revoke_resp.json()["status"] == "revoked"


# ---------------------------------------------------------------------------
# ingest — error paths (lines 487-488, 499-500, 523-524)
# ---------------------------------------------------------------------------


class TestIngestErrors:
    """Cover ingest endpoint error paths."""

    def test_ingest_unresolvable_author(self, setup) -> None:
        """Author DID not resolvable raises 400 (lines 487-488)."""
        client, state, author = setup

        # Create a valid record, then craft an ingest request with an
        # unresolvable DID
        record, data = AttributionRecord.create(b"hello", author)
        record_dict = record.to_dict()
        # Change the author DID to something unresolvable but keep the signature
        record_dict["author_did"] = "did:polis:nonexistent_author"

        resp = client.post(
            "/records/ingest",
            json={
                "record": record_dict,
                "data": base64.b64encode(data).decode(),
            },
        )
        # Should fail because the author can't be resolved for signature verification
        assert resp.status_code == 400

    def test_ingest_invalid_base64_data(self, setup) -> None:
        """Invalid base64 in data field (lines 523-524)."""
        client, state, author = setup

        record, data = AttributionRecord.create(b"hello", author)

        resp = client.post(
            "/records/ingest",
            json={
                "record": record.to_dict(),
                "data": "not-valid-base64!!!@#$",
            },
        )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_data"


# ---------------------------------------------------------------------------
# /access endpoint — full flow (lines 595-650)
# ---------------------------------------------------------------------------


class TestAccessEndpoint:
    """Cover the /{cid}/access endpoint end-to-end."""

    def test_access_record_not_found(self, setup) -> None:
        client, state, author = setup
        resp = client.post(
            "/records/fakecid/access",
            json={
                "token_id": "t",
                "recipient_did": "did:polis:x",
            },
        )
        assert resp.status_code == 404

    def test_access_invalid_token(self, setup) -> None:
        client, state, author = setup

        payload = base64.b64encode(b"test").decode()
        create_resp = client.post(
            "/records/create",
            json={"payload": payload, "author_did": author.did, "visibility": "selective"},
        )
        cid = create_resp.json()["cid"]

        resp = client.post(
            f"/records/{cid}/access",
            json={
                "token_id": "bad_token",
                "recipient_did": "did:polis:x",
            },
        )
        assert resp.status_code == 403

    def test_access_full_decrypt_flow(self, setup) -> None:
        """Full flow: create selective record → grant → access → get encrypted envelope."""
        client, state, author = setup
        recipient = PolisIdentity.create()
        state.register_identity(recipient)

        original_payload = b"secret content for recipient"
        payload_b64 = base64.b64encode(original_payload).decode()

        # 1. Create selective record
        create_resp = client.post(
            "/records/create",
            json={
                "payload": payload_b64,
                "author_did": author.did,
                "visibility": "selective",
            },
        )
        assert create_resp.status_code == 200
        cid = create_resp.json()["cid"]

        # 2. Grant access to recipient
        grant_resp = client.post(
            f"/records/{cid}/grant",
            json={
                "recipient_did": recipient.did,
                "expiry_seconds": 3600,
            },
        )
        assert grant_resp.status_code == 200
        grant_data = grant_resp.json()

        # 3. Access with the token — server returns encrypted envelope
        access_resp = client.post(
            f"/records/{cid}/access",
            json={
                "token_id": grant_data["token_id"],
                "recipient_did": recipient.did,
            },
        )
        assert access_resp.status_code == 200
        envelope = access_resp.json()
        assert "ciphertext" in envelope
        assert "wrapped_key" in envelope
        assert "wrap_nonce" in envelope
        assert "record_nonce" in envelope
        assert "record_salt" in envelope
        assert "grantor_public_key_hex" in envelope
        # Verify ciphertext is non-empty base64
        ct_bytes = base64.b64decode(envelope["ciphertext"])
        assert len(ct_bytes) > 0

        # 4. Client-side decryption to verify the full chain
        from polis_node.attribution.record import _unwrap_key_for_recipient
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aes_key = _unwrap_key_for_recipient(
            wrapped_key=bytes.fromhex(envelope["wrapped_key"]),
            wrap_nonce=bytes.fromhex(envelope["wrap_nonce"]),
            recipient_private=recipient.signing_key_private,
            grantor_public=bytes.fromhex(envelope["grantor_public_key_hex"]),
        )
        nonce = bytes.fromhex(envelope["record_nonce"])
        plaintext = AESGCM(aes_key).decrypt(nonce, ct_bytes, None)
        assert plaintext == original_payload

    def test_access_key_unwrap_failure(self, setup) -> None:
        """Token not stored in state → token metadata not found."""
        client, state, author = setup
        recipient = PolisIdentity.create()
        state.register_identity(recipient)

        payload_b64 = base64.b64encode(b"secret").decode()

        create_resp = client.post(
            "/records/create",
            json={
                "payload": payload_b64,
                "author_did": author.did,
                "visibility": "selective",
            },
        )
        cid = create_resp.json()["cid"]

        grant_resp = client.post(
            f"/records/{cid}/grant",
            json={"recipient_did": recipient.did, "expiry_seconds": 3600},
        )
        token_id = grant_resp.json()["token_id"]

        # Remove the token object from state to simulate missing metadata
        state.permission_token_objects.pop(token_id, None)

        access_resp = client.post(
            f"/records/{cid}/access",
            json={
                "token_id": token_id,
                "recipient_did": recipient.did,
            },
        )
        assert access_resp.status_code == 403
        assert access_resp.json()["detail"]["error"] == "invalid_token"

    def test_access_decryption_failure(self, setup) -> None:
        """Tampered ciphertext → client would fail, but server returns envelope intact."""
        client, state, author = setup
        recipient = PolisIdentity.create()
        state.register_identity(recipient)

        payload_b64 = base64.b64encode(b"secret").decode()

        create_resp = client.post(
            "/records/create",
            json={
                "payload": payload_b64,
                "author_did": author.did,
                "visibility": "selective",
            },
        )
        cid = create_resp.json()["cid"]

        grant_resp = client.post(
            f"/records/{cid}/grant",
            json={"recipient_did": recipient.did, "expiry_seconds": 3600},
        )
        grant_data = grant_resp.json()

        # Tamper with the ciphertext stored in state
        state.record_data[cid] = b"tampered ciphertext data"

        access_resp = client.post(
            f"/records/{cid}/access",
            json={
                "token_id": grant_data["token_id"],
                "recipient_did": recipient.did,
            },
        )
        # Server now returns 200 with the tampered data; decryption failure is client-side
        assert access_resp.status_code == 200
        envelope = access_resp.json()
        # The ciphertext is the tampered data
        ct = base64.b64decode(envelope["ciphertext"])
        assert ct == b"tampered ciphertext data"


# ---------------------------------------------------------------------------
# create_record — signature verification failure (lines 217-218, 228)
# ---------------------------------------------------------------------------


class TestCreateRecordVerifyFailure:
    """Cover the unlikely signature-verification-failed branch."""

    def test_create_record_verify_fails(self, setup) -> None:
        """Mock record.verify to return False → 500."""
        client, state, author = setup
        payload = base64.b64encode(b"test").decode()

        with patch(
            "polis_node.api.routes.records.AttributionRecord.create"
        ) as mock_create:
            mock_record = MagicMock()
            mock_record.verify.return_value = False
            mock_create.return_value = (mock_record, b"data")

            resp = client.post(
                "/records/create",
                json={"payload": payload, "author_did": author.did},
            )

        assert resp.status_code == 500
        assert resp.json()["detail"]["error"] == "signature_verification_failed"


# ---------------------------------------------------------------------------
# create_record — invalid visibility (ValueError branch lines 217-218)
# ---------------------------------------------------------------------------


class TestCreateRecordInvalidParams:
    """Cover ValueError from AttributionRecord.create (line 217-218)."""

    def test_invalid_visibility_returns_400(self, setup) -> None:
        client, state, author = setup
        payload = base64.b64encode(b"test").decode()
        resp = client.post(
            "/records/create",
            json={
                "payload": payload,
                "author_did": author.did,
                "visibility": "INVALID_VIS",
            },
        )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_parameters"


# ---------------------------------------------------------------------------
# ingest — ValueError from record.verify (lines 487-488)
# ---------------------------------------------------------------------------


class TestIngestVerifyValueError:
    """Cover the except ValueError branch in ingest_record."""

    def test_ingest_verify_raises_value_error(self, setup) -> None:
        """record.verify raises ValueError → 400 unresolvable_author."""
        client, state, author = setup

        record, data = AttributionRecord.create(b"hello", author)
        record_dict = record.to_dict()

        # Patch verify on the AttributionRecord class so the real from_dict
        # runs, but verify raises ValueError when called.
        with patch.object(
            AttributionRecord, "verify", side_effect=ValueError("Cannot resolve DID")
        ):
            resp = client.post(
                "/records/ingest",
                json={
                    "record": record_dict,
                    "data": base64.b64encode(data).decode(),
                },
            )

        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "unresolvable_author"

    def test_ingest_malformed_record_dict(self, setup) -> None:
        """Malformed record dict causes from_dict to raise → 400 invalid_record (lines 487-488)."""
        client, state, author = setup

        # Missing required fields → from_dict raises KeyError
        resp = client.post(
            "/records/ingest",
            json={
                "record": {"polis_version": "0.1", "bogus": True},
                "data": base64.b64encode(b"data").decode(),
            },
        )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_record"


# ---------------------------------------------------------------------------
# /access — data_not_found (line 631)
# ---------------------------------------------------------------------------


class TestAccessDataNotFound:
    """Cover line 631: record_data missing for a known record."""

    def test_access_data_not_found(self, setup) -> None:
        """Record exists in state.records but not in state.record_data → 404."""
        client, state, author = setup
        recipient = PolisIdentity.create()
        state.register_identity(recipient)

        payload_b64 = base64.b64encode(b"secret").decode()
        create_resp = client.post(
            "/records/create",
            json={
                "payload": payload_b64,
                "author_did": author.did,
                "visibility": "selective",
            },
        )
        cid = create_resp.json()["cid"]

        grant_resp = client.post(
            f"/records/{cid}/grant",
            json={"recipient_did": recipient.did, "expiry_seconds": 3600},
        )
        grant_data = grant_resp.json()

        # Remove the record data to trigger data_not_found
        del state.record_data[cid]

        access_resp = client.post(
            f"/records/{cid}/access",
            json={
                "token_id": grant_data["token_id"],
                "recipient_did": recipient.did,
                "wrapped_key": base64.b64decode(grant_data["wrapped_key"]).hex(),
                "wrap_nonce": base64.b64decode(grant_data["wrap_nonce"]).hex(),
                "record_nonce": grant_data["record_nonce"],
                "record_salt": grant_data["record_salt"],
                "recipient_private_key_hex": recipient.signing_key_private.hex(),
                "grantor_public_key_hex": author.signing_key_public.hex(),
            },
        )
        assert access_resp.status_code == 404
        assert access_resp.json()["detail"]["error"] == "data_not_found"
