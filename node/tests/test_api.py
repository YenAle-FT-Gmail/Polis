# polis/node/tests/test_api.py
"""
Tests for the Polis Node API.

Uses FastAPI's TestClient for synchronous testing of all API endpoints.
Covers identity creation, resolution, key rotation, record creation,
record retrieval, and node status.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from polis_node.api.app import create_app
from polis_node.config.settings import PolisNodeSettings


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def settings(tmp_path: str) -> PolisNodeSettings:
    """Create test settings with a temporary data directory."""
    return PolisNodeSettings(
        node_id="test-node",
        host="127.0.0.1",
        port=8000,
        storage_backend="local",
        data_dir=str(tmp_path),
        peers=[],
        log_level="DEBUG",
    )


@pytest.fixture
def app(settings: PolisNodeSettings) -> FastAPI:
    """Create a test FastAPI app."""
    return create_app(settings)


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create a test client."""
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Identity Endpoints
# ---------------------------------------------------------------------------


class TestIdentityAPI:
    """Tests for identity API endpoints."""

    def test_create_identity(self, client: TestClient) -> None:
        """POST /identity/create returns a valid DID and recovery mnemonic."""
        response = client.post("/identity/create", json={})
        assert response.status_code == 200
        data = response.json()
        assert data["did"].startswith("did:polis:")
        assert len(data["recovery_mnemonic"].split()) == 24
        assert data["did_document"]["id"] == data["did"]

    def test_create_identity_with_storage_endpoint(self, client: TestClient) -> None:
        """POST /identity/create with storage_endpoint includes it in the document."""
        response = client.post(
            "/identity/create",
            json={"storage_endpoint": "https://storage.example.com"},
        )
        assert response.status_code == 200
        doc = response.json()["did_document"]
        assert any(
            s["serviceEndpoint"] == "https://storage.example.com"
            for s in doc.get("service", [])
        )

    def test_resolve_identity(self, client: TestClient) -> None:
        """GET /identity/{did} returns the DID Document."""
        # First create an identity
        create_resp = client.post("/identity/create", json={})
        did = create_resp.json()["did"]

        # Then resolve it
        response = client.get(f"/identity/{did}")
        assert response.status_code == 200
        assert response.json()["id"] == did

    def test_resolve_unknown_identity(self, client: TestClient) -> None:
        """GET /identity/{did} returns 404 for unknown DIDs."""
        response = client.get("/identity/did:polis:nonexistent")
        assert response.status_code == 404

    def test_rotate_key(self, client: TestClient) -> None:
        """POST /identity/{did}/rotate-key rotates the signing key."""
        create_resp = client.post("/identity/create", json={})
        did = create_resp.json()["did"]
        original_doc = create_resp.json()["did_document"]

        response = client.post(f"/identity/{did}/rotate-key", json={})
        assert response.status_code == 200
        data = response.json()
        assert data["did"] == did
        # The signing key should be different
        new_doc = data["did_document"]
        original_key = original_doc["verificationMethod"][0]["publicKeyBase58"]
        new_key = new_doc["verificationMethod"][0]["publicKeyBase58"]
        assert original_key != new_key

    def test_rotate_key_unknown_identity(self, client: TestClient) -> None:
        """POST /identity/{did}/rotate-key returns 404 for unknown DIDs."""
        response = client.post("/identity/did:polis:nonexistent/rotate-key", json={})
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Record Endpoints
# ---------------------------------------------------------------------------


class TestRecordAPI:
    """Tests for attribution record API endpoints."""

    def _create_identity(self, client: TestClient) -> str:
        """Helper to create an identity and return the DID."""
        resp = client.post("/identity/create", json={})
        return resp.json()["did"]

    def test_create_record(self, client: TestClient) -> None:
        """POST /records/create creates a signed attribution record."""
        did = self._create_identity(client)
        payload = base64.b64encode(b"Hello, Polis!").decode()

        response = client.post(
            "/records/create",
            json={
                "payload": payload,
                "author_did": did,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["cid"].startswith("01551220")
        assert data["record"]["author_did"] == did
        assert data["record"]["signature"] != ""

    def test_create_private_record(self, client: TestClient) -> None:
        """POST /records/create with private visibility includes encryption metadata."""
        did = self._create_identity(client)
        payload = base64.b64encode(b"secret data").decode()

        response = client.post(
            "/records/create",
            json={
                "payload": payload,
                "author_did": did,
                "visibility": "private",
            },
        )
        assert response.status_code == 200
        record = response.json()["record"]
        assert record["visibility"] == "private"
        assert "encryption_metadata" in record

    def test_create_record_unknown_author(self, client: TestClient) -> None:
        """POST /records/create returns 404 for unknown author DID."""
        payload = base64.b64encode(b"test").decode()
        response = client.post(
            "/records/create",
            json={
                "payload": payload,
                "author_did": "did:polis:nonexistent",
            },
        )
        assert response.status_code == 404

    def test_create_record_invalid_payload(self, client: TestClient) -> None:
        """POST /records/create returns 400 for invalid base64 payload."""
        did = self._create_identity(client)
        response = client.post(
            "/records/create",
            json={
                "payload": "not-valid-base64!!!",
                "author_did": did,
            },
        )
        assert response.status_code == 400

    def test_get_record(self, client: TestClient) -> None:
        """GET /records/{cid} returns the record."""
        did = self._create_identity(client)
        payload = base64.b64encode(b"test content").decode()
        create_resp = client.post(
            "/records/create",
            json={"payload": payload, "author_did": did},
        )
        cid = create_resp.json()["cid"]

        response = client.get(f"/records/{cid}")
        assert response.status_code == 200
        assert response.json()["cid"] == cid

    def test_get_record_not_found(self, client: TestClient) -> None:
        """GET /records/{cid} returns 404 for unknown CID."""
        response = client.get("/records/01551220" + "0" * 64)
        assert response.status_code == 404

    def test_get_records_by_author(self, client: TestClient) -> None:
        """GET /records/by-author/{did} returns all records by the author."""
        did = self._create_identity(client)

        for i in range(3):
            payload = base64.b64encode(f"content {i}".encode()).decode()
            client.post(
                "/records/create",
                json={"payload": payload, "author_did": did},
            )

        response = client.get(f"/records/by-author/{did}")
        assert response.status_code == 200
        records = response.json()
        assert len(records) == 3
        assert all(r["author_did"] == did for r in records)

    def test_get_records_by_unknown_author(self, client: TestClient) -> None:
        """GET /records/by-author/{did} returns empty list for unknown author."""
        response = client.get("/records/by-author/did:polis:unknown")
        assert response.status_code == 200
        assert response.json() == []


# ---------------------------------------------------------------------------
# Node Endpoints
# ---------------------------------------------------------------------------


class TestNodeAPI:
    """Tests for node management API endpoints."""

    def test_node_status(self, client: TestClient) -> None:
        """GET /node/status returns healthy status."""
        response = client.get("/node/status")
        assert response.status_code == 200
        data = response.json()
        assert data["node_id"] == "test-node"
        assert data["status"] == "healthy"
        assert data["storage_backend"] == "local"

    def test_node_peers_empty(self, client: TestClient) -> None:
        """GET /node/peers returns empty list when no peers configured."""
        response = client.get("/node/peers")
        assert response.status_code == 200
        assert response.json() == []

    def test_connect_peer_unreachable(self, client: TestClient) -> None:
        """POST /node/peers/connect adds an unreachable peer."""
        response = client.post(
            "/node/peers/connect",
            json={"address": "localhost:9999"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "added_unreachable"

    def test_status_reflects_identities_and_records(
        self, client: TestClient
    ) -> None:
        """Node status counts reflect created identities and records."""
        # Create an identity
        create_resp = client.post("/identity/create", json={})
        did = create_resp.json()["did"]

        # Create a record
        payload = base64.b64encode(b"test").decode()
        client.post(
            "/records/create",
            json={"payload": payload, "author_did": did},
        )

        status = client.get("/node/status").json()
        assert status["identity_count"] == 1
        assert status["record_count"] == 1
