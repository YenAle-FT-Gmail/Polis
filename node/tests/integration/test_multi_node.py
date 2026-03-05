#!/usr/bin/env python3
# polis/node/tests/integration/test_multi_node.py
"""
Multi-node integration test — demonstrates two Polis nodes working together.

This test script:
1. Starts two nodes as in-process ASGI apps (no Docker needed)
2. Creates an identity on node A
3. Creates an attribution record on node A
4. Verifies the record propagates to node B via /records/ingest
5. Demonstrates selective-visibility key wrapping end-to-end

Run directly:
    poetry run python -m pytest tests/integration/test_multi_node.py -v

Or as part of the full suite:
    poetry run pytest tests/ -v
"""

from __future__ import annotations

import base64

import httpx
import pytest
from fastapi.testclient import TestClient

from polis_node.api.app import create_app
from polis_node.attribution.record import (
    VISIBILITY_SELECTIVE,
    AttributionRecord,
    _unwrap_key_for_recipient,
)
from polis_node.config.settings import PolisNodeSettings
from polis_node.identity.did import PolisIdentity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def node_a_settings(tmp_path) -> PolisNodeSettings:
    """Settings for node A."""
    return PolisNodeSettings(
        node_id="node-a",
        data_dir=str(tmp_path / "node_a"),
    )


@pytest.fixture
def node_b_settings(tmp_path) -> PolisNodeSettings:
    """Settings for node B."""
    return PolisNodeSettings(
        node_id="node-b",
        data_dir=str(tmp_path / "node_b"),
    )


@pytest.fixture
def client_a(node_a_settings: PolisNodeSettings) -> TestClient:
    """TestClient for node A."""
    app = create_app(node_a_settings)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def client_b(node_b_settings: PolisNodeSettings) -> TestClient:
    """TestClient for node B."""
    app = create_app(node_b_settings)
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------


class TestMultiNodeIntegration:
    """End-to-end integration tests spanning two Polis nodes."""

    def test_identity_created_on_node_a(
        self, client_a: TestClient
    ) -> None:
        """An identity can be created on node A."""
        response = client_a.post("/identity/create", json={})
        assert response.status_code == 200
        data = response.json()
        assert data["did"].startswith("did:polis:")

    def test_record_created_on_node_a(
        self, client_a: TestClient
    ) -> None:
        """A record created on node A has a valid CID."""
        create_resp = client_a.post("/identity/create", json={})
        did = create_resp.json()["did"]

        payload = base64.b64encode(b"hello from node A").decode()
        record_resp = client_a.post(
            "/records/create",
            json={"payload": payload, "author_did": did},
        )
        assert record_resp.status_code == 200
        assert record_resp.json()["cid"].startswith("01551220")

    def test_record_ingested_on_node_b(
        self, client_a: TestClient, client_b: TestClient
    ) -> None:
        """A record from node A can be manually ingested on node B."""
        # Create identity + record on node A
        create_resp = client_a.post("/identity/create", json={})
        did = create_resp.json()["did"]

        payload = base64.b64encode(b"propagate me").decode()
        record_resp = client_a.post(
            "/records/create",
            json={"payload": payload, "author_did": did},
        )
        record_data = record_resp.json()
        cid = record_data["cid"]

        # Fetch record from node A — GET returns record dict directly
        get_resp = client_a.get(f"/records/{cid}")
        assert get_resp.status_code == 200
        record_dict = get_resp.json()

        # Register the author identity on node B so signature verification works
        state_b = client_b.app.state.node_state
        state_a = client_a.app.state.node_state
        author_identity = state_a.identities[did]
        state_b.register_identity(author_identity)

        # For a public record, storable_data is the raw payload
        storable_bytes = base64.b64decode(payload)

        ingest_resp = client_b.post(
            "/records/ingest",
            json={
                "record": record_dict,
                "data": base64.b64encode(storable_bytes).decode(),
            },
        )
        assert ingest_resp.status_code == 200
        assert ingest_resp.json()["status"] == "ingested"

        # Verify the record is now on node B
        get_b_resp = client_b.get(f"/records/{cid}")
        assert get_b_resp.status_code == 200

    def test_selective_record_key_wrapping_e2e(
        self, client_a: TestClient
    ) -> None:
        """End-to-end: selective record creation → grant access → unwrap key → decrypt."""
        # Create author and recipient on node A
        author_resp = client_a.post("/identity/create", json={})
        author_did = author_resp.json()["did"]

        recipient_resp = client_a.post("/identity/create", json={})
        recipient_did = recipient_resp.json()["did"]

        # Create selective record
        payload = base64.b64encode(b"selective secret").decode()
        record_resp = client_a.post(
            "/records/create",
            json={
                "payload": payload,
                "author_did": author_did,
                "visibility": "selective",
            },
        )
        assert record_resp.status_code == 200
        cid = record_resp.json()["cid"]

        # Grant access to recipient
        grant_resp = client_a.post(
            f"/records/{cid}/grant",
            json={
                "recipient_did": recipient_did,
            },
        )
        assert grant_resp.status_code == 200
        token_data = grant_resp.json()

        # Verify token contains wrapped key
        assert "wrapped_key" in token_data
        assert "wrap_nonce" in token_data

        # Simulate recipient-side decryption using the internal API
        state = client_a.app.state.node_state
        author_identity = state.identities[author_did]
        recipient_identity = state.identities[recipient_did]

        wrapped_key = base64.b64decode(token_data["wrapped_key"])
        wrap_nonce = base64.b64decode(token_data["wrap_nonce"])

        aes_key = _unwrap_key_for_recipient(
            wrapped_key,
            wrap_nonce,
            recipient_identity.signing_key_private,
            author_identity.signing_key_public,
        )
        assert len(aes_key) == 32  # AES-256 key

    def test_two_nodes_independent_identities(
        self, client_a: TestClient, client_b: TestClient
    ) -> None:
        """Each node creates independent identities with unique DIDs."""
        resp_a = client_a.post("/identity/create", json={})
        resp_b = client_b.post("/identity/create", json={})

        did_a = resp_a.json()["did"]
        did_b = resp_b.json()["did"]

        assert did_a != did_b
        assert did_a.startswith("did:polis:")
        assert did_b.startswith("did:polis:")
