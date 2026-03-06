# tests/test_api_middleware.py
"""Tests for API middleware: security headers, rate limiting, pagination params."""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from polis_node.api.app import create_app, _RATE_BUCKETS, _RATE_LIMIT
from polis_node.config.settings import PolisNodeSettings


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def settings() -> PolisNodeSettings:
    return PolisNodeSettings(
        node_id="test-middleware",
        storage_backend="local",
        log_level="DEBUG",
        data_dir="/tmp/polis-test-middleware",
    )


@pytest.fixture
def app(settings: PolisNodeSettings):
    return create_app(settings)


@pytest.fixture
def client(app) -> TestClient:
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    """Verify security headers are present on every response."""

    def test_x_content_type_options(self, client: TestClient) -> None:
        resp = client.get("/node/status")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, client: TestClient) -> None:
        resp = client.get("/node/status")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_referrer_policy(self, client: TestClient) -> None:
        resp = client.get("/node/status")
        assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    def test_permissions_policy(self, client: TestClient) -> None:
        resp = client.get("/node/status")
        assert "camera=()" in resp.headers.get("Permissions-Policy", "")

    def test_csp_on_api_endpoint(self, client: TestClient) -> None:
        resp = client.get("/node/status")
        assert resp.headers.get("Content-Security-Policy") == "default-src 'none'"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    """Verify the sliding-window rate limiter."""

    def test_under_limit_returns_200(self, client: TestClient) -> None:
        resp = client.get("/node/status")
        assert resp.status_code == 200

    def test_exceeding_limit_returns_429(self, client: TestClient) -> None:
        # Fill the bucket
        for _ in range(_RATE_LIMIT):
            client.get("/node/status")
        # Next request should be rate-limited
        resp = client.get("/node/status")
        assert resp.status_code == 429
        body = resp.json()
        assert "rate_limit_exceeded" in body.get("error", "")
        assert "Retry-After" in resp.headers


# ---------------------------------------------------------------------------
# Pagination query params on /records/by-author
# ---------------------------------------------------------------------------


class TestPaginationAPI:
    """Test offset/limit query params on the by-author endpoint."""

    def _create_identity(self, client: TestClient) -> str:
        resp = client.post("/identity/create", json={})
        return resp.json()["did"]

    def test_default_pagination(self, client: TestClient) -> None:
        did = self._create_identity(client)
        resp = client.get(f"/records/by-author/{did}")
        body = resp.json()
        assert body["offset"] == 0
        assert body["limit"] == 50
        assert body["total"] == 0
        assert body["records"] == []

    def test_custom_pagination(self, client: TestClient) -> None:
        did = self._create_identity(client)
        # Create a few records
        for i in range(3):
            payload = base64.b64encode(f"p{i}".encode()).decode()
            client.post("/records/create", json={"payload": payload, "author_did": did})

        resp = client.get(f"/records/by-author/{did}?offset=1&limit=1")
        body = resp.json()
        assert body["offset"] == 1
        assert body["limit"] == 1
        assert len(body["records"]) == 1
        assert body["total"] == 3


# ---------------------------------------------------------------------------
# Health / uptime in /node/status
# ---------------------------------------------------------------------------


class TestNodeStatusUptime:
    """Verify uptime_seconds is reported in /node/status."""

    def test_uptime_field_present(self, client: TestClient) -> None:
        resp = client.get("/node/status")
        body = resp.json()
        assert "uptime_seconds" in body
        assert body["uptime_seconds"] >= 0


# ---------------------------------------------------------------------------
# Moderation rejection via API
# ---------------------------------------------------------------------------


class TestModerationRejection:
    """Verify that oversized payloads are rejected at API level."""

    def test_oversized_record_rejected(self, client: TestClient) -> None:
        did = self._create_identity(client)
        # 15 MB base64 payload exceeds the moderation engine's 10 MB limit
        huge_payload = base64.b64encode(b"x" * (15 * 1024 * 1024)).decode()
        resp = client.post(
            "/records/create",
            json={"payload": huge_payload, "author_did": did},
        )
        # Should be rejected (422 from pydantic max_length or 400 from moderation)
        assert resp.status_code in (400, 422)

    def _create_identity(self, client: TestClient) -> str:
        return client.post("/identity/create", json={}).json()["did"]
