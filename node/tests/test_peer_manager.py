# tests/test_peer_manager.py
"""Tests for the Polis network peer manager."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from polis_node.network.peer import PeerInfo, PeerManager, PeerStatus


# ---------------------------------------------------------------------------
# Basic CRUD
# ---------------------------------------------------------------------------


class TestPeerManagerCRUD:
    """Add / remove / query operations."""

    def test_add_peer(self) -> None:
        pm = PeerManager()
        peer = pm.add("node-a:8000")
        assert peer.address == "node-a:8000"
        assert peer.status == PeerStatus.CONFIGURED
        assert "node-a:8000" in pm.addresses

    def test_add_idempotent(self) -> None:
        pm = PeerManager()
        p1 = pm.add("node-a:8000")
        p2 = pm.add("node-a:8000")
        assert p1 is p2
        assert len(pm.peers) == 1

    def test_remove_peer(self) -> None:
        pm = PeerManager()
        pm.add("node-a:8000")
        pm.remove("node-a:8000")
        assert "node-a:8000" not in pm.peers

    def test_remove_nonexistent(self) -> None:
        pm = PeerManager()
        pm.remove("ghost:9999")  # should not raise

    def test_get_peer(self) -> None:
        pm = PeerManager()
        pm.add("node-a:8000")
        assert pm.get("node-a:8000") is not None
        assert pm.get("missing:1234") is None


# ---------------------------------------------------------------------------
# Health tracking
# ---------------------------------------------------------------------------


class TestPeerManagerHealth:
    """mark_success / mark_failure / connected property."""

    def test_mark_success(self) -> None:
        pm = PeerManager()
        pm.add("node-a:8000")
        pm.mark_success("node-a:8000", node_id="a-id")
        peer = pm.get("node-a:8000")
        assert peer is not None
        assert peer.status == PeerStatus.CONNECTED
        assert peer.node_id == "a-id"
        assert peer.failures == 0

    def test_mark_failure_below_threshold(self) -> None:
        pm = PeerManager(max_failures=3)
        pm.add("node-a:8000")
        pm.mark_failure("node-a:8000")
        pm.mark_failure("node-a:8000")
        peer = pm.get("node-a:8000")
        assert peer is not None
        assert peer.failures == 2
        assert peer.status != PeerStatus.UNREACHABLE

    def test_mark_failure_exceeds_threshold(self) -> None:
        pm = PeerManager(max_failures=2)
        pm.add("node-a:8000")
        pm.mark_failure("node-a:8000")
        pm.mark_failure("node-a:8000")
        peer = pm.get("node-a:8000")
        assert peer is not None
        assert peer.status == PeerStatus.UNREACHABLE

    def test_success_resets_failures(self) -> None:
        pm = PeerManager(max_failures=3)
        pm.add("node-a:8000")
        pm.mark_failure("node-a:8000")
        pm.mark_failure("node-a:8000")
        pm.mark_success("node-a:8000")
        peer = pm.get("node-a:8000")
        assert peer is not None
        assert peer.failures == 0
        assert peer.status == PeerStatus.CONNECTED

    def test_connected_property(self) -> None:
        pm = PeerManager()
        pm.add("node-a:8000")
        pm.add("node-b:8000")
        pm.mark_success("node-a:8000")
        assert len(pm.connected) == 1
        assert pm.connected[0].address == "node-a:8000"

    def test_mark_unknown_peer_is_noop(self) -> None:
        pm = PeerManager()
        pm.mark_success("ghost:1111")  # no KeyError
        pm.mark_failure("ghost:1111")


# ---------------------------------------------------------------------------
# Probe (mocked HTTP)
# ---------------------------------------------------------------------------


class TestPeerManagerProbe:
    """probe() and probe_all() with mocked httpx."""

    @pytest.mark.asyncio
    async def test_probe_success(self) -> None:
        pm = PeerManager(dev_mode=True)
        pm.add("node-a:8000")

        mock_resp = httpx.Response(
            200,
            json={"node_id": "a-id", "status": "healthy"},
            request=httpx.Request("GET", "http://node-a:8000/node/status"),
        )
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("polis_node.network.peer.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            ok = await pm.probe("node-a:8000")

        assert ok is True
        peer = pm.get("node-a:8000")
        assert peer is not None
        assert peer.status == PeerStatus.CONNECTED

    @pytest.mark.asyncio
    async def test_probe_failure(self) -> None:
        pm = PeerManager(dev_mode=True)
        pm.add("node-a:8000")

        with patch("polis_node.network.peer.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(
                side_effect=httpx.ConnectError("refused")
            )
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            ok = await pm.probe("node-a:8000")

        assert ok is False

    @pytest.mark.asyncio
    async def test_probe_all(self) -> None:
        pm = PeerManager(dev_mode=True)
        pm.add("node-a:8000")
        pm.add("node-b:8000")

        mock_resp = httpx.Response(
            200,
            json={"node_id": "x"},
            request=httpx.Request("GET", "http://x/node/status"),
        )
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("polis_node.network.peer.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            results = await pm.probe_all()

        assert len(results) == 2
        assert all(v is True for v in results.values())

    def test_scheme_default_https(self) -> None:
        pm = PeerManager()
        assert pm.scheme == "https"

    def test_scheme_dev_http(self) -> None:
        pm = PeerManager(dev_mode=True)
        assert pm.scheme == "http"
