# polis/node/tests/test_ipfs_arweave.py
"""Tests for IPFS and Arweave storage backends (mocked HTTP)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from polis_node.storage.ipfs import IPFSBackend
from polis_node.storage.arweave import ArweaveBackend
from polis_node.storage.interface import IntegrityError, StorageBackend, StorageError


# ---------------------------------------------------------------------------
# Helpers — build fake httpx.Response objects
# ---------------------------------------------------------------------------


def _fake_response(
    status_code: int = 200,
    content: bytes = b"",
    json_data: dict | None = None,
) -> httpx.Response:
    """Build a minimal ``httpx.Response`` for testing."""
    resp = httpx.Response(
        status_code=status_code,
        request=httpx.Request("POST", "http://test"),
        content=content,
    )
    if json_data is not None:
        import json as _json
        resp = httpx.Response(
            status_code=status_code,
            request=httpx.Request("POST", "http://test"),
            content=_json.dumps(json_data).encode(),
            headers={"content-type": "application/json"},
        )
    return resp


def _mock_client_post(return_response: httpx.Response | Exception):
    """Return an AsyncMock for ``httpx.AsyncClient`` whose ``.post()`` returns *return_response*."""
    client = AsyncMock()
    if isinstance(return_response, Exception):
        client.post.side_effect = return_response
        client.get.side_effect = return_response
        client.head.side_effect = return_response
    else:
        client.post.return_value = return_response
        client.get.return_value = return_response
        client.head.return_value = return_response
    return client


# ---------------------------------------------------------------------------
# IPFS Backend
# ---------------------------------------------------------------------------


class TestIPFSBackend:
    """Tests for IPFSBackend with mocked IPFS daemon."""

    def test_init_strips_trailing_slash(self) -> None:
        backend = IPFSBackend("http://localhost:5001/")
        assert backend.api_url == "http://localhost:5001"

    def test_init_default_url(self) -> None:
        backend = IPFSBackend()
        assert backend.api_url == "http://localhost:5001"

    @pytest.mark.asyncio
    async def test_put_success(self) -> None:
        backend = IPFSBackend("http://fake:5001")
        client = _mock_client_post(
            _fake_response(json_data={"Hash": "QmFakeHash", "Size": "42"})
        )
        with patch("polis_node.storage.ipfs.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            cid = await backend.put(b"data")
        assert cid == "QmFakeHash"

    @pytest.mark.asyncio
    async def test_put_http_error(self) -> None:
        backend = IPFSBackend("http://fake:5001")
        client = _mock_client_post(httpx.ConnectError("refused"))
        with patch("polis_node.storage.ipfs.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            with pytest.raises(StorageError, match="Failed to store"):
                await backend.put(b"data")

    @pytest.mark.asyncio
    async def test_put_status_error(self) -> None:
        backend = IPFSBackend("http://fake:5001")
        resp = _fake_response(status_code=500);
        client = _mock_client_post(resp)
        with patch("polis_node.storage.ipfs.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            with pytest.raises(StorageError, match="Failed to store"):
                await backend.put(b"data")

    @pytest.mark.asyncio
    async def test_get_success(self) -> None:
        data = b"test content"
        cid = StorageBackend.compute_cid(data)
        backend = IPFSBackend("http://fake:5001")
        client = _mock_client_post(_fake_response(content=data))
        with patch("polis_node.storage.ipfs.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await backend.get(cid)
        assert result == data

    @pytest.mark.asyncio
    async def test_get_not_found(self) -> None:
        backend = IPFSBackend("http://fake:5001")
        client = _mock_client_post(_fake_response(status_code=404))
        with patch("polis_node.storage.ipfs.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            with pytest.raises(KeyError, match="not found"):
                await backend.get("QmMissing")

    @pytest.mark.asyncio
    async def test_get_integrity_failure(self) -> None:
        cid = StorageBackend.compute_cid(b"original data")
        backend = IPFSBackend("http://fake:5001")
        client = _mock_client_post(_fake_response(content=b"tampered"))
        with patch("polis_node.storage.ipfs.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            with pytest.raises(IntegrityError, match="integrity check failed"):
                await backend.get(cid)

    @pytest.mark.asyncio
    async def test_get_http_error(self) -> None:
        backend = IPFSBackend("http://fake:5001")
        client = _mock_client_post(httpx.ConnectError("refused"))
        with patch("polis_node.storage.ipfs.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            with pytest.raises(StorageError, match="Failed to retrieve"):
                await backend.get("QmDown")

    @pytest.mark.asyncio
    async def test_pin_success(self) -> None:
        backend = IPFSBackend("http://fake:5001")
        client = _mock_client_post(_fake_response(json_data={"Pins": ["Qm"]}))
        with patch("polis_node.storage.ipfs.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            assert await backend.pin("QmTest") is True

    @pytest.mark.asyncio
    async def test_pin_http_error(self) -> None:
        backend = IPFSBackend("http://fake:5001")
        client = _mock_client_post(httpx.ConnectError("refused"))
        with patch("polis_node.storage.ipfs.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            with pytest.raises(StorageError, match="Failed to pin"):
                await backend.pin("QmBad")

    @pytest.mark.asyncio
    async def test_is_available_true(self) -> None:
        backend = IPFSBackend("http://fake:5001")
        client = _mock_client_post(_fake_response(content=b"data"))
        with patch("polis_node.storage.ipfs.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            assert await backend.is_available("QmExists") is True

    @pytest.mark.asyncio
    async def test_is_available_false(self) -> None:
        backend = IPFSBackend("http://fake:5001")
        client = _mock_client_post(httpx.ConnectError("refused"))
        with patch("polis_node.storage.ipfs.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            assert await backend.is_available("QmTest") is False


# ---------------------------------------------------------------------------
# Arweave Backend
# ---------------------------------------------------------------------------


class TestArweaveBackend:
    """Tests for ArweaveBackend with mocked gateway."""

    def test_init_strips_trailing_slash(self) -> None:
        backend = ArweaveBackend("https://arweave.net/")
        assert backend.gateway_url == "https://arweave.net"

    def test_init_default_url(self) -> None:
        backend = ArweaveBackend()
        assert backend.gateway_url == "https://arweave.net"

    @pytest.mark.asyncio
    async def test_put_success(self) -> None:
        backend = ArweaveBackend("https://fake-arweave")
        client = _mock_client_post(_fake_response(status_code=202))
        with patch("polis_node.storage.arweave.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            cid = await backend.put(b"data")
        assert cid  # returns a CID string

    @pytest.mark.asyncio
    async def test_put_gateway_rejected_returns_cid(self) -> None:
        """When gateway rejects, put() still returns the local CID."""
        backend = ArweaveBackend("https://fake-arweave")
        client = _mock_client_post(_fake_response(status_code=400))
        with patch("polis_node.storage.arweave.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            cid = await backend.put(b"data")
        assert cid == StorageBackend.compute_cid(b"data")

    @pytest.mark.asyncio
    async def test_put_gateway_unreachable_returns_cid(self) -> None:
        """When gateway is down, put() still returns the local CID."""
        backend = ArweaveBackend("https://fake-arweave")
        client = _mock_client_post(httpx.ConnectError("refused"))
        with patch("polis_node.storage.arweave.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            cid = await backend.put(b"data")
        assert cid == StorageBackend.compute_cid(b"data")

    @pytest.mark.asyncio
    async def test_get_success(self) -> None:
        data = b"arweave content"
        cid = StorageBackend.compute_cid(data)
        backend = ArweaveBackend("https://fake-arweave")
        client = _mock_client_post(_fake_response(content=data))
        with patch("polis_node.storage.arweave.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await backend.get(cid)
        assert result == data

    @pytest.mark.asyncio
    async def test_get_not_found(self) -> None:
        backend = ArweaveBackend("https://fake-arweave")
        client = _mock_client_post(_fake_response(status_code=404))
        with patch("polis_node.storage.arweave.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            with pytest.raises(KeyError, match="not found"):
                await backend.get("txMissing")

    @pytest.mark.asyncio
    async def test_get_integrity_failure(self) -> None:
        cid = StorageBackend.compute_cid(b"original")
        backend = ArweaveBackend("https://fake-arweave")
        client = _mock_client_post(_fake_response(content=b"tampered"))
        with patch("polis_node.storage.arweave.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            with pytest.raises(IntegrityError, match="integrity check failed"):
                await backend.get(cid)

    @pytest.mark.asyncio
    async def test_get_http_error(self) -> None:
        backend = ArweaveBackend("https://fake-arweave")
        client = _mock_client_post(httpx.ConnectError("refused"))
        with patch("polis_node.storage.arweave.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            with pytest.raises(StorageError, match="Failed to retrieve"):
                await backend.get("txDown")

    @pytest.mark.asyncio
    async def test_pin_always_true(self) -> None:
        backend = ArweaveBackend()
        assert await backend.pin("txAnyId") is True

    @pytest.mark.asyncio
    async def test_is_available_true(self) -> None:
        backend = ArweaveBackend("https://fake-arweave")
        client = _mock_client_post(_fake_response())
        with patch("polis_node.storage.arweave.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            assert await backend.is_available("txExists") is True

    @pytest.mark.asyncio
    async def test_is_available_false_on_error(self) -> None:
        backend = ArweaveBackend("https://fake-arweave")
        client = _mock_client_post(httpx.ConnectError("refused"))
        with patch("polis_node.storage.arweave.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            assert await backend.is_available("txTest") is False

    @pytest.mark.asyncio
    async def test_is_available_false_on_404(self) -> None:
        backend = ArweaveBackend("https://fake-arweave")
        client = _mock_client_post(_fake_response(status_code=404))
        with patch("polis_node.storage.arweave.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            assert await backend.is_available("txMissing") is False
