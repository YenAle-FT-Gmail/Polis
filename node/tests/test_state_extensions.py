# tests/test_state_extensions.py
"""Tests for NodeState gap-closure additions: health, pagination, persistence."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from polis_node.api.state import NodeState, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from polis_node.config.settings import PolisNodeSettings
from polis_node.identity.did import PolisIdentity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _settings(**overrides) -> PolisNodeSettings:
    defaults = dict(
        node_id="test-node",
        storage_backend="local",
        log_level="DEBUG",
        data_dir="/tmp/polis-test-state",
        identity_dir="/tmp/polis-test-identities",
        identity_passphrase="",
    )
    defaults.update(overrides)
    return PolisNodeSettings(**defaults)


def _make_state(**kw) -> NodeState:
    return NodeState(_settings(**kw))


# ---------------------------------------------------------------------------
# Health status
# ---------------------------------------------------------------------------


class TestGetHealthStatus:
    """Tests for NodeState.get_health_status()."""

    def test_healthy_with_data(self) -> None:
        state = _make_state()
        ident = PolisIdentity.create()
        state.register_identity(ident)
        status = state.get_health_status()
        assert status["status"] == "healthy"
        assert status["identity_count"] == 1
        assert status["storage_ok"] is True
        assert "uptime_seconds" in status

    def test_uptime_increases(self) -> None:
        state = _make_state()
        s1 = state.get_health_status()["uptime_seconds"]
        time.sleep(0.05)
        s2 = state.get_health_status()["uptime_seconds"]
        assert s2 > s1

    def test_idle_after_60s_with_nothing(self) -> None:
        state = _make_state()
        # Fake started_at to >60 s ago
        state._started_at = time.monotonic() - 120
        status = state.get_health_status()
        assert status["status"] == "idle"

    def test_peer_count_reflected(self) -> None:
        state = _make_state()
        state.peers.append("node-b:8000")
        status = state.get_health_status()
        assert status["peer_count"] == 1


# ---------------------------------------------------------------------------
# Pagination helpers
# ---------------------------------------------------------------------------


class TestPagination:
    """Tests for get_records_by_author with offset/limit."""

    @pytest.mark.asyncio
    async def test_default_page_size(self) -> None:
        state = _make_state()
        await state.initialize()
        ident = PolisIdentity.create()
        state.register_identity(ident)

        # Store 5 records
        from polis_node.attribution.record import AttributionRecord
        for i in range(5):
            payload = f"payload-{i}".encode()
            rec, storable = AttributionRecord.create(
                payload=payload, author=ident,
            )
            await state.store_record(rec, storable)

        records = state.get_records_by_author(ident.did)
        assert len(records) == 5

    @pytest.mark.asyncio
    async def test_offset_and_limit(self) -> None:
        state = _make_state()
        await state.initialize()
        ident = PolisIdentity.create()
        state.register_identity(ident)

        from polis_node.attribution.record import AttributionRecord
        for i in range(10):
            payload = f"p-{i}".encode()
            rec, storable = AttributionRecord.create(
                payload=payload, author=ident,
            )
            await state.store_record(rec, storable)

        page = state.get_records_by_author(ident.did, offset=3, limit=4)
        assert len(page) == 4

    @pytest.mark.asyncio
    async def test_limit_capped_at_max(self) -> None:
        state = _make_state()
        await state.initialize()
        ident = PolisIdentity.create()
        state.register_identity(ident)
        # Request beyond MAX_PAGE_SIZE — should be capped
        page = state.get_records_by_author(ident.did, limit=MAX_PAGE_SIZE + 100)
        assert isinstance(page, list)  # no error


# ---------------------------------------------------------------------------
# Persistence (identity load/save)
# ---------------------------------------------------------------------------


class TestPersistence:
    """Tests for identity persistence on shutdown."""

    @pytest.mark.asyncio
    async def test_persist_and_restore(self, tmp_path: Path) -> None:
        passphrase = "test-secret-123"
        id_dir = str(tmp_path / "identities")

        state1 = _make_state(identity_dir=id_dir, identity_passphrase=passphrase)
        await state1.initialize()
        ident = PolisIdentity.create()
        state1.register_identity(ident)
        await state1.shutdown()  # should persist

        # New state instance should restore
        state2 = _make_state(identity_dir=id_dir, identity_passphrase=passphrase)
        state2._load_persisted_identities()
        assert ident.did in state2.identities

    @pytest.mark.asyncio
    async def test_skip_persist_without_passphrase(self, tmp_path: Path) -> None:
        id_dir = str(tmp_path / "identities")
        state = _make_state(identity_dir=id_dir, identity_passphrase="")
        await state.initialize()
        ident = PolisIdentity.create()
        state.register_identity(ident)
        await state.shutdown()
        # No files should be written
        path = Path(id_dir)
        if path.exists():
            assert list(path.glob("*.json")) == []

    @pytest.mark.asyncio
    async def test_load_from_empty_dir(self, tmp_path: Path) -> None:
        id_dir = str(tmp_path / "identities")
        Path(id_dir).mkdir(parents=True)
        state = _make_state(identity_dir=id_dir, identity_passphrase="pw")
        state._load_persisted_identities()
        assert len(state.identities) == 0

    @pytest.mark.asyncio
    async def test_load_from_nonexistent_dir(self, tmp_path: Path) -> None:
        state = _make_state(
            identity_dir=str(tmp_path / "does_not_exist"),
            identity_passphrase="pw",
        )
        state._load_persisted_identities()  # should not raise
        assert len(state.identities) == 0


# ---------------------------------------------------------------------------
# Moderation integration on state
# ---------------------------------------------------------------------------


class TestStateModerationIntegration:
    """Verify state embeds a ModerationEngine."""

    def test_state_has_moderation(self) -> None:
        state = _make_state()
        assert state.moderation is not None
        result = state.moderation.screen(b"clean data")
        from polis_node.moderation.engine import ModerationVerdict
        assert result.verdict == ModerationVerdict.PASS


# ---------------------------------------------------------------------------
# Record persistence
# ---------------------------------------------------------------------------


class TestRecordPersistence:
    """Tests for record persistence on shutdown/restore."""

    @pytest.mark.asyncio
    async def test_persist_and_restore_records(self, tmp_path: Path) -> None:
        data_dir = str(tmp_path / "data")
        passphrase = "test-pw"
        id_dir = str(tmp_path / "identities")

        state1 = _make_state(data_dir=data_dir, identity_dir=id_dir, identity_passphrase=passphrase)
        await state1.initialize()
        ident = PolisIdentity.create()
        state1.register_identity(ident)

        import base64
        from polis_node.attribution.record import AttributionRecord

        record, storable = AttributionRecord.create(
            payload=b"hello world",
            author=ident,
            record_type="polis.content.post",
            visibility="public",
        )
        await state1.store_record(record, storable)
        await state1.shutdown()

        # Records dir should exist
        records_dir = Path(data_dir) / "records"
        assert records_dir.exists()
        meta_files = list(records_dir.glob("*.meta.json"))
        assert len(meta_files) == 1

        # New state should restore the record
        state2 = _make_state(data_dir=data_dir, identity_dir=id_dir, identity_passphrase=passphrase)
        await state2.initialize()
        assert record.cid in state2.records
        assert state2.record_data[record.cid] == storable

    @pytest.mark.asyncio
    async def test_persist_records_empty(self, tmp_path: Path) -> None:
        data_dir = str(tmp_path / "data")
        state = _make_state(data_dir=data_dir)
        await state.initialize()
        await state.shutdown()
        # Should not fail even with empty records
        records_dir = Path(data_dir) / "records"
        assert records_dir.exists()

    @pytest.mark.asyncio
    async def test_load_records_nonexistent_dir(self, tmp_path: Path) -> None:
        state = _make_state(data_dir=str(tmp_path / "nope"))
        state._load_persisted_records()  # should not raise
        assert len(state.records) == 0

    def test_store_permission_token(self) -> None:
        from polis_node.attribution.record import PermissionToken
        state = _make_state()
        token = PermissionToken(
            record_cid="test-cid",
            recipient_did="did:polis:r",
            grantor_did="did:polis:g",
            wrapped_key=b"\x01" * 32,
            wrap_nonce=b"\x02" * 12,
            record_salt=b"\x03" * 16,
            record_nonce=b"\x04" * 12,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        state.store_permission_token(token)
        assert state.get_permission_token(token.token_id) is token
        assert state.get_permission_token("nonexistent") is None
