# polis/node/tests/test_delegation.py
"""Tests for the DelegationToken and DelegationRegistry modules."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from polis_node.identity.delegation import DelegationToken, DelegationRegistry


class TestDelegationToken:
    """Tests for DelegationToken dataclass and is_valid()."""

    def test_valid_not_revoked_no_expiry(self) -> None:
        token = DelegationToken(
            delegator_did="did:polis:alice",
            delegate_did="did:polis:node1",
        )
        assert token.is_valid() is True

    def test_valid_not_revoked_with_future_expiry(self) -> None:
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        token = DelegationToken(
            delegator_did="did:polis:alice",
            delegate_did="did:polis:node1",
            expires_at=future,
        )
        assert token.is_valid() is True

    def test_invalid_revoked(self) -> None:
        token = DelegationToken(
            delegator_did="did:polis:alice",
            delegate_did="did:polis:node1",
            revoked=True,
        )
        assert token.is_valid() is False

    def test_invalid_expired(self) -> None:
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        token = DelegationToken(
            delegator_did="did:polis:alice",
            delegate_did="did:polis:node1",
            expires_at=past,
        )
        assert token.is_valid() is False

    def test_scope_defaults_to_empty(self) -> None:
        token = DelegationToken(
            delegator_did="did:polis:alice",
            delegate_did="did:polis:node1",
        )
        assert token.scope == []

    def test_token_id_generated(self) -> None:
        token = DelegationToken(
            delegator_did="did:polis:alice",
            delegate_did="did:polis:node1",
        )
        assert isinstance(token.token_id, str)
        assert len(token.token_id) == 32  # hex(16 bytes)

    def test_two_tokens_have_unique_ids(self) -> None:
        t1 = DelegationToken(delegator_did="a", delegate_did="b")
        t2 = DelegationToken(delegator_did="a", delegate_did="b")
        assert t1.token_id != t2.token_id

    def test_custom_scope(self) -> None:
        token = DelegationToken(
            delegator_did="did:polis:alice",
            delegate_did="did:polis:node1",
            scope=["polis.content.post", "polis.content.comment"],
        )
        assert len(token.scope) == 2

    def test_is_in_scope_empty_allows_all(self) -> None:
        token = DelegationToken(delegator_did="a", delegate_did="b")
        assert token.is_in_scope("anything") is True

    def test_is_in_scope_restricted(self) -> None:
        token = DelegationToken(
            delegator_did="a",
            delegate_did="b",
            scope=["polis.content.post"],
        )
        assert token.is_in_scope("polis.content.post") is True
        assert token.is_in_scope("polis.content.media") is False

    def test_canonical_bytes_deterministic(self) -> None:
        token = DelegationToken(
            delegator_did="did:polis:alice",
            delegate_did="did:polis:node",
            scope=["a", "b"],
            expires_at="2026-01-01T00:00:00+00:00",
            token_id="abc123",
        )
        assert token.canonical_bytes() == token.canonical_bytes()
        assert b"did:polis:alice" in token.canonical_bytes()


# ---------------------------------------------------------------------------
# DelegationRegistry
# ---------------------------------------------------------------------------


class TestDelegationRegistry:
    """Tests for the DelegationRegistry (issue / verify / revoke)."""

    def test_issue_and_verify(self) -> None:
        reg = DelegationRegistry()
        token = reg.issue("did:polis:alice", "did:polis:node")
        assert reg.verify(token.token_id)

    def test_verify_with_scope_match(self) -> None:
        reg = DelegationRegistry()
        token = reg.issue(
            "did:polis:alice",
            "did:polis:node",
            scope=["polis.content.post"],
        )
        assert reg.verify(token.token_id, record_type="polis.content.post")

    def test_verify_with_scope_mismatch(self) -> None:
        reg = DelegationRegistry()
        token = reg.issue(
            "did:polis:alice",
            "did:polis:node",
            scope=["polis.content.post"],
        )
        assert not reg.verify(token.token_id, record_type="polis.content.media")

    def test_verify_unknown_token(self) -> None:
        reg = DelegationRegistry()
        assert not reg.verify("nonexistent")

    def test_revoke_success(self) -> None:
        reg = DelegationRegistry()
        token = reg.issue("did:polis:alice", "did:polis:node")
        assert reg.revoke(token.token_id) is True
        assert not reg.verify(token.token_id)

    def test_revoke_unknown(self) -> None:
        reg = DelegationRegistry()
        assert reg.revoke("missing") is False

    def test_get_returns_token(self) -> None:
        reg = DelegationRegistry()
        token = reg.issue("did:polis:alice", "did:polis:node")
        fetched = reg.get(token.token_id)
        assert fetched is not None
        assert fetched.delegator_did == "did:polis:alice"

    def test_get_unknown(self) -> None:
        reg = DelegationRegistry()
        assert reg.get("nope") is None

    def test_issue_with_sign_fn(self) -> None:
        reg = DelegationRegistry()
        token = reg.issue(
            "did:polis:alice",
            "did:polis:node",
            sign_fn=lambda data: b"\x00" * 64,
        )
        assert token.signature == ("00" * 64)

    def test_issue_custom_duration(self) -> None:
        reg = DelegationRegistry()
        token = reg.issue(
            "did:polis:alice",
            "did:polis:node",
            duration_hours=1,
        )
        expiry = datetime.fromisoformat(token.expires_at)
        delta = expiry - datetime.now(timezone.utc)
        assert 0 < delta.total_seconds() < 3700
