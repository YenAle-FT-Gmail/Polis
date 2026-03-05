# polis/node/tests/test_delegation.py
"""Tests for the DelegationToken placeholder module."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from polis_node.identity.delegation import DelegationToken


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
