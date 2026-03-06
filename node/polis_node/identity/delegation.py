# polis/node/polis_node/identity/delegation.py
"""
Polis Key Delegation.

Key delegation allows a user to authorize a node to sign records on
their behalf using a delegated signing key, without exposing the
primary signing key.

Features:
- DelegationToken: time-limited, scope-limited signing authority
- DelegationRegistry: issue, verify, and revoke delegation tokens.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

import secrets


@dataclass
class DelegationToken:
    """A key delegation token.

    Attributes:
        delegator_did: DID of the identity delegating authority.
        delegate_did: DID of the node/identity receiving authority.
        scope: List of allowed record types (empty = all).
        expires_at: ISO 8601 UTC expiry timestamp.
        token_id: Unique identifier.
        revoked: Whether the delegation has been revoked.
        signature: Hex-encoded signature by the delegator over the token content.
    """

    delegator_did: str
    delegate_did: str
    scope: list[str] = field(default_factory=list)
    expires_at: str = ""
    token_id: str = field(default_factory=lambda: secrets.token_hex(16))
    revoked: bool = False
    signature: str = ""

    def is_valid(self) -> bool:
        """Check if this delegation token is currently valid.

        Returns:
            True if not revoked and not expired.
        """
        if self.revoked:
            return False
        if not self.expires_at:
            return True
        expiry = datetime.fromisoformat(self.expires_at)
        return datetime.now(timezone.utc) < expiry

    def is_in_scope(self, record_type: str) -> bool:
        """Check if a record type is allowed under this delegation.

        Args:
            record_type: The namespaced record type.

        Returns:
            True if the scope allows this record type.
        """
        if not self.scope:
            return True  # empty scope = all types allowed
        return record_type in self.scope

    def canonical_bytes(self) -> bytes:
        """Return the canonical byte representation for signing.

        Returns:
            UTF-8 bytes of the canonical content.
        """
        parts = [
            self.delegator_did,
            self.delegate_did,
            ",".join(sorted(self.scope)),
            self.expires_at,
            self.token_id,
        ]
        return "|".join(parts).encode("utf-8")


class DelegationRegistry:
    """Manages delegation tokens for the node.

    Attributes:
        tokens: Dict of token_id -> DelegationToken.
    """

    def __init__(self) -> None:
        self.tokens: dict[str, DelegationToken] = {}

    def issue(
        self,
        delegator_did: str,
        delegate_did: str,
        *,
        scope: list[str] | None = None,
        duration_hours: int = 24,
        sign_fn: callable | None = None,
    ) -> DelegationToken:
        """Issue a new delegation token.

        Args:
            delegator_did: The DID of the delegator.
            delegate_did: The DID of the delegate.
            scope: Allowed record types (None = all).
            duration_hours: Token lifetime in hours.
            sign_fn: Optional callable(bytes) -> bytes for signing.

        Returns:
            The created DelegationToken.
        """
        expires = (
            datetime.now(timezone.utc) + timedelta(hours=duration_hours)
        ).isoformat()

        token = DelegationToken(
            delegator_did=delegator_did,
            delegate_did=delegate_did,
            scope=scope or [],
            expires_at=expires,
        )

        if sign_fn:
            sig_bytes = sign_fn(token.canonical_bytes())
            token.signature = sig_bytes.hex()

        self.tokens[token.token_id] = token
        return token

    def verify(self, token_id: str, record_type: str = "") -> bool:
        """Verify a delegation token is valid and in scope.

        Args:
            token_id: The token to verify.
            record_type: Optional record type to check scope.

        Returns:
            True if valid and in scope.
        """
        token = self.tokens.get(token_id)
        if token is None:
            return False
        if not token.is_valid():
            return False
        if record_type and not token.is_in_scope(record_type):
            return False
        return True

    def revoke(self, token_id: str) -> bool:
        """Revoke a delegation token.

        Args:
            token_id: The token to revoke.

        Returns:
            True if found and revoked, False if not found.
        """
        token = self.tokens.get(token_id)
        if token is None:
            return False
        token.revoked = True
        return True

    def get(self, token_id: str) -> DelegationToken | None:
        """Look up a token by ID."""
        return self.tokens.get(token_id)
