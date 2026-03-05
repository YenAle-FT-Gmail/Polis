# polis/node/polis_node/identity/delegation.py
"""
Polis Key Delegation — Placeholder for v0.2.

Key delegation allows a user to authorize a node to sign records on
their behalf using a delegated signing key, without exposing the
primary signing key.

In v0.1, the node holds the primary signing key directly. This module
will implement the delegation chain in a future version.

Planned features:
- DelegationToken: time-limited, scope-limited signing authority
- Delegation chain verification
- Revocation of delegated keys
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import secrets


@dataclass
class DelegationToken:
    """Placeholder for a key delegation token.

    Attributes:
        delegator_did: DID of the identity delegating authority.
        delegate_did: DID of the node/identity receiving authority.
        scope: List of allowed record types (empty = all).
        expires_at: ISO 8601 UTC expiry timestamp.
        token_id: Unique identifier.
        revoked: Whether the delegation has been revoked.
    """

    delegator_did: str
    delegate_did: str
    scope: list[str] = field(default_factory=list)
    expires_at: str = ""
    token_id: str = field(default_factory=lambda: secrets.token_hex(16))
    revoked: bool = False

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
