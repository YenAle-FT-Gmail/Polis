# polis/node/polis_node/identity/did.py
"""
Polis DID (Decentralized Identifier) — Identity Primitive

Implements W3C DID Core compliant identifiers for the Polis protocol.
A Polis DID is derived deterministically from an Ed25519 public key
and remains permanent regardless of key rotation.

DID format: did:polis:<base58btc-encoded-public-key-fingerprint>
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from mnemonic import Mnemonic

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

POLIS_DID_METHOD: str = "polis"
"""The DID method name registered for Polis identifiers."""

POLIS_DID_PREFIX: str = f"did:{POLIS_DID_METHOD}:"
"""Full DID prefix prepended to the fingerprint."""

FINGERPRINT_HASH_ALGORITHM: str = "sha256"
"""Hash algorithm used to derive the fingerprint from the public key."""

BIP39_LANGUAGE: str = "english"
"""Language for the BIP-39 mnemonic wordlist."""

RECOVERY_WINDOW_HOURS: int = 72
"""Hours within which the recovery key can override a signing key rotation.

Used by :meth:`PolisIdentity.is_within_recovery_window` to determine
whether a recovery-key override is still valid after the last key
rotation.  Set to 72 hours per the Polis spec.
"""

DID_DOCUMENT_CONTEXT: tuple[str, ...] = (
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
)
"""JSON-LD @context values for a Polis DID Document (immutable tuple)."""


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 keypair using OS-level CSPRNG.

    Returns:
        A tuple of (private_key, public_key).

    Raises:
        OSError: If the OS CSPRNG is unavailable.
    """
    # Ed25519PrivateKey.generate() uses OpenSSL which sources from OS CSPRNG.
    # We additionally seed via secrets to be explicit about intent.
    _ = secrets.token_bytes(32)  # exercise the CSPRNG — defence in depth
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def _public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key to its raw 32-byte representation.

    Args:
        public_key: The Ed25519 public key to serialize.

    Returns:
        Raw 32-byte public key.
    """
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _private_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    """Serialize an Ed25519 private key to its raw 32-byte seed.

    Args:
        private_key: The Ed25519 private key to serialize.

    Returns:
        Raw 32-byte private key seed.
    """
    return private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _compute_fingerprint(public_key_raw: bytes) -> str:
    """Compute a Base58btc-encoded SHA-256 fingerprint of a public key.

    Args:
        public_key_raw: Raw 32-byte public key.

    Returns:
        Base58btc-encoded fingerprint string.
    """
    digest = hashlib.sha256(public_key_raw).digest()
    return base58.b58encode(digest).decode("ascii")


def _make_did(public_key_raw: bytes) -> str:
    """Construct a Polis DID from a raw public key.

    Args:
        public_key_raw: Raw 32-byte public key bytes.

    Returns:
        A fully-qualified DID string, e.g. ``did:polis:<fingerprint>``.
    """
    fingerprint = _compute_fingerprint(public_key_raw)
    return f"{POLIS_DID_PREFIX}{fingerprint}"


def _private_key_to_mnemonic(private_key_bytes_raw: bytes) -> str:
    """Encode a 32-byte private key seed as a BIP-39 mnemonic phrase.

    Args:
        private_key_bytes_raw: 32-byte Ed25519 private key seed.

    Returns:
        A BIP-39 mnemonic string (24 words for 256 bits).

    Raises:
        ValueError: If the key is not exactly 32 bytes.
    """
    if len(private_key_bytes_raw) != 32:
        raise ValueError(
            f"Private key seed must be exactly 32 bytes, got {len(private_key_bytes_raw)}"
        )
    m = Mnemonic(BIP39_LANGUAGE)
    return m.to_mnemonic(private_key_bytes_raw)


def _mnemonic_to_private_key(mnemonic_phrase: str) -> Ed25519PrivateKey:
    """Recover an Ed25519 private key from a BIP-39 mnemonic phrase.

    Args:
        mnemonic_phrase: A valid BIP-39 mnemonic (24 words).

    Returns:
        The recovered Ed25519PrivateKey.

    Raises:
        ValueError: If the mnemonic is invalid.
    """
    m = Mnemonic(BIP39_LANGUAGE)
    if not m.check(mnemonic_phrase):
        raise ValueError("Invalid BIP-39 mnemonic phrase")
    entropy = m.to_entropy(mnemonic_phrase)
    seed = bytes(entropy)
    return Ed25519PrivateKey.from_private_bytes(seed)


# ---------------------------------------------------------------------------
# PolisIdentity
# ---------------------------------------------------------------------------


@dataclass
class PolisIdentity:
    """Represents a complete Polis identity with signing and recovery keys.

    A PolisIdentity encapsulates:
    - A permanent DID derived from the initial signing public key.
    - A signing keypair used for daily operations (delegatable to a node).
    - A recovery keypair held offline by the user for key recovery.
    - An optional storage endpoint URI.

    .. note::
        Private key fields are stored as raw bytes in v0.1.  Use
        :class:`polis_node.identity.secure_bytes.SecureBytes` when storing
        keys for extended periods.  A future version will integrate
        ``SecureBytes`` directly into identity fields.

    Attributes:
        did: The permanent Polis DID string (``did:polis:<fingerprint>``).
        signing_key_public: Raw 32-byte Ed25519 signing public key.
        signing_key_private: Raw 32-byte Ed25519 signing private key seed.
            Never persisted unencrypted.
        recovery_key_public: Raw 32-byte Ed25519 recovery public key.
        recovery_key_private: Raw 32-byte Ed25519 recovery private key seed.
            Never persisted unencrypted — serialize to mnemonic for backup.
        storage_endpoint: URI of the user's primary data store (optional).
        created_at: ISO 8601 UTC timestamp of identity creation.
        updated_at: ISO 8601 UTC timestamp of last modification.
    """

    did: str
    signing_key_public: bytes
    signing_key_private: bytes
    recovery_key_public: bytes
    recovery_key_private: bytes
    storage_endpoint: Optional[str] = None
    created_at: str = field(default_factory=lambda: "")
    updated_at: str = field(default_factory=lambda: "")

    @classmethod
    def create(cls, storage_endpoint: Optional[str] = None) -> PolisIdentity:
        """Create a new Polis identity with fresh keypairs.

        Generates both a signing keypair and a recovery keypair using
        OS-level CSPRNG. The DID is derived deterministically from the
        initial signing public key.

        Args:
            storage_endpoint: Optional URI to the user's primary data store.

        Returns:
            A new PolisIdentity instance.
        """
        signing_private, signing_public = _generate_ed25519_keypair()
        recovery_private, recovery_public = _generate_ed25519_keypair()

        signing_pub_bytes = _public_key_bytes(signing_public)
        signing_priv_bytes = _private_key_bytes(signing_private)
        recovery_pub_bytes = _public_key_bytes(recovery_public)
        recovery_priv_bytes = _private_key_bytes(recovery_private)

        did = _make_did(signing_pub_bytes)
        now = datetime.now(timezone.utc).isoformat()

        return cls(
            did=did,
            signing_key_public=signing_pub_bytes,
            signing_key_private=signing_priv_bytes,
            recovery_key_public=recovery_pub_bytes,
            recovery_key_private=recovery_priv_bytes,
            storage_endpoint=storage_endpoint,
            created_at=now,
            updated_at=now,
        )

    def to_did_document(self) -> dict:
        """Serialize this identity to a W3C DID Document (JSON-LD).

        The DID Document contains only public information: the DID,
        public keys, verification methods, and the storage endpoint.
        Private key material is *never* included.

        Returns:
            A dict representing the DID Document conforming to
            W3C DID Core and Ed25519 2020 crypto suite.
        """
        signing_key_b58 = base58.b58encode(self.signing_key_public).decode("ascii")
        recovery_key_b58 = base58.b58encode(self.recovery_key_public).decode("ascii")

        doc: dict = {
            "@context": list(DID_DOCUMENT_CONTEXT),
            "id": self.did,
            "created": self.created_at,
            "updated": self.updated_at,
            "verificationMethod": [
                {
                    "id": f"{self.did}#signing-key",
                    "type": "Ed25519VerificationKey2020",
                    "controller": self.did,
                    "publicKeyBase58": signing_key_b58,
                },
                {
                    "id": f"{self.did}#recovery-key",
                    "type": "Ed25519VerificationKey2020",
                    "controller": self.did,
                    "publicKeyBase58": recovery_key_b58,
                },
            ],
            "authentication": [f"{self.did}#signing-key"],
            "assertionMethod": [f"{self.did}#signing-key"],
            "capabilityDelegation": [f"{self.did}#signing-key"],
            "keyAgreement": [],
        }

        if self.storage_endpoint:
            doc["service"] = [
                {
                    "id": f"{self.did}#storage",
                    "type": "PolisStorageEndpoint",
                    "serviceEndpoint": self.storage_endpoint,
                }
            ]

        return doc

    def sign(self, payload: bytes) -> bytes:
        """Sign arbitrary bytes with this identity's signing key.

        Args:
            payload: The bytes to sign.

        Returns:
            The Ed25519 signature bytes (64 bytes).

        Raises:
            ValueError: If the signing key is unavailable.
        """
        private_key = Ed25519PrivateKey.from_private_bytes(self.signing_key_private)
        return private_key.sign(payload)

    def verify(self, payload: bytes, signature: bytes) -> bool:
        """Verify a signature against this identity's signing public key.

        Args:
            payload: The original payload that was signed.
            signature: The signature bytes to verify.

        Returns:
            True if the signature is valid, False otherwise.
        """
        public_key = Ed25519PublicKey.from_public_bytes(self.signing_key_public)
        try:
            public_key.verify(signature, payload)
            return True
        except Exception:
            return False

    def rotate_signing_key(self, new_private_key: Optional[Ed25519PrivateKey] = None) -> PolisIdentity:
        """Rotate the signing key while preserving the DID.

        The DID is permanent — it was derived from the *initial* signing
        key and does not change when the signing key is rotated.

        Args:
            new_private_key: An optional new Ed25519PrivateKey. If None,
                a fresh keypair is generated.

        Returns:
            A new PolisIdentity with the updated signing key and
            ``updated_at`` timestamp.
        """
        if new_private_key is None:
            new_private_key, _ = _generate_ed25519_keypair()

        new_public_key = new_private_key.public_key()
        now = datetime.now(timezone.utc).isoformat()

        return PolisIdentity(
            did=self.did,  # DID never changes
            signing_key_public=_public_key_bytes(new_public_key),
            signing_key_private=_private_key_bytes(new_private_key),
            recovery_key_public=self.recovery_key_public,
            recovery_key_private=self.recovery_key_private,
            storage_endpoint=self.storage_endpoint,
            created_at=self.created_at,
            updated_at=now,
        )

    def serialize_recovery_key_to_mnemonic(self) -> str:
        """Serialize the recovery private key to a BIP-39 mnemonic phrase.

        This mnemonic should be written down and stored securely offline.
        It is the *only* way to recover the identity if the signing key
        is compromised.

        Returns:
            A 24-word BIP-39 mnemonic string.

        Raises:
            ValueError: If the recovery private key is malformed.
        """
        return _private_key_to_mnemonic(self.recovery_key_private)

    def is_within_recovery_window(self) -> bool:
        """Check if the identity is within the recovery window.

        The recovery window is the period after the last key update
        during which the recovery key can override a signing key
        rotation.  Defined by :data:`RECOVERY_WINDOW_HOURS`.

        Returns:
            True if the current time is within ``RECOVERY_WINDOW_HOURS``
            of the ``updated_at`` timestamp, False otherwise.
        """
        if not self.updated_at:
            return False
        updated = datetime.fromisoformat(self.updated_at)
        window = timedelta(hours=RECOVERY_WINDOW_HOURS)
        return datetime.now(timezone.utc) - updated <= window

    @classmethod
    def recover_from_mnemonic(cls, mnemonic_phrase: str, signing_key_private: bytes, did: str, created_at: str, storage_endpoint: Optional[str] = None) -> PolisIdentity:
        """Recover a PolisIdentity using a BIP-39 mnemonic for the recovery key.

        Args:
            mnemonic_phrase: The 24-word BIP-39 mnemonic.
            signing_key_private: The current signing private key seed (32 bytes).
            did: The permanent DID string.
            created_at: The original creation timestamp.
            storage_endpoint: Optional storage endpoint URI.

        Returns:
            A reconstructed PolisIdentity.

        Raises:
            ValueError: If the mnemonic is invalid.
        """
        recovery_private = _mnemonic_to_private_key(mnemonic_phrase)
        recovery_public = recovery_private.public_key()

        signing_key = Ed25519PrivateKey.from_private_bytes(signing_key_private)
        signing_public = signing_key.public_key()
        now = datetime.now(timezone.utc).isoformat()

        return cls(
            did=did,
            signing_key_public=_public_key_bytes(signing_public),
            signing_key_private=signing_key_private,
            recovery_key_public=_public_key_bytes(recovery_public),
            recovery_key_private=_private_key_bytes(recovery_private),
            storage_endpoint=storage_endpoint,
            created_at=created_at,
            updated_at=now,
        )


# ---------------------------------------------------------------------------
# DID Resolver
# ---------------------------------------------------------------------------


class DIDResolver:
    """Resolves Polis DIDs to their DID Documents.

    In v0.1, resolution is local-only — DID documents are stored in an
    in-memory registry. Future versions will support distributed resolution
    across the Polis network.
    """

    def __init__(self) -> None:
        """Initialize an empty DID resolver."""
        self._registry: dict[str, dict] = {}

    def register(self, identity: PolisIdentity) -> None:
        """Register a PolisIdentity's DID Document in the local resolver.

        Args:
            identity: The PolisIdentity to register.
        """
        self._registry[identity.did] = identity.to_did_document()

    def resolve(self, did: str) -> Optional[dict]:
        """Resolve a DID to its DID Document.

        Args:
            did: The DID string to resolve.

        Returns:
            The DID Document dict if found, None otherwise.
        """
        return self._registry.get(did)

    def get_signing_public_key(self, did: str) -> Optional[bytes]:
        """Extract the signing public key bytes from a resolved DID.

        Args:
            did: The DID string to look up.

        Returns:
            Raw 32-byte public key if found, None otherwise.
        """
        doc = self.resolve(did)
        if doc is None:
            return None

        for method in doc.get("verificationMethod", []):
            if method.get("id", "").endswith("#signing-key"):
                key_b58 = method.get("publicKeyBase58", "")
                return base58.b58decode(key_b58)

        return None

    def update(self, identity: PolisIdentity) -> None:
        """Update the DID Document for an existing identity (e.g. after key rotation).

        Args:
            identity: The PolisIdentity whose document should be updated.

        Raises:
            KeyError: If the DID is not registered.
        """
        if identity.did not in self._registry:
            raise KeyError(
                f"Cannot update unregistered DID: {identity.did}. "
                "Register the identity first with resolver.register()."
            )
        self._registry[identity.did] = identity.to_did_document()
