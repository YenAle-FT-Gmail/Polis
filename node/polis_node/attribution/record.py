# polis/node/polis_node/attribution/record.py
"""
Polis Attribution Record — the atomic unit of permanent attribution.

Every piece of content or action on Polis is an Attribution Record.
Records are cryptographically signed, content-addressed, and permanently
attributed to their author's DID.

Records are serialized to canonical JSON (RFC 8785 / JCS) before signing
to ensure identical verification across all implementations.

.. note::
    ``canonicaljson`` is used for deterministic serialization.  The library
    implements RFC 8785 (JSON Canonicalization Scheme) which guarantees:
    - Sorted keys (lexicographic Unicode codepoint order)
    - No insignificant whitespace
    - Deterministic number formatting
    Full compliance details: https://tools.ietf.org/html/rfc8785
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import canonicaljson
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

from polis_node.identity.did import DIDResolver, PolisIdentity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

POLIS_VERSION: str = "0.1.0"
"""Current Polis protocol version."""

VISIBILITY_PUBLIC: str = "public"
"""Record is visible to everyone."""

VISIBILITY_PRIVATE: str = "private"
"""Record is encrypted; only the author can decrypt."""

VISIBILITY_SELECTIVE: str = "selective"
"""Record is encrypted; access granted via permission tokens."""

VALID_VISIBILITIES: frozenset[str] = frozenset({
    VISIBILITY_PUBLIC,
    VISIBILITY_PRIVATE,
    VISIBILITY_SELECTIVE,
})
"""Set of valid visibility values."""

AES_KEY_SIZE_BYTES: int = 32
"""AES-256 key size in bytes."""

AES_NONCE_SIZE_BYTES: int = 12
"""AES-GCM nonce size in bytes."""

HKDF_INFO_PRIVATE: bytes = b"polis-private-record-encryption"
"""HKDF info parameter for deriving private record encryption keys."""

PERMISSION_TOKEN_HKDF_INFO: bytes = b"polis-permission-token"
"""HKDF info parameter for deriving permission-token encryption keys."""


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _ed25519_private_to_x25519(ed_private_bytes: bytes) -> X25519PrivateKey:
    """Convert Ed25519 private key seed to X25519 private key for key agreement.

    Uses the standard birational map from Ed25519 to X25519.

    Args:
        ed_private_bytes: 32-byte Ed25519 private key seed.

    Returns:
        An X25519PrivateKey suitable for Diffie-Hellman exchange.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Ed25519Priv

    ed_priv = Ed25519Priv.from_private_bytes(ed_private_bytes)
    # Serialize to PKCS8, then extract the raw X25519 key via standard conversion
    # The cryptography library supports direct X25519 from raw bytes
    raw = ed_priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    # Hash the Ed25519 seed to produce the X25519 scalar (standard conversion)
    x_scalar = hashlib.sha512(raw).digest()[:32]
    # Clamp the scalar per X25519 spec
    x_bytes = bytearray(x_scalar)
    x_bytes[0] &= 248
    x_bytes[31] &= 127
    x_bytes[31] |= 64
    return X25519PrivateKey.from_private_bytes(bytes(x_bytes))


def _ed25519_public_to_x25519(ed_public_bytes: bytes) -> X25519PublicKey:
    """Convert Ed25519 public key to X25519 public key for key agreement.

    Uses compressed Edwards-to-Montgomery conversion.

    Args:
        ed_public_bytes: 32-byte Ed25519 public key.

    Returns:
        An X25519PublicKey suitable for Diffie-Hellman exchange.
    """
    # Mathematically convert Edwards point to Montgomery point
    # u = (1 + y) / (1 - y) mod p where p = 2^255 - 19
    p = (1 << 255) - 19
    y = int.from_bytes(ed_public_bytes, "little")
    # Clear the sign bit
    y &= (1 << 255) - 1
    u = ((1 + y) * pow(1 - y, p - 2, p)) % p
    x25519_bytes = u.to_bytes(32, "little")
    return X25519PublicKey.from_public_bytes(x25519_bytes)


def _wrap_key_for_recipient(
    aes_key: bytes,
    grantor_private: bytes,
    recipient_public: bytes,
) -> tuple[bytes, bytes]:
    """Encrypt an AES key for a specific recipient using X25519 + AES-256-GCM.

    Performs ECDH between the grantor's X25519 private key and the
    recipient's X25519 public key to derive a shared wrapping key,
    then encrypts the AES key with AES-256-GCM.

    Args:
        aes_key: The AES-256 key to wrap.
        grantor_private: 32-byte Ed25519 private key seed of the grantor.
        recipient_public: 32-byte Ed25519 public key of the recipient.

    Returns:
        A tuple of (wrapped_key, wrap_nonce) where:
        - wrapped_key: AES-256-GCM encrypted AES key.
        - wrap_nonce: 12-byte nonce used for wrapping.
    """
    grantor_x25519 = _ed25519_private_to_x25519(grantor_private)
    recipient_x25519 = _ed25519_public_to_x25519(recipient_public)

    shared_secret = grantor_x25519.exchange(recipient_x25519)

    # Derive wrapping key from shared secret via HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE_BYTES,
        salt=None,
        info=PERMISSION_TOKEN_HKDF_INFO,
    )
    wrapping_key = hkdf.derive(shared_secret)

    wrap_nonce = secrets.token_bytes(AES_NONCE_SIZE_BYTES)
    aesgcm = AESGCM(wrapping_key)
    wrapped_key = aesgcm.encrypt(wrap_nonce, aes_key, None)
    return wrapped_key, wrap_nonce


def _unwrap_key_for_recipient(
    wrapped_key: bytes,
    wrap_nonce: bytes,
    recipient_private: bytes,
    grantor_public: bytes,
) -> bytes:
    """Decrypt a wrapped AES key using X25519 key agreement.

    Args:
        wrapped_key: The AES-256-GCM encrypted AES key.
        wrap_nonce: The 12-byte nonce used for wrapping.
        recipient_private: 32-byte Ed25519 private key seed of the recipient.
        grantor_public: 32-byte Ed25519 public key of the grantor.

    Returns:
        The unwrapped AES-256 key.

    Raises:
        cryptography.exceptions.InvalidTag: If the key cannot be unwrapped.
    """
    recipient_x25519 = _ed25519_private_to_x25519(recipient_private)
    grantor_x25519 = _ed25519_public_to_x25519(grantor_public)

    shared_secret = recipient_x25519.exchange(grantor_x25519)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE_BYTES,
        salt=None,
        info=PERMISSION_TOKEN_HKDF_INFO,
    )
    wrapping_key = hkdf.derive(shared_secret)

    aesgcm = AESGCM(wrapping_key)
    return aesgcm.decrypt(wrap_nonce, wrapped_key, None)


def _compute_cid(data: bytes) -> str:
    """Compute a content identifier using SHA-256 multihash (IPFS standard).

    In v0.1, this produces a hex-encoded SHA-256 hash prefixed with the
    multihash identifier. A full CIDv1 implementation will be added when
    IPFS integration is completed.

    Args:
        data: The raw bytes to hash.

    Returns:
        A hex-encoded SHA-256 content identifier string.
    """
    digest = hashlib.sha256(data).hexdigest()
    # CIDv1: version=01, codec=55(raw), hash-fn=12(sha256), len=20(32 bytes)
    return f"01551220{digest}"


def _compute_payload_hash(payload: bytes) -> str:
    """Compute the SHA-256 hex digest of a payload.

    Args:
        payload: Raw payload bytes.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    return hashlib.sha256(payload).hexdigest()


def _derive_encryption_key(signing_key_private: bytes, salt: bytes, info: bytes) -> bytes:
    """Derive an AES-256 encryption key from a signing key using HKDF-SHA256.

    Args:
        signing_key_private: The 32-byte private key seed as input key material.
        salt: Random salt for HKDF.
        info: Context info for HKDF.

    Returns:
        32-byte AES-256 key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE_BYTES,
        salt=salt,
        info=info,
    )
    return hkdf.derive(signing_key_private)


def _encrypt_payload(payload: bytes, signing_key_private: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt a payload using AES-256-GCM with a key derived from the signing key.

    Args:
        payload: The plaintext payload to encrypt.
        signing_key_private: The 32-byte signing private key seed.

    Returns:
        A tuple of (ciphertext, nonce, salt) where:
        - ciphertext: The AES-256-GCM encrypted payload.
        - nonce: The 12-byte nonce used for encryption.
        - salt: The 32-byte salt used for HKDF key derivation.
    """
    salt = secrets.token_bytes(AES_KEY_SIZE_BYTES)
    nonce = secrets.token_bytes(AES_NONCE_SIZE_BYTES)
    key = _derive_encryption_key(signing_key_private, salt, HKDF_INFO_PRIVATE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, payload, None)
    return ciphertext, nonce, salt


def _decrypt_payload(ciphertext: bytes, nonce: bytes, salt: bytes, signing_key_private: bytes) -> bytes:
    """Decrypt a payload encrypted with _encrypt_payload.

    Args:
        ciphertext: The AES-256-GCM encrypted data.
        nonce: The 12-byte nonce.
        salt: The 32-byte HKDF salt.
        signing_key_private: The 32-byte signing private key seed.

    Returns:
        The decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If decryption fails (wrong key or tampered data).
    """
    key = _derive_encryption_key(signing_key_private, salt, HKDF_INFO_PRIVATE)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# Permission Token
# ---------------------------------------------------------------------------


@dataclass
class PermissionToken:
    """A time-limited access grant for a selective-visibility record.

    The record encryption key is wrapped (encrypted) specifically for
    the recipient using X25519 ECDH + AES-256-GCM.  Only the intended
    recipient can unwrap the key.

    Attributes:
        record_cid: The CID of the record being shared.
        recipient_did: The DID of the recipient.
        grantor_did: The DID of the identity granting access.
        wrapped_key: The record AES key, encrypted for the recipient via ECDH.
        wrap_nonce: The 12-byte nonce used for the key-wrapping encryption.
        record_salt: The HKDF salt used for the record's encryption key derivation.
        record_nonce: The AES-GCM nonce used for the record's encryption.
        expires_at: ISO 8601 UTC timestamp when the token expires.
        token_id: Unique identifier for this token.
        revoked: Whether this token has been revoked.
    """

    record_cid: str
    recipient_did: str
    grantor_did: str
    wrapped_key: bytes
    wrap_nonce: bytes
    record_salt: bytes
    record_nonce: bytes
    expires_at: str
    token_id: str = field(default_factory=lambda: secrets.token_hex(16))
    revoked: bool = False

    def is_valid(self) -> bool:
        """Check if this permission token is currently valid.

        Returns:
            True if the token is not revoked and has not expired.
        """
        if self.revoked:
            return False
        expiry = datetime.fromisoformat(self.expires_at)
        now = datetime.now(timezone.utc)
        return now < expiry


# ---------------------------------------------------------------------------
# Attribution Record
# ---------------------------------------------------------------------------


@dataclass
class AttributionRecord:
    """The atomic unit of permanent attribution in Polis.

    Every piece of content or action on Polis is represented as an
    AttributionRecord. Records are cryptographically signed by their
    author and content-addressed for integrity verification.

    Attributes:
        polis_version: Protocol version string.
        record_type: Namespaced record type (polis.<category>.<type>).
        cid: Content identifier (SHA-256 multihash of the payload or ciphertext).
        author_did: The DID of the record's author.
        timestamp: ISO 8601 UTC timestamp of record creation.
        visibility: One of "public", "private", or "selective".
        payload_hash: SHA-256 hex digest of the raw (unencrypted) payload.
        signature: Ed25519 signature of the canonical record bytes (hex-encoded).
        permission_tokens: List of permission token IDs (for selective visibility).
        encryption_metadata: Optional dict with nonce/salt for encrypted records.
    """

    polis_version: str
    record_type: str
    cid: str
    author_did: str
    timestamp: str
    visibility: str
    payload_hash: str
    signature: str
    permission_tokens: list[str] = field(default_factory=list)
    encryption_metadata: Optional[dict] = None

    @classmethod
    def create(
        cls,
        payload: bytes,
        author: PolisIdentity,
        record_type: str = "polis.content.post",
        visibility: str = VISIBILITY_PUBLIC,
    ) -> tuple[AttributionRecord, bytes]:
        """Create a new attribution record atomically.

        The record is created and signed in a single operation. If any step
        fails, no record is produced — records are atomic.

        For private/selective visibility, the payload is encrypted with
        AES-256-GCM before the CID is computed. The CID always references
        the stored form (ciphertext for encrypted records, plaintext for public).

        Args:
            payload: The raw content bytes.
            author: The PolisIdentity of the record's author.
            record_type: Namespaced record type (default: polis.content.post).
            visibility: Record visibility ("public", "private", or "selective").

        Returns:
            A tuple of (fully signed AttributionRecord, storable_data) where
            storable_data is the ciphertext for encrypted records or the
            original plaintext for public records.

        Raises:
            ValueError: If the visibility value is invalid or the record type
                is malformed.
        """
        if visibility not in VALID_VISIBILITIES:
            raise ValueError(
                f"Invalid visibility '{visibility}'. "
                f"Must be one of: {', '.join(sorted(VALID_VISIBILITIES))}"
            )

        if not record_type.startswith("polis."):
            raise ValueError(
                f"Record type must be namespaced with 'polis.' prefix, got: '{record_type}'"
            )

        payload_hash = _compute_payload_hash(payload)
        timestamp = datetime.now(timezone.utc).isoformat()
        encryption_metadata: Optional[dict] = None

        # For private/selective records, encrypt before computing CID
        if visibility in (VISIBILITY_PRIVATE, VISIBILITY_SELECTIVE):
            ciphertext, nonce, salt = _encrypt_payload(payload, author.signing_key_private)
            cid = _compute_cid(ciphertext)
            storable_data = ciphertext
            encryption_metadata = {
                "nonce": nonce.hex(),
                "salt": salt.hex(),
            }
        else:
            cid = _compute_cid(payload)
            storable_data = payload

        # Build the record (unsigned)
        record = cls(
            polis_version=POLIS_VERSION,
            record_type=record_type,
            cid=cid,
            author_did=author.did,
            timestamp=timestamp,
            visibility=visibility,
            payload_hash=payload_hash,
            signature="",  # Will be set after signing
            permission_tokens=[],
            encryption_metadata=encryption_metadata,
        )

        # Sign the canonical record bytes
        canonical = record.canonical_bytes()
        signature = author.sign(canonical)
        record.signature = signature.hex()

        return record, storable_data

    def canonical_bytes(self) -> bytes:
        """Serialize the record to canonical JSON bytes for signing/verification.

        Uses RFC 8785 (JCS) — keys sorted lexicographically, no whitespace.
        The signature field is excluded from the canonical form.

        Returns:
            Canonical JSON bytes suitable for signing or verification.
        """
        canonical_dict = {
            "author_did": self.author_did,
            "cid": self.cid,
            "payload_hash": self.payload_hash,
            "polis_version": self.polis_version,
            "record_type": self.record_type,
            "timestamp": self.timestamp,
            "visibility": self.visibility,
        }
        return canonicaljson.encode_canonical_json(canonical_dict)

    def verify(self, did_resolver: DIDResolver) -> bool:
        """Verify this record's signature against the author's signing key.

        Resolves the author's DID, extracts the signing public key, and
        verifies the Ed25519 signature over the canonical record bytes.

        Args:
            did_resolver: A DIDResolver capable of resolving the author's DID.

        Returns:
            True if the signature is valid, False otherwise.

        Raises:
            ValueError: If the author's DID cannot be resolved or has no
                signing key.
        """
        public_key_bytes = did_resolver.get_signing_public_key(self.author_did)
        if public_key_bytes is None:
            raise ValueError(
                f"Failed to verify signature: cannot resolve signing key for "
                f"DID {self.author_did}"
            )

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        canonical = self.canonical_bytes()
        signature_bytes = bytes.fromhex(self.signature)

        try:
            public_key.verify(signature_bytes, canonical)
            return True
        except Exception:
            return False

    def to_dict(self) -> dict:
        """Serialize the record to a dictionary.

        Returns:
            A dict representation of the record, suitable for JSON encoding.
        """
        result = {
            "polis_version": self.polis_version,
            "record_type": self.record_type,
            "cid": self.cid,
            "author_did": self.author_did,
            "timestamp": self.timestamp,
            "visibility": self.visibility,
            "payload_hash": self.payload_hash,
            "signature": self.signature,
            "permission_tokens": self.permission_tokens,
        }
        if self.encryption_metadata:
            result["encryption_metadata"] = self.encryption_metadata
        return result

    @classmethod
    def from_dict(cls, data: dict) -> AttributionRecord:
        """Deserialize a record from a dictionary.

        Args:
            data: A dict containing all record fields.

        Returns:
            An AttributionRecord instance.

        Raises:
            KeyError: If required fields are missing.
        """
        return cls(
            polis_version=data["polis_version"],
            record_type=data["record_type"],
            cid=data["cid"],
            author_did=data["author_did"],
            timestamp=data["timestamp"],
            visibility=data["visibility"],
            payload_hash=data["payload_hash"],
            signature=data["signature"],
            permission_tokens=data.get("permission_tokens", []),
            encryption_metadata=data.get("encryption_metadata"),
        )

    def grant_access(
        self,
        recipient_did: str,
        author: PolisIdentity,
        expiry_seconds: int = 3600,
        recipient_public_key: Optional[bytes] = None,
    ) -> PermissionToken:
        """Grant access to this record for a specific recipient.

        Creates a permission token that allows the recipient to decrypt
        the record content.  The AES record-key is wrapped (encrypted)
        using X25519 ECDH between the author and the recipient so that
        only the intended recipient can unwrap it.

        Only works for selective-visibility records.

        Args:
            recipient_did: The DID of the identity to grant access to.
            author: The author's PolisIdentity (needed for key derivation).
            expiry_seconds: How long the token is valid, in seconds.
            recipient_public_key: 32-byte Ed25519 public key of the
                recipient.  If ``None``, the key must be resolvable at
                decryption time (for v0.1, pass explicitly).

        Returns:
            A PermissionToken granting the recipient access.

        Raises:
            ValueError: If the record is not selective-visibility,
                encryption metadata is missing, or the recipient's public
                key is not provided.
        """
        if self.visibility != VISIBILITY_SELECTIVE:
            raise ValueError(
                f"Cannot grant access to a '{self.visibility}' record. "
                f"Only '{VISIBILITY_SELECTIVE}' records support access grants."
            )

        if self.encryption_metadata is None:
            raise ValueError(
                "Cannot grant access: record is missing encryption metadata."
            )

        if recipient_public_key is None:
            raise ValueError(
                "Cannot grant access: recipient_public_key is required so the "
                "AES key can be encrypted specifically for the recipient."
            )

        salt = bytes.fromhex(self.encryption_metadata["salt"])
        nonce = bytes.fromhex(self.encryption_metadata["nonce"])

        # Re-derive the record encryption key
        encryption_key = _derive_encryption_key(
            author.signing_key_private, salt, HKDF_INFO_PRIVATE
        )

        # Wrap the encryption key for the recipient using ECDH
        wrapped_key, wrap_nonce = _wrap_key_for_recipient(
            aes_key=encryption_key,
            grantor_private=author.signing_key_private,
            recipient_public=recipient_public_key,
        )

        expiry = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() + expiry_seconds,
            tz=timezone.utc,
        ).isoformat()

        token = PermissionToken(
            record_cid=self.cid,
            recipient_did=recipient_did,
            grantor_did=self.author_did,
            wrapped_key=wrapped_key,
            wrap_nonce=wrap_nonce,
            record_salt=salt,
            record_nonce=nonce,
            expires_at=expiry,
        )

        self.permission_tokens.append(token.token_id)
        return token

    def revoke_access(self, token: PermissionToken) -> None:
        """Revoke a previously granted permission token.

        Revocation is immediate — the token ceases to function.

        Args:
            token: The PermissionToken to revoke.

        Raises:
            ValueError: If the token does not belong to this record.
        """
        if token.record_cid != self.cid:
            raise ValueError(
                f"Token {token.token_id} does not belong to record {self.cid}"
            )
        token.revoked = True
        if token.token_id in self.permission_tokens:
            self.permission_tokens.remove(token.token_id)
