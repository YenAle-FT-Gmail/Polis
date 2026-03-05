# polis/node/polis_node/identity/persistence.py
"""
Polis Identity Persistence — encrypted file-based identity storage.

Provides a secure mechanism to persist and reload PolisIdentity
instances across node restarts.  Private keys are encrypted at rest
using a passphrase-derived key (PBKDF2 → AES-256-GCM).

This is a Phase 1 skeleton intended for single-node development use.
Production deployments should migrate to a hardware-backed key store.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from polis_node.identity.did import PolisIdentity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS: int = 600_000
"""PBKDF2 iteration count per OWASP 2023 recommendation for SHA-256."""

SALT_SIZE_BYTES: int = 32
"""Size of the random salt for PBKDF2."""

NONCE_SIZE_BYTES: int = 12
"""AES-GCM nonce size."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a passphrase using PBKDF2-SHA256.

    Args:
        passphrase: The user-supplied passphrase.
        salt: A random salt (at least 32 bytes).

    Returns:
        A 32-byte derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def save_identity(
    identity: PolisIdentity,
    path: str | Path,
    passphrase: str,
) -> None:
    """Persist a PolisIdentity to an encrypted file.

    The file contains a JSON envelope with:
    - ``did``, ``created_at``, ``updated_at``, ``storage_endpoint`` (plaintext)
    - ``signing_key_public``, ``recovery_key_public`` (base64, plaintext)
    - ``encrypted_private_keys`` (base64 ciphertext of signing + recovery private keys)
    - ``salt``, ``nonce`` (base64, needed for decryption)

    Args:
        identity: The identity to persist.
        path: Filesystem path for the output file.
        passphrase: Encryption passphrase (never stored).

    Raises:
        OSError: If the file cannot be written.
        ValueError: If the passphrase is empty.
    """
    if not passphrase:
        raise ValueError("Passphrase must not be empty")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    salt = os.urandom(SALT_SIZE_BYTES)
    nonce = os.urandom(NONCE_SIZE_BYTES)
    key = _derive_key(passphrase, salt)

    # Concatenate private keys: signing (32 bytes) + recovery (32 bytes)
    plaintext = identity.signing_key_private + identity.recovery_key_private
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    envelope = {
        "version": 1,
        "did": identity.did,
        "created_at": identity.created_at,
        "updated_at": identity.updated_at,
        "storage_endpoint": identity.storage_endpoint,
        "signing_key_public": base64.b64encode(identity.signing_key_public).decode(),
        "recovery_key_public": base64.b64encode(identity.recovery_key_public).decode(),
        "encrypted_private_keys": base64.b64encode(ciphertext).decode(),
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }

    path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")


def load_identity(
    path: str | Path,
    passphrase: str,
) -> PolisIdentity:
    """Load a PolisIdentity from an encrypted file.

    Args:
        path: Path to the encrypted identity file.
        passphrase: The passphrase used when saving.

    Returns:
        The decrypted PolisIdentity.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the passphrase is wrong or the file is corrupt.
    """
    path = Path(path)
    envelope = json.loads(path.read_text(encoding="utf-8"))

    salt = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["encrypted_private_keys"])

    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError(
            "Failed to decrypt identity file. Wrong passphrase or corrupt data."
        ) from exc

    if len(plaintext) != 64:
        raise ValueError(
            f"Decrypted private key data has unexpected length: {len(plaintext)}"
        )

    signing_key_private = plaintext[:32]
    recovery_key_private = plaintext[32:]

    return PolisIdentity(
        did=envelope["did"],
        signing_key_public=base64.b64decode(envelope["signing_key_public"]),
        signing_key_private=signing_key_private,
        recovery_key_public=base64.b64decode(envelope["recovery_key_public"]),
        recovery_key_private=recovery_key_private,
        storage_endpoint=envelope.get("storage_endpoint"),
        created_at=envelope["created_at"],
        updated_at=envelope["updated_at"],
    )
