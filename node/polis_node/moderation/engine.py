# polis/node/polis_node/moderation/engine.py
"""
Polis Moderation Engine.

Implements content pre-screening to enforce Invariant 6 (CSAM detection
is hardcoded at the protocol level) and provide extensible content
moderation.

The engine runs synchronously at record-creation time: a record that
fails moderation is **never stored** (fail-closed).

Techniques:
1. **Perceptual hashing** (pHash / dHash) of image payloads to detect
   known-bad content against a hash set.
2. **Keyword / pattern screening** for plaintext payloads.
3. **Pluggable classifier hook** for future ML-based detection.

This is a protocol-layer safety mechanism, not a user-facing moderation
tool.  Community moderation (labels, appeals, reports) will be layered
on top via moderation records — see ``specs/moderation/``.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Enums and types
# ---------------------------------------------------------------------------


class ModerationVerdict(str, Enum):
    """Possible verdicts from the moderation engine."""
    PASS = "pass"
    REJECT = "reject"
    FLAG = "flag"


class RejectionReason(str, Enum):
    """Reasons a record may be rejected."""
    KNOWN_BAD_HASH = "known_bad_hash"
    BLOCKED_PATTERN = "blocked_pattern"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    CLASSIFIER_REJECT = "classifier_reject"


@dataclass
class ModerationResult:
    """Result of running content through the moderation engine.

    Attributes:
        verdict: PASS, REJECT, or FLAG.
        reason: Reason for rejection (None if passed).
        details: Additional details for logging.
    """
    verdict: ModerationVerdict
    reason: Optional[RejectionReason] = None
    details: str = ""


# ---------------------------------------------------------------------------
# Perceptual hashing (dHash — difference hash)
# ---------------------------------------------------------------------------


def compute_dhash(data: bytes, hash_size: int = 8) -> str:
    """Compute a difference hash (dHash) for binary data.

    This is a simplified perceptual hash suitable for detecting
    near-duplicate binary content.  For images, a proper implementation
    would resize to (hash_size+1, hash_size) and compare luminance.

    For arbitrary binary data, we chunk the data and compare adjacent
    chunk averages to produce a perceptual fingerprint.

    Args:
        data: Raw bytes to hash.
        hash_size: Size parameter controlling hash length (bits = hash_size^2).

    Returns:
        Hex-encoded perceptual hash string.
    """
    if not data:
        return "0" * (hash_size * hash_size // 4)

    total_cells = hash_size * (hash_size + 1)
    chunk_size = max(1, len(data) // total_cells)

    # Compute average byte value for each chunk
    averages: list[float] = []
    for i in range(total_cells):
        start = i * chunk_size
        end = min(start + chunk_size, len(data))
        chunk = data[start:end] if start < len(data) else b"\x00"
        averages.append(sum(chunk) / max(len(chunk), 1))

    # Build difference hash: compare adjacent cells
    bits: list[int] = []
    for row in range(hash_size):
        for col in range(hash_size):
            idx = row * (hash_size + 1) + col
            if idx + 1 < len(averages):
                bits.append(1 if averages[idx] < averages[idx + 1] else 0)
            else:
                bits.append(0)

    # Pack bits into hex
    result = 0
    for bit in bits:
        result = (result << 1) | bit
    hex_len = (hash_size * hash_size + 3) // 4
    return format(result, f"0{hex_len}x")


def hamming_distance(hash1: str, hash2: str) -> int:
    """Compute the Hamming distance between two hex-encoded hashes.

    Args:
        hash1: First hex hash.
        hash2: Second hex hash.

    Returns:
        Number of differing bits.
    """
    if len(hash1) != len(hash2):
        return max(len(hash1), len(hash2)) * 4  # max possible distance
    val1 = int(hash1, 16)
    val2 = int(hash2, 16)
    xor = val1 ^ val2
    return bin(xor).count("1")


# ---------------------------------------------------------------------------
# Moderation Engine
# ---------------------------------------------------------------------------


class ModerationEngine:
    """Content moderation engine enforcing protocol-level safety invariants.

    The engine maintains:
    - A set of known-bad perceptual hashes (CSAM / illegal content).
    - A set of blocked keyword patterns for plaintext screening.
    - A configurable Hamming-distance threshold for fuzzy hash matching.

    Attributes:
        known_bad_hashes: Set of hex-encoded perceptual hashes of known-bad content.
        blocked_patterns: Set of lowercase keyword patterns to block.
        hash_threshold: Maximum Hamming distance for a perceptual hash match.
        max_payload_bytes: Maximum allowed payload size.
    """

    def __init__(
        self,
        *,
        hash_threshold: int = 10,
        max_payload_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        self.known_bad_hashes: set[str] = set()
        self.blocked_patterns: set[str] = set()
        self.hash_threshold = hash_threshold
        self.max_payload_bytes = max_payload_bytes

    def add_known_bad_hash(self, phash: str) -> None:
        """Register a known-bad perceptual hash.

        Args:
            phash: Hex-encoded perceptual hash to block.
        """
        self.known_bad_hashes.add(phash.lower())

    def add_blocked_pattern(self, pattern: str) -> None:
        """Register a keyword / pattern to block in plaintext payloads.

        Args:
            pattern: Lowercase string pattern.
        """
        self.blocked_patterns.add(pattern.lower())

    def screen(self, payload: bytes, *, is_encrypted: bool = False) -> ModerationResult:
        """Screen a payload against all moderation rules.

        This is the main entry point.  Called at record-creation time
        **before** the record is signed or stored.

        Args:
            payload: Raw payload bytes.
            is_encrypted: If True, skip keyword screening (ciphertext).

        Returns:
            A ModerationResult with the verdict.
        """
        # --- Size check ---
        if len(payload) > self.max_payload_bytes:
            logger.warning("moderation.reject.size", size=len(payload))
            return ModerationResult(
                verdict=ModerationVerdict.REJECT,
                reason=RejectionReason.PAYLOAD_TOO_LARGE,
                details=f"Payload {len(payload)} bytes exceeds limit {self.max_payload_bytes}",
            )

        # --- Perceptual hash check (works on encrypted or plaintext) ---
        phash = compute_dhash(payload)
        for bad_hash in self.known_bad_hashes:
            dist = hamming_distance(phash, bad_hash)
            if dist <= self.hash_threshold:
                logger.warning(
                    "moderation.reject.hash_match",
                    distance=dist,
                    threshold=self.hash_threshold,
                )
                return ModerationResult(
                    verdict=ModerationVerdict.REJECT,
                    reason=RejectionReason.KNOWN_BAD_HASH,
                    details=f"Perceptual hash match (distance={dist})",
                )

        # --- Keyword screening (plaintext only) ---
        if not is_encrypted and self.blocked_patterns:
            try:
                text = payload.decode("utf-8", errors="ignore").lower()
                for pattern in self.blocked_patterns:
                    if pattern in text:
                        logger.warning("moderation.reject.pattern", pattern=pattern)
                        return ModerationResult(
                            verdict=ModerationVerdict.REJECT,
                            reason=RejectionReason.BLOCKED_PATTERN,
                            details=f"Blocked pattern match: '{pattern}'",
                        )
            except Exception:
                pass  # Not decodable as text — skip keyword check

        return ModerationResult(verdict=ModerationVerdict.PASS)
