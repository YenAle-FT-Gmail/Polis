# tests/test_moderation.py
"""Tests for the Polis moderation engine (Invariant 6 — CSAM detection)."""

from __future__ import annotations

import pytest

from polis_node.moderation.engine import (
    ModerationEngine,
    ModerationResult,
    ModerationVerdict,
    RejectionReason,
    compute_dhash,
    hamming_distance,
)


# ---------------------------------------------------------------------------
# compute_dhash
# ---------------------------------------------------------------------------


class TestComputeDhash:
    """Unit tests for the perceptual difference-hash function."""

    def test_empty_data_returns_zero_hash(self) -> None:
        h = compute_dhash(b"")
        assert all(c == "0" for c in h)

    def test_deterministic(self) -> None:
        data = b"hello world"
        assert compute_dhash(data) == compute_dhash(data)

    def test_different_data_different_hash(self) -> None:
        h1 = compute_dhash(b"alpha payload")
        h2 = compute_dhash(b"beta payload that is totally different content")
        assert h1 != h2

    def test_similar_data_close_distance(self) -> None:
        base = b"A" * 1024
        variant = bytearray(base)
        variant[500] = ord("B")
        h1 = compute_dhash(base)
        h2 = compute_dhash(bytes(variant))
        dist = hamming_distance(h1, h2)
        # Perturbing a single byte should yield a small distance
        assert dist < 20

    def test_custom_hash_size(self) -> None:
        h = compute_dhash(b"data", hash_size=4)
        assert isinstance(h, str)
        assert len(h) > 0


# ---------------------------------------------------------------------------
# hamming_distance
# ---------------------------------------------------------------------------


class TestHammingDistance:
    """Unit tests for the Hamming distance helper."""

    def test_identical_hashes(self) -> None:
        assert hamming_distance("abcd", "abcd") == 0

    def test_completely_different(self) -> None:
        assert hamming_distance("0000", "ffff") == 16

    def test_single_bit_diff(self) -> None:
        assert hamming_distance("0000", "0001") == 1

    def test_mismatched_length_returns_max(self) -> None:
        dist = hamming_distance("ab", "abcd")
        assert dist == 4 * 4  # max(2,4)*4


# ---------------------------------------------------------------------------
# ModerationEngine.screen
# ---------------------------------------------------------------------------


class TestModerationEngine:
    """Integration tests for the ModerationEngine."""

    def test_pass_clean_payload(self) -> None:
        engine = ModerationEngine()
        result = engine.screen(b"perfectly fine content")
        assert result.verdict == ModerationVerdict.PASS
        assert result.reason is None

    def test_reject_payload_too_large(self) -> None:
        engine = ModerationEngine(max_payload_bytes=100)
        result = engine.screen(b"x" * 200)
        assert result.verdict == ModerationVerdict.REJECT
        assert result.reason == RejectionReason.PAYLOAD_TOO_LARGE

    def test_reject_known_bad_hash(self) -> None:
        data = b"known bad content bytes"
        engine = ModerationEngine(hash_threshold=5)
        bad_hash = compute_dhash(data)
        engine.add_known_bad_hash(bad_hash)
        result = engine.screen(data)
        assert result.verdict == ModerationVerdict.REJECT
        assert result.reason == RejectionReason.KNOWN_BAD_HASH

    def test_near_duplicate_caught(self) -> None:
        """A slightly modified version of known-bad content is also caught."""
        data = b"A" * 512
        engine = ModerationEngine(hash_threshold=15)
        engine.add_known_bad_hash(compute_dhash(data))
        variant = bytearray(data)
        variant[200] = ord("Z")
        result = engine.screen(bytes(variant))
        assert result.verdict == ModerationVerdict.REJECT

    def test_reject_blocked_pattern(self) -> None:
        engine = ModerationEngine()
        engine.add_blocked_pattern("forbidden_phrase")
        result = engine.screen(b"this contains a forbidden_phrase inside")
        assert result.verdict == ModerationVerdict.REJECT
        assert result.reason == RejectionReason.BLOCKED_PATTERN

    def test_skip_pattern_check_when_encrypted(self) -> None:
        engine = ModerationEngine()
        engine.add_blocked_pattern("forbidden_phrase")
        result = engine.screen(
            b"this contains a forbidden_phrase inside", is_encrypted=True
        )
        assert result.verdict == ModerationVerdict.PASS

    def test_pattern_case_insensitive(self) -> None:
        engine = ModerationEngine()
        engine.add_blocked_pattern("bad_word")
        result = engine.screen(b"Some BAD_WORD here")
        assert result.verdict == ModerationVerdict.REJECT

    def test_add_known_bad_hash_case_insensitive(self) -> None:
        engine = ModerationEngine()
        engine.add_known_bad_hash("ABCDEF")
        assert "abcdef" in engine.known_bad_hashes

    def test_size_check_runs_first(self) -> None:
        """Even if content matches a pattern, size is checked first."""
        engine = ModerationEngine(max_payload_bytes=10)
        engine.add_blocked_pattern("bad")
        result = engine.screen(b"bad" * 100)
        assert result.reason == RejectionReason.PAYLOAD_TOO_LARGE
