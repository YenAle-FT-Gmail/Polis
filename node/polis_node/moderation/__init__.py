# polis/node/polis_node/moderation/__init__.py
"""
Polis Moderation Module.

Provides community-driven, transparent, and permanently attributed
content moderation. All moderation actions are Attribution Records
signed by the moderator's DID.

Components:
- ``engine.ModerationEngine``: Protocol-level content pre-screening
  (Invariant 6: CSAM detection, perceptual hashing, keyword filters).
- Future: moderation record types (label, appeal, report).

See specs/moderation/polis-moderation-spec.md.
"""

from polis_node.moderation.engine import (
    ModerationEngine,
    ModerationResult,
    ModerationVerdict,
    RejectionReason,
    compute_dhash,
    hamming_distance,
)

__all__ = [
    "ModerationEngine",
    "ModerationResult",
    "ModerationVerdict",
    "RejectionReason",
    "compute_dhash",
    "hamming_distance",
]
