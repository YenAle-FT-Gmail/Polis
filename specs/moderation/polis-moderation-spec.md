# Polis Moderation Specification — v0.1

## Overview

Polis moderation operates under the principle that accountability is
mathematically equal for all actors. Moderation is not censorship —
it is community-driven, transparent, and permanently attributed.

## Design Principles

1. **Every moderation action is an Attribution Record.** Moderation
   decisions are signed by the moderator's DID and permanently attributed.
2. **No anonymous moderation.** All moderation actions are publicly linked
   to the moderator's identity.
3. **Moderation is additive, not destructive.** Content is never deleted —
   moderation labels are added alongside content.
4. **Users choose their moderation view.** Clients can subscribe to
   different moderation label sets.

## Planned Record Types

| Type | Description |
|------|-------------|
| `polis.moderation.label` | A label applied to content by a moderator |
| `polis.moderation.appeal` | An appeal of a moderation decision |
| `polis.moderation.report` | A user report of content |

## Status

Moderation module is scaffolded but not implemented in v0.1.
The interface will be defined in Phase 2.
