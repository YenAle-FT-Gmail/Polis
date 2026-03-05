# Polis Storage Specification — v0.1

## Overview

Polis uses content-addressed storage where every piece of data is identified
by a CID (Content Identifier) derived from its SHA-256 hash. Storage backends
are interchangeable — the CID is the same regardless of where data is stored.

## Storage Backends

### Local Filesystem (v0.1 — Development)
- Data stored as files named by CID in a configurable directory.
- Integrity verified on every retrieval.

### IPFS (Planned)
- Communicates with a local IPFS daemon via HTTP API.
- CID computed using SHA-256 multihash (IPFS standard).

### Arweave (Planned)
- Permanent, immutable storage via the Arweave gateway.
- Data is permanent by design — no pinning needed.

## Invariants

- **Invariant 23:** Storage backends are interchangeable. CID is backend-independent.
- **Invariant 24:** CID generation uses SHA-256 multihash (IPFS standard).
- **Invariant 25:** Data integrity is verified on every `get` operation.

## CID Format

```
01551220<sha256-hex-digest>
```

Where `01` = CIDv1 version, `55` = raw binary codec, `12` = SHA-256 multihash code, `20` = digest length (32 bytes).

## API

```python
class StorageBackend(ABC):
    async def put(data: bytes) -> str       # Store and return CID
    async def get(cid: str) -> bytes        # Retrieve with integrity check
    async def pin(cid: str) -> bool         # Ensure persistence
    async def is_available(cid: str) -> bool # Check availability
```
