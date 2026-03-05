# Polis Network Specification — v0.1

## Overview

Polis nodes form a peer-to-peer network for identity resolution,
record propagation, and distributed verification. In v0.1, nodes
communicate via HTTP(S) with DID-signed requests.

## Node Discovery

- Peers are configured via the `POLIS_PEERS` environment variable.
- Dynamic peer discovery is planned for future versions.
- Nodes can add peers at runtime via `POST /node/peers/connect`.

## Inter-Node Communication

### Transport Security (Invariant 20)
- All inter-node communication uses TLS 1.3 minimum in production.
- Development nodes (prefixed `dev-`) may use HTTP for local testing.

### Request Authentication (Invariant 21)
- Every inter-node request includes:
  - `X-Polis-Node-DID`: The requesting node's DID.
  - `X-Polis-Timestamp`: Unix timestamp of the request.
  - `X-Polis-Signature`: Ed25519 signature of `METHOD|URL|TIMESTAMP`.

### Record Propagation
- When a record is created, the originating node propagates it to all
  known peers via `POST /records/ingest`.
- Receiving nodes independently verify the record signature before storing
  (Invariant 22).
- Propagation is best-effort — individual peer failures do not block
  the creation response.

### Identity Resolution
- In v0.1, DID resolution is local to each node.
- Inter-node DID resolution is planned for future versions.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/node/status` | Node health and statistics |
| GET | `/node/peers` | List configured peers |
| POST | `/node/peers/connect` | Add a peer |
| POST | `/records/ingest` | Accept a record from a peer |

## Invariants

- **Invariant 19:** No single point of failure.
- **Invariant 20:** Transport uses TLS 1.3 minimum.
- **Invariant 21:** All inter-node requests are signed.
- **Invariant 22:** Nodes verify all incoming records independently.
