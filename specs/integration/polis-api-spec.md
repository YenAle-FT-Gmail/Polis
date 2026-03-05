# Polis API Integration Specification — v0.1

## Overview

The Polis node exposes a REST API via FastAPI for identity management,
record creation, and inter-node communication.

## Base URL

Default: `http://localhost:8000` (development)

## Endpoints

### Identity (`/identity`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/identity/create` | Create a new Polis identity |
| GET | `/identity/{did}` | Resolve a DID Document |
| POST | `/identity/{did}/rotate-key` | Rotate the signing key |

### Records (`/records`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/records/create` | Create an attribution record |
| GET | `/records/{cid}` | Retrieve a record by CID |
| GET | `/records/by-author/{did}` | List records by author |
| POST | `/records/{cid}/grant` | Grant selective access |
| POST | `/records/{cid}/revoke` | Revoke a permission token |
| POST | `/records/ingest` | Ingest an external record |
| POST | `/records/{cid}/access` | Present a permission token to access content |

### Node (`/node`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/node/status` | Node health and statistics |
| GET | `/node/peers` | List connected peers |
| POST | `/node/peers/connect` | Add a new peer |

## Authentication

- Identity creation does not require authentication.
- Record creation requires the author's identity to be registered on the node.
- Inter-node requests include DID-signed headers (see network spec).

## Error Format

All errors follow the structure:
```json
{
  "error": "error_code",
  "message": "Human-readable description",
  "did": "optional context field"
}
```
