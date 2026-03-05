# Polis DID Specification

## Overview

A Polis DID is a W3C DID Core compliant identifier using the `polis` method.

## Format

```
did:polis:<base58btc-encoded-sha256-fingerprint-of-initial-signing-public-key>
```

## DID Document Structure

Each DID Document contains:
- `signingKey`: Ed25519 public key for daily operations
- `recoveryKey`: Ed25519 public key held offline by user
- `storageEndpoint`: URI of the user's primary data store
- `created`: ISO 8601 timestamp
- `updated`: ISO 8601 timestamp

## Key Properties

- DIDs are permanent — they never change regardless of key rotation
- DIDs are derived deterministically from the initial Ed25519 public key
- Recovery keys never touch the network
- Recovery keys are serializable to BIP-39 mnemonic phrases
- Key rotation preserves the DID
