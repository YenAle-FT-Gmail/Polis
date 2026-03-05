# Polis — System Invariants

These invariants are absolute. They are never violated, never "temporarily" bypassed, never deferred to a later version. If an implementation decision would violate an invariant, the decision is wrong — not the invariant.

---

## Identity Invariants

1. **A Polis DID is permanent.** Once created, a DID string never changes regardless of key rotation, recovery, or any other operation.
2. **Every DID is derived deterministically** from its initial Ed25519 public key fingerprint. Given the same key, the same DID is always produced.
3. **Recovery keys never touch the network.** They are generated locally, serialized to a BIP-39 mnemonic, and stored offline by the user. No node ever transmits or stores a recovery private key.
4. **Key rotation preserves the DID.** Only the signing key changes; the DID identifier remains the same.
5. **All key material is generated using OS-level CSPRNG** (`secrets` module in Python, `getrandom` in Rust). The use of `random.random()` or any non-cryptographic RNG for security-relevant operations is a critical defect.

---

## Attribution Invariants

6. **Every piece of content or action is an Attribution Record.** There are no anonymous operations in Polis. Every action is permanently attributed to its cryptographic author.
7. **Attribution Records are atomic.** A record either exists with a valid signature or does not exist. There is no intermediate state.
8. **No unsigned record is ever stored or propagated.** Unsigned or invalidly signed records are rejected at ingest.
9. **Canonical serialization is inviolable.** Records are serialized to canonical JSON (RFC 8785 / JCS) before signing. This ensures identical signing across all implementations.
10. **Timestamps are always UTC, always ISO 8601.**

---

## Privacy Invariants

11. **Private records are encrypted before CID computation.** The CID of a private record is computed over the ciphertext, never the plaintext.
12. **Visibility is enforced cryptographically, not by policy.** There is no access control list that can be bypassed — if you don't have the decryption key, you cannot read the content.
13. **Permission tokens have mandatory expiry.** No permanent access grants exist. Access must be periodically renewed.
14. **Revocation is immediate and enforced.** A revoked permission token ceases to function immediately; no grace periods.

---

## Cryptographic Invariants

15. **No custom cryptographic algorithms.** All cryptography uses established, audited libraries (cryptography, ed25519-dalek, aes-gcm).
16. **All signing and encryption modules sit behind algorithm-agnostic interfaces.** This enables post-quantum algorithm substitution (ML-DSA, ML-KEM) without changing calling code.
17. **Keys never leave the node unencrypted.** Private key material stored on disk must be encrypted. Private key material in transit must be encrypted.
18. **Secrets are never logged.** No key material, tokens, signatures, or private data appears in any log output at any log level.

---

## Network Invariants

19. **No single point of failure.** No singleton services, no required central coordinators, no authority nodes.
20. **Transport between nodes uses TLS 1.3 minimum.**
21. **All inter-node requests are signed by the requesting node's DID.** There are no anonymous inter-node communications.
22. **Nodes verify all incoming records independently.** No node trusts another node's verification — every node re-verifies every record it receives.

---

## Storage Invariants

23. **Storage backends are interchangeable.** The CID of a record is the same regardless of which storage backend holds the data.
24. **CID generation uses SHA-256 multihash (IPFS standard).**
25. **Data integrity is verified on retrieval.** Every `get` operation verifies the retrieved data matches the requested CID.

---

## Code Quality Invariants

26. **Every file starts with a commented filepath.**
27. **Type hints on every function signature.** No untyped public interfaces.
28. **Docstrings on every public function and class.**
29. **No magic numbers.** All constants are named and documented.
30. **No global mutable state.**
31. **Async by default for all I/O operations.**
32. **Error messages are actionable.** They describe what failed, why, and what the caller can do about it.
