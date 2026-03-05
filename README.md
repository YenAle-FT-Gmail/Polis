# Polis
## A New Internet Infrastructure for Free Flow of Information, Permanent Attribution, and Equal Accountability

---

## Vision

The modern web is structurally broken. Data about people is treated as property of whoever collects it. Surveillance is asymmetric — the powerful watch the powerless with zero reciprocal accountability. Centralized platforms control identity, content, and access. This is not an accident. It is the architectural consequence of building the web around location-addressed, server-dependent, corporately-hosted infrastructure.

Polis is a ground-up replacement of that architecture. Not an app built on top of the broken web. A new substrate beneath it.

The governing principle is singular and non-negotiable:

> **Information flows freely. Every interaction with that information is permanently and cryptographically attributed to its author. Accountability is equal for all actors regardless of wealth, political power, or institutional status. No single entity controls, surveils, or selectively enforces the system. These guarantees are enforced by mathematics, not by institutions.**

---

## The Four Problems Being Solved

### 1. Mass Surveillance
Centralized ISPs, DNS providers, CDNs, and cloud providers create choke points that governments and corporations tap or coerce. Every packet you send carries metadata that reveals who you are and what you are doing simultaneously.

### 2. Unaccountable Abuse of Personal Data
Data about people — faces, biometrics, behavioral patterns, private images — is harvested without consent and used without consequence. The Epstein network's use of scraped yearbook photos as a catalog is the extreme expression of a systemic architectural failure. The data was publicly accessible because the web's architecture made it so.

### 3. Centralized Content Control
Five corporations control what five billion people see, say, and find online. Content moderation is opaque, inconsistent, and subject to political and financial pressure. There is no appeal. There is no equal treatment.

### 4. Identity Owned by Platforms
Your online identity belongs to the platform that hosts it. They can delete it, modify it, sell it, or hand it to a government. You have no cryptographic ownership of who you are online.

---

## The Core Principle: Equal Treatment Under Mathematics

The system does not have institutional hierarchies. A private citizen and a head of state are subject to identical rules enforced by identical code. Wealth cannot buy exemption. Political power cannot buy opacity. The same cryptographic accountability that applies to a teenager posting online applies to a billionaire, a corporation, and a government agency.

**Published data** — what you choose to share — flows freely, is permanently attributed to you, and is yours to revoke or maintain.

**Personal data** — what exists about you that you never chose to publish — is structurally inaccessible to any party without your explicit cryptographic consent.

---

## Architecture Overview

Polis is a layered protocol stack. Each layer is independently functional but designed for deep integration with every other layer. No layer requires blockchain for its core function. Cryptographic ledgers are used strictly as minimal, neutral trust anchors for identity resolution and dispute arbitration — never as data stores.

```
┌─────────────────────────────────────────────────────┐
│                  APPLICATION LAYER                   │
│         Social · Publishing · Messaging · Commerce   │
│         Any application built on Polis primitives    │
├─────────────────────────────────────────────────────┤
│                  MODERATION LAYER                    │
│    Decentralized labeling · Edge AI inference        │
│    Perceptual hashing · Reputation-weighted gossip   │
│    Community-governed · No central override          │
├─────────────────────────────────────────────────────┤
│                  IDENTITY LAYER                      │
│    Universal DID · Zero-Knowledge Proofs             │
│    Verifiable Credentials · Selective disclosure     │
│    Pseudonymous accountability · Sybil resistance    │
├─────────────────────────────────────────────────────┤
│                  STORAGE LAYER                       │
│    Content-addressed (IPFS/Arweave) · Solid Pods     │
│    User-controlled encryption at rest                │
│    Confidential Computing / TEEs                     │
│    Permanent attribution via signed repositories     │
├─────────────────────────────────────────────────────┤
│                  NETWORK LAYER                       │
│    Mixnet routing (Nym/Sphinx) · Tor fallback        │
│    Mesh networking (Althea/Meshtastic)               │
│    DePIN physical infrastructure                     │
│    Post-quantum hybrid cryptography                  │
└─────────────────────────────────────────────────────┘
         ↕ Trust Anchor: Minimal cryptographic ledger
           Identity resolution · Dispute arbitration only
```

---

## The Seven Gaps This Project Closes

### Gap 1 — Universal Identity Primitive
**Problem:** Every existing layer has its own identity system. AT Protocol uses DIDs. Ethereum uses wallets. Solid uses WebID. None interoperate natively.
**Solution:** A single cryptographic identity primitive — a Polis DID — that works identically across network routing, storage access, content attribution, and accountability enforcement. Built on W3C DID Core but extended for cross-layer interoperability.

### Gap 2 — Private and Public Data in One System
**Problem:** AT Protocol is optimized for public broadcasting. Solid is optimized for private data. No production system allows selective publication — sharing some things openly with full attribution while keeping other things structurally inaccessible — within one unified architecture.
**Solution:** A unified data model with per-record visibility controls enforced cryptographically. Public records are signed and broadcast. Private records are encrypted with user-held keys and only accessible via explicit permission tokens with defined scope and expiry.

### Gap 3 — Decentralized Moderation at Scale
**Problem:** Distributed AI moderation exists in research papers but not in production. Bluesky's labeling marketplace re-centralizes in practice because users default to the dominant labeling service.
**Solution:** A gossip-protocol verdict propagation system where quantized local LLMs classify content, produce signed verdicts, and broadcast them peer-to-peer. Verdicts are weighted by node reputation accumulated over time. No single labeling authority. Perceptual hashing for known illegal content (CSAM) propagated as a protocol-level invariant — not optional, not bypassable.

### Gap 4 — Sybil Resistance Without Economic Exclusion
**Problem:** All current Sybil resistance mechanisms either require staking capital (excluding the poor) or require centralized identity verification (destroying privacy).
**Solution:** Bayesian mechanism design (Lenzi 2024) mathematically guarantees that splitting stake across Sybil accounts produces negative expected utility for the attacker. Combined with time-weighted reputation accumulation — reputation that cannot be bought, only earned through consistent behavior — the system achieves Sybil resistance accessible to anyone regardless of capital.

### Gap 5 — The Integration Layer
**Problem:** No common API, unified node software, or single coherent system connects physical mesh networking, content-addressed storage, cryptographic identity, and decentralized moderation. Each exists as an isolated project.
**Solution:** The Polis Node — a single piece of software that participates in all layers simultaneously. Runs on a Raspberry Pi. Speaks to every layer through a unified internal API. Is the integration layer.

### Gap 6 — Usability
**Problem:** Every existing system requires technical sophistication. Managing cryptographic keys, running a personal data server, choosing labeling services — none of this is accessible to ordinary people.
**Solution:** The Polis Client — a front-end that abstracts all cryptographic complexity behind interactions as simple as any existing social application. Key management is automatic. Data sovereignty is the default, not a setting. The user never needs to understand what a DID is to benefit from having one.

### Gap 7 — Political Resilience
**Problem:** Governments are actively drafting regulation to mandate KYC on exit nodes, mixnets, and decentralized storage providers. No coordinated legal defense exists at the scale required.
**Solution:** A nonprofit foundation structure modeled on the Tor Project. Open source everything under a maximally permissive license. Legal defense built in from day one. Jurisdiction diversification for node operators. RFC-style open governance — no token, no corporation, rough consensus and code.

---

## What Already Exists (Not Being Rebuilt)

Polis is integration, not invention from scratch. The cryptographic primitives are proven and production-tested.

| Primitive | Existing Implementation | Polis Usage |
|---|---|---|
| Content-addressed storage | IPFS, Arweave | Storage layer |
| Decentralized identity | W3C DID Core | Identity layer foundation |
| Cryptographic signing | Ed25519, secp256k1 | Attribution on every record |
| Zero-knowledge proofs | ZK-SNARKs, ZK-STARKs | Accountability without surveillance |
| Mixnet routing | Nym / Sphinx packet format | Network anonymity layer |
| Selective disclosure | W3C Verifiable Credentials | Minimum necessary disclosure |
| Local AI inference | llama.cpp, GGUF quantization | Edge moderation |
| Mesh networking | Althea, Meshtastic | Physical layer independence |
| Federated data streams | AT Protocol | Public broadcast layer |
| Personal data stores | Solid Pods | Private data layer |
| Perceptual hashing | PDQ, NeuralHash equivalents | CSAM detection |
| Biometric protection | Cancelable biometrics + FHE | Structural harvesting prevention |
| Sybil resistance | Bayesian mechanism (Lenzi 2024) | Equal participation |
| Post-quantum crypto | HPQKE, ML-KEM + ECDHE | Future-proof transport |

---

## Invariants — The Non-Negotiable Truths

These are the properties that must always be true regardless of implementation decisions, optimizations, or external pressure. Every architectural decision is evaluated against these invariants. Any design that violates one is rejected.

1. **No single point of control.** No entity — including the creators of Polis — can unilaterally modify, censor, or surveil the network.
2. **Equal treatment.** The same rules execute identically for a private citizen and a head of state. Wealth and power purchase no exemption.
3. **Attribution is permanent.** Every published action is cryptographically signed. It cannot be denied, forged, or erased.
4. **Personal data is structurally protected.** Data you did not choose to publish is mathematically inaccessible without your explicit consent. This is not a policy. It is an architectural guarantee.
5. **Free flow of information.** The network does not restrict what can be published. It restricts what can be *done* to others' data without consent.
6. **CSAM detection is a protocol invariant.** Detection of known child sexual abuse material is not optional, not bypassable, and not governed by community preference. It is hardcoded at the protocol level.
7. **No economic exclusion.** Participating in the network's governance and accountability mechanisms does not require capital. The system is accessible to anyone with a device and a connection.
8. **Open source, always.** Every line of code, every protocol specification, every governance document is public, auditable, and forkable.

---

## Governance Model

Polis is governed by rough consensus and running code, modeled on IETF RFC 7282. There is no token. There is no corporation. There is no founding team veto.

Protocol changes are proposed via open RFCs. Changes require:
- A working implementation
- No unaddressed substantive technical objections
- Rough consensus among active contributors — not majority vote

A nonprofit foundation holds the trademark and funds legal defense. It does not control the protocol. The protocol is controlled by its specification and its implementations.

---

## Roadmap

### Phase 0 — Foundation (Now)
- Technical literacy in all five core primitives: DIDs, ZKPs, content-addressed storage, cryptographic signing, federated networking
- Written protocol specification for the unified identity primitive
- Invariants document (this document)
- Private repository established

### Phase 1 — Proof of Concept
- Polis Node v0.1: two nodes, one identity, one piece of content
- Permanently attributed, structurally private unless explicitly shared
- Demonstrates the integration layer functioning end-to-end
- Published openly, MIT licensed

### Phase 2 — Protocol Specification
- Full Polis Protocol RFC published
- External cryptographic review
- Community formation around the specification

### Phase 3 — Production Node Software
- Polis Node v1.0: all layers integrated
- Runs on Raspberry Pi 4 or equivalent
- Single install, unified API

### Phase 4 — Client and Foundation
- Polis Client v1.0: zero-complexity user interface
- Nonprofit foundation established
- Legal defense infrastructure in place

---

## Reading List — Technical Foundations

**Specifications (primary sources):**
- AT Protocol Specification — atproto.com/specs/atp
- W3C DID Core — w3.org/TR/did-core
- W3C Verifiable Credentials 2.0 — w3.org/TR/vc-data-model-2.0
- IETF RFC 7282 — On Consensus and Humming in the IETF
- Nym Whitepaper — nymtech.net

**Academic Papers:**
- Lenzi (2024) — Bayesian Mechanism Design for Sybil Resistance
- Kleppmann et al. (2024) — Bluesky and the AT Protocol: Usable Decentralized Social Media
- W3C STS Framework for Decentralized Identity

**Books:**
- Preukschat & Reed — Self-Sovereign Identity (Manning, 2021)
- Antonopoulos & Wood — Mastering Ethereum
- Diffie & Hellman — New Directions in Cryptography (original 1976 paper)

**Critical Perspectives (read these especially):**
- Molly White — web3isgoinggreat.com
- Stanford Internet Observatory — decentralization failure modes
- David Gerard — Attack of the 50 Foot Blockchain

---

## Repository Structure

```
polis/
├── README.md                  ← This document
├── INVARIANTS.md              ← The non-negotiable truths
├── GOVERNANCE.md              ← How decisions are made
├── specs/
│   ├── identity/              ← Polis DID specification
│   ├── storage/               ← Storage layer specification
│   ├── network/               ← Network layer specification
│   ├── moderation/            ← Moderation layer specification
│   └── integration/           ← Cross-layer API specification
├── research/
│   ├── existing-primitives/   ← Analysis of what we build on
│   ├── gap-analysis/          ← Detailed gap documentation
│   └── papers/                ← Key academic references
├── node/                      ← Polis Node implementation
├── client/                    ← Polis Client implementation
└── foundation/                ← Legal and governance documents
```

---

*Polis is infrastructure for humanity. It is owned by no one. It serves everyone equally. It is governed by mathematics and rough consensus. It will outlast its creators.*
