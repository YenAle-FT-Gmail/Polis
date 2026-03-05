# Polis — Coding Agent Master Prompt
## Instructions for AI Coding Agents Working on This Codebase

---

## What You Are Building

You are building **Polis** — a new internet infrastructure protocol stack. Not an application. Not a service. A protocol. Like HTTP, but for identity, attribution, data sovereignty, and accountability simultaneously.

The governing principle that overrides every technical decision:

> **Information flows freely. Every interaction is permanently attributed to its cryptographic author. Accountability is mathematically equal for all actors. No single entity controls the system. These guarantees are enforced by code, not policy.**

You are not building a blockchain. You are not building a social network. You are building the substrate that makes both possible without any central authority.

---

## Environment

- **OS:** macOS (Apple Silicon / M1 Mac Mini)
- **Python:** 3.11
- **Primary languages:** Python 3.11 (orchestration, node logic, API), Rust (performance-critical cryptographic and networking components)
- **Package management:** Poetry (Python), Cargo (Rust)
- **Containerization:** Docker + Docker Compose for local multi-node testing
- **Version control:** Git, conventional commits
- **Testing:** pytest (Python), cargo test (Rust), minimum 80% coverage on all core modules
- **Always add a commented filepath at the top of every file**
- **Architecture:** Simple and scalable. No premature optimization. No unnecessary abstraction layers. One thing done well is better than ten things done poorly.

---

## Context For Every Session

At the start of every coding session, re-read:
1. This file (AGENT.md)
2. INVARIANTS.md
3. The specification file for the module being worked on

The invariants are not suggestions. If an implementation decision would violate an invariant, the decision is wrong — not the invariant.
