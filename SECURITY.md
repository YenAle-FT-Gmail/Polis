# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@polis-protocol.org** with:

1. A description of the vulnerability.
2. Steps to reproduce or a proof-of-concept.
3. The affected component(s) and version(s).
4. Your assessment of severity (Critical / High / Medium / Low).

We will acknowledge receipt within **48 hours** and aim to provide a fix
or mitigation plan within **7 days** for critical issues.

## Scope

The following components are in scope:

- `node/` — the Polis Node daemon (Python / FastAPI)
- `crypto/` — the Polis cryptographic primitives (Rust)
- `client/` — the Polis client SDK (Python)
- Protocol specifications in `specs/`

## Responsible Disclosure

We follow a **90-day** coordinated disclosure policy. After a fix is
released, we will publish a security advisory on GitHub.

## Security Invariants

See [INVARIANTS.md](INVARIANTS.md) for the protocol's hardcoded safety
properties. Any violation of these invariants is considered a critical
security issue.
