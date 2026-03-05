// polis/crypto/src/lib.rs
//! Polis cryptographic primitives.
//!
//! This crate provides the performance-critical cryptographic operations
//! for the Polis protocol stack:
//!
//! - **signing**: Ed25519 signing and verification
//! - **hashing**: SHA-256 content addressing and BLAKE3 for performance paths
//! - **did**: DID generation and resolution helpers
//! - **zkp**: Zero-knowledge proof interface (future)

pub mod did;
pub mod hashing;
pub mod signing;
pub mod zkp;
