// polis/crypto/src/did.rs
//! DID generation and resolution helpers.
//!
//! Computes Polis DID identifiers from Ed25519 public keys.
//! DID format: did:polis:<base58btc-encoded-sha256-fingerprint>

use sha2::{Digest, Sha256};

/// The Polis DID method prefix.
const DID_PREFIX: &str = "did:polis:";

/// Generate a Polis DID from a raw Ed25519 public key.
///
/// The fingerprint is the Base58btc encoding of the SHA-256 hash
/// of the public key bytes.
///
/// # Arguments
/// * `public_key` - 32-byte Ed25519 public key.
///
/// # Returns
/// A fully qualified DID string.
pub fn generate_did(public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let digest = hasher.finalize();
    let fingerprint = bs58::encode(digest).into_string();
    format!("{}{}", DID_PREFIX, fingerprint)
}

/// Extract the fingerprint portion from a Polis DID.
///
/// # Arguments
/// * `did` - A Polis DID string.
///
/// # Returns
/// The Base58btc fingerprint, or None if the DID is malformed.
pub fn extract_fingerprint(did: &str) -> Option<&str> {
    did.strip_prefix(DID_PREFIX)
}

/// Validate that a string is a well-formed Polis DID.
///
/// # Arguments
/// * `did` - The string to validate.
///
/// # Returns
/// `true` if the string is a valid Polis DID format.
pub fn is_valid_did(did: &str) -> bool {
    if let Some(fingerprint) = extract_fingerprint(did) {
        !fingerprint.is_empty() && bs58::decode(fingerprint).into_vec().is_ok()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_keypair;

    #[test]
    fn test_generate_did_format() {
        let (_, public_key) = generate_keypair();
        let did = generate_did(&public_key);
        assert!(did.starts_with("did:polis:"));
    }

    #[test]
    fn test_generate_did_deterministic() {
        let (_, public_key) = generate_keypair();
        assert_eq!(generate_did(&public_key), generate_did(&public_key));
    }

    #[test]
    fn test_extract_fingerprint() {
        let (_, public_key) = generate_keypair();
        let did = generate_did(&public_key);
        let fingerprint = extract_fingerprint(&did);
        assert!(fingerprint.is_some());
        assert!(!fingerprint.unwrap().is_empty());
    }

    #[test]
    fn test_is_valid_did() {
        let (_, public_key) = generate_keypair();
        let did = generate_did(&public_key);
        assert!(is_valid_did(&did));
    }

    #[test]
    fn test_invalid_did() {
        assert!(!is_valid_did("not:a:polis:did"));
        assert!(!is_valid_did("did:polis:"));
        assert!(!is_valid_did(""));
    }
}
