// polis/crypto/src/hashing.rs
//! Content addressing and hashing utilities.
//!
//! SHA-256 for content addressing (IPFS standard multihash),
//! BLAKE3 for performance-critical internal paths.

use sha2::{Digest, Sha256};

/// Compute a SHA-256 hash and return as a hex string with CIDv1 multihash prefix.
///
/// Format: `01551220<sha256-hex-digest>`
/// - `01` = CIDv1 version
/// - `55` = raw binary codec
/// - `12` = SHA-256 (multihash table)
/// - `20` = 32 bytes digest length
///
/// # Arguments
/// * `data` - The bytes to hash.
///
/// # Returns
/// Hex-encoded CIDv1 SHA-256 multihash string.
pub fn sha256_multihash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("01551220{}", hex::encode(result))
}

/// Compute a SHA-256 hash and return as a hex string.
///
/// # Arguments
/// * `data` - The bytes to hash.
///
/// # Returns
/// Hex-encoded SHA-256 digest.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Compute a BLAKE3 hash and return as a hex string.
///
/// BLAKE3 is used for performance-critical internal operations
/// where IPFS compatibility is not required.
///
/// # Arguments
/// * `data` - The bytes to hash.
///
/// # Returns
/// Hex-encoded BLAKE3 digest.
pub fn blake3_hex(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    hash.to_hex().to_string()
}

/// Verify that data matches an expected SHA-256 multihash CID.
///
/// # Arguments
/// * `cid` - The expected CID (hex-encoded SHA-256 multihash).
/// * `data` - The data to verify.
///
/// # Returns
/// `true` if the data matches the CID.
pub fn verify_integrity(cid: &str, data: &[u8]) -> bool {
    sha256_multihash(data) == cid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_multihash_deterministic() {
        let data = b"deterministic content";
        assert_eq!(sha256_multihash(data), sha256_multihash(data));
    }

    #[test]
    fn test_sha256_multihash_prefix() {
        let cid = sha256_multihash(b"test");
        assert!(cid.starts_with("01551220"));
    }

    #[test]
    fn test_sha256_different_data() {
        assert_ne!(sha256_multihash(b"data a"), sha256_multihash(b"data b"));
    }

    #[test]
    fn test_blake3_deterministic() {
        let data = b"test data";
        assert_eq!(blake3_hex(data), blake3_hex(data));
    }

    #[test]
    fn test_verify_integrity_valid() {
        let data = b"valid data";
        let cid = sha256_multihash(data);
        assert!(verify_integrity(&cid, data));
    }

    #[test]
    fn test_verify_integrity_tampered() {
        let cid = sha256_multihash(b"original");
        assert!(!verify_integrity(&cid, b"tampered"));
    }
}
