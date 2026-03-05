// polis/crypto/src/signing.rs
//! Ed25519 signing and verification.
//!
//! Uses ed25519-dalek for all signing operations. Keys are generated
//! using OS-level CSPRNG via rand_core::OsRng.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

/// Generate a new Ed25519 signing keypair using OS-level CSPRNG.
///
/// # Returns
/// A tuple of (signing_key, verifying_key) as raw byte arrays.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key.to_bytes(), verifying_key.to_bytes())
}

/// Sign a message with an Ed25519 signing key.
///
/// # Arguments
/// * `signing_key_bytes` - 32-byte Ed25519 signing key seed
/// * `message` - The message bytes to sign
///
/// # Returns
/// A 64-byte Ed25519 signature.
pub fn sign(signing_key_bytes: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(signing_key_bytes);
    let signature: Signature = signing_key.sign(message);
    signature.to_bytes()
}

/// Verify an Ed25519 signature.
///
/// # Arguments
/// * `verifying_key_bytes` - 32-byte Ed25519 verifying (public) key
/// * `message` - The original message bytes
/// * `signature_bytes` - 64-byte Ed25519 signature
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
pub fn verify(verifying_key_bytes: &[u8; 32], message: &[u8], signature_bytes: &[u8; 64]) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(verifying_key_bytes) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (signing, verifying) = generate_keypair();
        assert_eq!(signing.len(), 32);
        assert_eq!(verifying.len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let (signing_key, verifying_key) = generate_keypair();
        let message = b"Hello, Polis!";
        let signature = sign(&signing_key, message);
        assert!(verify(&verifying_key, message, &signature));
    }

    #[test]
    fn test_verify_wrong_message() {
        let (signing_key, verifying_key) = generate_keypair();
        let signature = sign(&signing_key, b"original");
        assert!(!verify(&verifying_key, b"tampered", &signature));
    }

    #[test]
    fn test_verify_wrong_key() {
        let (signing_key_a, _) = generate_keypair();
        let (_, verifying_key_b) = generate_keypair();
        let signature = sign(&signing_key_a, b"test");
        assert!(!verify(&verifying_key_b, b"test", &signature));
    }
}
