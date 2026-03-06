// polis/crypto/src/zkp.rs
//! Zero-Knowledge Proof primitives.
//!
//! Implements a Schnorr-style proof of knowledge of a discrete log
//! over the Ed25519 curve.  This allows a prover to demonstrate that
//! they possess the private key corresponding to a public key **without
//! revealing the private key itself**.
//!
//! Protocol (Σ-protocol / Schnorr identification):
//!
//! 1. **Commit**: Prover picks random scalar `k`, computes `R = k·G`.
//! 2. **Challenge**: Hash `R || public_key || message` → scalar `e`.
//! 3. **Response**: Compute `s = k - e·x`  (mod group order).
//! 4. **Verify**: Check that  `s·G + e·PK == R`.
//!
//! The proof is non-interactive (Fiat-Shamir heuristic via SHA-512
//! reduced to a scalar mod ℓ).

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha512};

/// A Schnorr zero-knowledge proof of knowledge of a private key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SchnorrProof {
    /// The commitment point `R` (compressed Edwards Y, 32 bytes hex).
    pub commitment: String,
    /// The response scalar `s` (32 bytes little-endian hex).
    pub response: String,
    /// The message that was bound into the challenge.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derive the Schnorr challenge scalar: e = H(R || PK || msg) mod ℓ.
fn challenge_scalar(r_compressed: &[u8; 32], pk_compressed: &[u8; 32], message: &str) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(r_compressed);
    hasher.update(pk_compressed);
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    // from_bytes_mod_order_wide reduces a 64-byte hash mod ℓ (group order)
    Scalar::from_bytes_mod_order_wide(&hash.into())
}

/// Clamp a 32-byte seed into an Ed25519 private scalar the same way
/// `ed25519-dalek` does (see RFC 8032 §5.1.5).
fn private_scalar_from_seed(seed: &[u8; 32]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(seed);
    let hash = hasher.finalize();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    Scalar::from_bytes_mod_order(scalar_bytes)
}

/// Compute the public point from a seed (matching ed25519-dalek).
fn public_point_from_seed(seed: &[u8; 32]) -> EdwardsPoint {
    let x = private_scalar_from_seed(seed);
    &x * ED25519_BASEPOINT_TABLE
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a Schnorr ZK proof that the caller knows the private key
/// behind `public_key_bytes`, binding the proof to `message`.
///
/// # Arguments
/// * `private_key_bytes` – 32-byte Ed25519 private key seed.
/// * `message` – Arbitrary context string bound into the proof.
///
/// # Returns
/// A `SchnorrProof` that can be verified with [`verify_proof`].
pub fn generate_proof(private_key_bytes: &[u8; 32], message: &str) -> SchnorrProof {
    let x = private_scalar_from_seed(private_key_bytes);
    let pk_point: EdwardsPoint = &x * ED25519_BASEPOINT_TABLE;
    let pk_compressed = pk_point.compress().to_bytes();

    // Step 1: random nonce k, commitment R = k·G
    let mut nonce_bytes = [0u8; 64];
    OsRng.fill_bytes(&mut nonce_bytes);
    let k = Scalar::from_bytes_mod_order_wide(&nonce_bytes);
    let r_point: EdwardsPoint = &k * ED25519_BASEPOINT_TABLE;
    let r_compressed = r_point.compress().to_bytes();

    // Step 2: Fiat-Shamir challenge e = H(R || PK || message) mod ℓ
    let e = challenge_scalar(&r_compressed, &pk_compressed, message);

    // Step 3: response s = k - e·x (mod ℓ)
    let s = k - e * x;

    SchnorrProof {
        commitment: hex::encode(r_compressed),
        response: hex::encode(s.to_bytes()),
        message: message.to_string(),
    }
}

/// Verify a Schnorr ZK proof against a public key.
///
/// Checks the algebraic relation: `s·G + e·PK == R`.
///
/// # Arguments
/// * `proof` – The proof to verify.
/// * `public_key_bytes` – 32-byte compressed Edwards Y public key.
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise.
pub fn verify_proof(proof: &SchnorrProof, public_key_bytes: &[u8; 32]) -> bool {
    // Decode commitment R
    let r_bytes: [u8; 32] = match hex::decode(&proof.commitment) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return false,
    };

    let r_point = match CompressedEdwardsY(r_bytes).decompress() {
        Some(pt) => pt,
        None => return false,
    };

    // Decode public key PK
    let pk_point = match CompressedEdwardsY(*public_key_bytes).decompress() {
        Some(pt) => pt,
        None => return false,
    };

    // Decode response scalar s
    let s_bytes: [u8; 32] = match hex::decode(&proof.response) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return false,
    };

    // Reject the trivial proof (s == 0)
    if s_bytes.iter().all(|&b| b == 0) {
        return false;
    }

    let s = match Option::from(Scalar::from_canonical_bytes(s_bytes)) {
        Some(sc) => sc,
        None => return false,
    };

    // Recompute challenge e = H(R || PK || message) mod ℓ
    let e = challenge_scalar(&r_bytes, public_key_bytes, &proof.message);

    // Algebraic check: s·G + e·PK == R
    let lhs = &s * ED25519_BASEPOINT_TABLE + e * pk_point;
    lhs == r_point
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_proof() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);

        let pk_point = public_point_from_seed(&seed);
        let pub_bytes = pk_point.compress().to_bytes();

        let proof = generate_proof(&seed, "test-message");
        assert!(
            verify_proof(&proof, &pub_bytes),
            "proof generated from the correct private key must verify"
        );
    }

    #[test]
    fn test_proof_fails_with_wrong_public_key() {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);

        let mut other_seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut other_seed);
        let wrong_pub = public_point_from_seed(&other_seed).compress().to_bytes();

        let proof = generate_proof(&seed, "test-message");
        assert!(
            !verify_proof(&proof, &wrong_pub),
            "proof must be rejected when verified against a different public key"
        );
    }

    #[test]
    fn test_invalid_commitment_rejected() {
        let proof = SchnorrProof {
            commitment: "deadbeef".to_string(), // too short
            response: hex::encode([1u8; 32]),
            message: "test".to_string(),
        };
        assert!(!verify_proof(&proof, &[0u8; 32]));
    }

    #[test]
    fn test_zero_response_rejected() {
        // Use a valid curve point for commitment
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        let pt = public_point_from_seed(&seed).compress().to_bytes();

        let proof = SchnorrProof {
            commitment: hex::encode(pt),
            response: hex::encode([0u8; 32]),
            message: "test".to_string(),
        };
        assert!(!verify_proof(&proof, &pt));
    }

    #[test]
    fn test_proof_serialization() {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);

        let proof = generate_proof(&seed, "serialize-me");
        let json = serde_json::to_string(&proof).unwrap();
        let deser: SchnorrProof = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.message, "serialize-me");
        assert_eq!(deser.commitment, proof.commitment);
    }

    #[test]
    fn test_tampered_message_rejected() {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        let pub_bytes = public_point_from_seed(&seed).compress().to_bytes();

        let mut proof = generate_proof(&seed, "original");
        proof.message = "tampered".to_string();
        assert!(
            !verify_proof(&proof, &pub_bytes),
            "changing the message must invalidate the proof"
        );
    }

    #[test]
    fn test_tampered_response_rejected() {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        let pub_bytes = public_point_from_seed(&seed).compress().to_bytes();

        let mut proof = generate_proof(&seed, "test");
        // Flip a bit in the response
        let mut resp_bytes = hex::decode(&proof.response).unwrap();
        resp_bytes[0] ^= 0x01;
        proof.response = hex::encode(resp_bytes);
        // May or may not parse as a valid scalar, but algebraic check should fail
        // (unless we got very unlucky and flipped to a valid proof, astronomically unlikely)
        let result = verify_proof(&proof, &pub_bytes);
        // We can't assert false 100% of the time due to scalar rejection,
        // but it should not verify as true
        assert!(!result, "tampered response must not verify");
    }

    use rand_core::{OsRng, RngCore};
}
