//! Ed25519 program: identity is the 32-byte public key, verified directly
//! over the advance digest.

use ed25519_dalek::{
    Signature, Signer as Ed25519Signer, SigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use solana_address::{address, Address};
use solana_instruction::Instruction;

use crate::instructions::{create_advance_instruction, create_initialize_instruction};
use crate::protocol::advance_vector_digest;
use crate::scheme::{Scheme, SchemeMeta, Signer, Verifier};

/// Length of an Ed25519 public key in bytes.
pub const ED25519_PUBKEY_LEN: usize = 32;

/// Ed25519 — identity is the 32-byte public key.
pub const ED25519: Scheme = Scheme {
    program_id: address!("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV"),
    signature_len: 64,
    identity_len: ED25519_PUBKEY_LEN,
    stored_identity_len: ED25519_PUBKEY_LEN,
};

/// 32-byte Ed25519 public key (the identity) for a signing key.
pub fn ed25519_pubkey(signing_key: &SigningKey) -> [u8; ED25519_PUBKEY_LEN] {
    signing_key.verifying_key().to_bytes()
}

/// Initialize an Ed25519 vector account. `pubkey` is the 32-byte public key.
pub fn create_initialize_ed25519(
    payer: &Address,
    pubkey: &[u8; ED25519_PUBKEY_LEN],
) -> Instruction {
    create_initialize_instruction(payer, &ED25519, pubkey, pubkey)
}

/// Sign the advance digest with an Ed25519 key, returning the advance ix
/// alone. Any CPI passthrough must be built separately via
/// [`crate::instructions::create_passthrough_instruction`] and included
/// among `pre_instructions` or `post_instructions` so the digest commits
/// to its bytes.
pub fn sign_advance_instruction_ed25519(
    signing_key: &SigningKey,
    nonce: &[u8; 32],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
) -> Instruction {
    let identity = ed25519_pubkey(signing_key);
    let digest = advance_vector_digest(
        &ED25519,
        nonce,
        &identity,
        pre_instructions,
        post_instructions,
    );
    let signature: [u8; 64] = signing_key.sign(&digest).to_bytes();
    create_advance_instruction(&ED25519, &identity, &signature)
}

// ---------------------------------------------------------------------------
// Ed25519 struct — implements SchemeMeta + Signer + Verifier
// ---------------------------------------------------------------------------

/// Ed25519 signer/verifier. Identity is the 32-byte public key.
#[derive(Clone)]
pub struct Ed25519 {
    key: SigningKey,
}

impl Ed25519 {
    /// Construct an Ed25519 signer from a 32-byte raw seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Borrow the inner `ed25519_dalek` signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

impl SchemeMeta for Ed25519 {
    const PROGRAM_ID: Address = ED25519.program_id;
    const SIGNATURE_LEN: usize = 64;
    const IDENTITY_LEN: usize = 32;
    const STORED_IDENTITY_LEN: usize = 32;
}

impl Signer for Ed25519 {
    fn identity(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }

    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        self.key.sign(digest).to_bytes().to_vec()
    }
}

impl crate::scheme::Registration for Ed25519 {}
impl crate::scheme::SingleTxRegister for Ed25519 {}

use crate::branching::derive_lane_seed;
impl crate::scheme::Derivable for Ed25519 {
    fn derive(&self, index: u32) -> Self {
        Self::from_seed(&derive_lane_seed(&self.key.to_bytes(), "ed25519", index))
    }
}

impl Verifier for Ed25519 {
    fn verify(identity: &[u8], _pk: Option<&[u8]>, digest: &[u8; 32], signature: &[u8]) -> bool {
        let (Ok(vk_bytes), Ok(sig_bytes)) = (
            <[u8; 32]>::try_from(identity),
            <[u8; 64]>::try_from(signature),
        ) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) else {
            return false;
        };
        DalekVerifier::verify(&vk, digest, &Signature::from_bytes(&sig_bytes)).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::{Signer, Verifier};

    fn key() -> Ed25519 {
        Ed25519::from_seed(&[7u8; 32])
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let k = key();
        let digest = [9u8; 32];
        let sig = k.sign(&digest);
        assert_eq!(sig.len(), 64);
        assert!(Ed25519::verify(&k.identity(), None, &digest, &sig));
        let mut bad = digest;
        bad[0] ^= 1;
        assert!(!Ed25519::verify(&k.identity(), None, &bad, &sig));
    }

    #[test]
    fn identity_is_pubkey() {
        assert_eq!(key().identity().len(), 32);
    }
}
