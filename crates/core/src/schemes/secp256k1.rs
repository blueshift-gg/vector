//! Plain secp256k1 ECDSA program: identity is the 33-byte sec1-compressed
//! pubkey, verified via standard ECDSA (no envelope, no recovery byte).

use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey as Secp256k1SigningKey};
use solana_address::{address, Address};
use solana_instruction::Instruction;

use crate::instructions::{create_advance_instruction, create_initialize_instruction};
use crate::protocol::advance_vector_digest;
use crate::scheme::Scheme;

/// Length of a sec1-compressed secp256k1 public key in bytes.
pub const SECP256K1_COMPRESSED_PUBKEY_LEN: usize = 33;

/// Plain secp256k1 ECDSA — identity is the 33-byte compressed pubkey.
pub const SECP256K1: Scheme = Scheme {
    program_id: address!("9NCknbW4LpePSZzbZGFk2HHsSH4y4pkmRjEguJo7qqjd"),
    signature_len: 64,
    identity_len: SECP256K1_COMPRESSED_PUBKEY_LEN,
    stored_identity_len: SECP256K1_COMPRESSED_PUBKEY_LEN,
};

/// 33-byte sec1-compressed secp256k1 public key (the identity).
pub fn secp256k1_compressed_pubkey(
    signing_key: &Secp256k1SigningKey,
) -> [u8; SECP256K1_COMPRESSED_PUBKEY_LEN] {
    let encoded = signing_key.verifying_key().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut out = [0u8; SECP256K1_COMPRESSED_PUBKEY_LEN];
    out.copy_from_slice(bytes);
    out
}

/// Initialize a plain-secp256k1 (compressed-pubkey) ECDSA vector account.
pub fn create_initialize_secp256k1_ecdsa(
    payer: &Address,
    compressed_pubkey: &[u8; SECP256K1_COMPRESSED_PUBKEY_LEN],
) -> Instruction {
    create_initialize_instruction(payer, &SECP256K1, compressed_pubkey, compressed_pubkey)
}

/// Sign the advance digest with a plain secp256k1 ECDSA key, returning the
/// advance ix alone. Any CPI passthrough must be built separately via
/// [`crate::instructions::create_passthrough_instruction`] and included
/// among `pre_instructions` or `post_instructions` so the digest commits
/// to its bytes.
pub fn sign_advance_instruction_secp256k1_ecdsa(
    signing_key: &Secp256k1SigningKey,
    nonce: &[u8; 32],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
) -> Instruction {
    let identity = secp256k1_compressed_pubkey(signing_key);
    let digest = advance_vector_digest(
        &SECP256K1,
        nonce,
        &identity,
        pre_instructions,
        post_instructions,
    );
    let (sig, _recid) = signing_key
        .sign_prehash(&digest)
        .expect("secp256k1 signing failed");
    let sig_bytes: [u8; 64] = sig.to_bytes().into();
    create_advance_instruction(&SECP256K1, &identity, &sig_bytes)
}

// ---------------------------------------------------------------------------
// Secp256k1 struct — implements SchemeMeta + Signer + Verifier
// ---------------------------------------------------------------------------

use crate::scheme::{SchemeMeta, Signer, Verifier};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

/// Secp256k1 signer/verifier. Identity is the 33-byte sec1-compressed pubkey.
#[derive(Clone)]
pub struct Secp256k1 {
    key: Secp256k1SigningKey,
}

impl Secp256k1 {
    /// Construct a secp256k1 signer from a 32-byte scalar (panics if not a valid scalar).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: Secp256k1SigningKey::from_slice(seed).expect("valid secp256k1 scalar"),
        }
    }
}

impl SchemeMeta for Secp256k1 {
    const PROGRAM_ID: solana_address::Address = SECP256K1.program_id;
    const SIGNATURE_LEN: usize = 64;
    const IDENTITY_LEN: usize = 33;
    const STORED_IDENTITY_LEN: usize = 33;
}

impl Signer for Secp256k1 {
    fn identity(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        let (sig, _recid): (Signature, _) = self
            .key
            .sign_prehash(digest)
            .expect("secp256k1 signing failed");
        sig.to_bytes().to_vec()
    }
}

impl crate::scheme::Registration for Secp256k1 {}
impl crate::scheme::SingleTxRegister for Secp256k1 {}

use crate::branching::derive_lane_seed;
impl crate::scheme::Derivable for Secp256k1 {
    fn derive(&self, index: u32) -> Self {
        let master: [u8; 32] = self.key.to_bytes().into();
        Self::from_seed(&derive_lane_seed(&master, "secp256k1", index))
    }
}

impl Verifier for Secp256k1 {
    fn verify(identity: &[u8], _pk: Option<&[u8]>, digest: &[u8; 32], signature: &[u8]) -> bool {
        let Ok(vk) = VerifyingKey::from_sec1_bytes(identity) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(signature) else {
            return false;
        };
        vk.verify_prehash(digest, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::{Signer, Verifier};

    #[test]
    fn sign_then_verify_roundtrip() {
        let k = Secp256k1::from_seed(&[3u8; 32]);
        let digest = [5u8; 32];
        let sig = k.sign(&digest);
        assert_eq!(sig.len(), 64);
        assert!(Secp256k1::verify(&k.identity(), None, &digest, &sig));
        let mut bad = digest;
        bad[1] ^= 1;
        assert!(!Secp256k1::verify(&k.identity(), None, &bad, &sig));
    }
}
