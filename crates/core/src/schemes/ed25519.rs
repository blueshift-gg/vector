//! Ed25519 program: identity is the 32-byte public key, verified directly
//! over the advance digest.

use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};
use solana_address::{address, Address};
use solana_instruction::Instruction;

use crate::digest::advance_vector_digest;
use crate::instructions::{create_advance_instruction, create_initialize_instruction};
use crate::scheme::Scheme;

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
