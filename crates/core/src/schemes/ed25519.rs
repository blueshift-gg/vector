//! Ed25519 scheme: identity is the 32-byte public key, verified directly
//! over the advance digest.

use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};
use solana_address::Address;
use solana_instruction::Instruction;

use crate::digest::advance_vector_digest;
use crate::instructions::{create_advance_instruction, create_initialize_instruction};
use crate::scheme::Scheme;

pub const ED25519_PUBKEY_LEN: usize = 32;

/// Ed25519 — identity is the 32-byte public key.
pub const ED25519: Scheme = Scheme {
    id: 1,
    signature_len: 64,
    identity_len: ED25519_PUBKEY_LEN,
    stored_identity_len: size_of::<vector::schemes::ed25519::Ed25519>(),
    next_key_len: 0,
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
    create_initialize_instruction(payer, &ED25519, pubkey)
}

/// Sign an advance with an Ed25519 key. Put any passthrough among
/// `pre_instructions` or `post_instructions`, so the signature covers it.
/// Pass `fee_payer` when it is also an account of one of those instructions.
pub fn sign_advance_instruction_ed25519(
    signing_key: &SigningKey,
    nonce: &[u8; 32],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
) -> Instruction {
    let identity = ed25519_pubkey(signing_key);
    let digest = advance_vector_digest(
        &ED25519,
        nonce,
        &identity,
        pre_instructions,
        post_instructions,
        fee_payer,
    );
    let signature: [u8; 64] = signing_key.sign(&digest).to_bytes();
    create_advance_instruction(&ED25519, &identity, &signature)
}

/// Sign an advance with nothing around it. Landing it only moves the nonce,
/// which cancels everything signed against the old one. It must be the only
/// instruction of its transaction.
pub fn sign_revocation_instruction_ed25519(
    signing_key: &SigningKey,
    nonce: &[u8; 32],
) -> Instruction {
    sign_advance_instruction_ed25519(signing_key, nonce, &[], &[], None)
}
