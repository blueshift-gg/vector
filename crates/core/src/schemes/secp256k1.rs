//! Plain secp256k1 ECDSA program: identity is the 33-byte sec1-compressed
//! pubkey, verified via standard ECDSA (no envelope, no recovery byte).

use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey as Secp256k1SigningKey};
use solana_address::{address, Address};
use solana_instruction::Instruction;

use crate::digest::advance_vector_digest;
use crate::instructions::{create_advance_instruction, create_initialize_instruction};
use crate::scheme::Scheme;

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
