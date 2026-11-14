//! Addresses: canonical PDA derivation for a vector account and its
//! system PDA, and what a signature over a nonce account is over.

use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::{address, Address};

pub const SYSTEM_PROGRAM_ID: Address = address!("11111111111111111111111111111111");
pub const INSTRUCTIONS_SYSVAR_ID: Address = address!("Sysvar1nstructions1111111111111111111111111");

/// The vector account's address seed, under the client's name for it.
pub use crate::state::VECTOR_SEED as VECTOR_PDA_SEED;
use crate::{scheme::Scheme, PROGRAM_ID};

/// The PDA seed for an identity: its SHA-256, for every scheme.
pub fn vector_seed(identity: &[u8]) -> [u8; 32] {
    Sha256::digest(identity).into()
}

/// Derive the canonical `(vector_pda, bump)` for a scheme + identity.
/// Seeds: `["vector", [scheme], sha256(identity)]`.
pub fn find_vector_pda(scheme: &Scheme, identity: &[u8]) -> (Address, u8) {
    assert_eq!(
        identity.len(),
        scheme.identity_len,
        "identity length mismatch"
    );
    Address::find_program_address(
        &[VECTOR_PDA_SEED, &[scheme.id], &vector_seed(identity)],
        &PROGRAM_ID,
    )
}

/// What a signature over a nonce account is over, in place of a nonce:
/// `SHA256(nonce account's nonce || vector's own nonce)`. Moving the vector's
/// own nonce changes it for every nonce account of the vector.
pub fn signed_nonce(nonce_account_nonce: &[u8; 32], vector_nonce: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(nonce_account_nonce)
        .chain_update(vector_nonce)
        .finalize()
        .into()
}

/// Derive the vector account's system PDA, `[vector]`, and its bump. It
/// belongs to the System program; a passthrough can sign as it.
pub fn find_system_pda(vector: &Address) -> (Address, u8) {
    Address::find_program_address(&[vector.as_ref()], &PROGRAM_ID)
}
