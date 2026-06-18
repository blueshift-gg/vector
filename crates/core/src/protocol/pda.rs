//! Canonical PDA derivation for Vector program accounts.
//!
//! Seeds: `["vector", identity_seed]`. The program ID (i.e. the scheme's
//! `program_id`) acts as the scheme discriminator — there is no extra byte.

use sha2::{Digest as Sha2Digest, Sha256};

use crate::protocol::encoding::VECTOR_PDA_SEED;
use crate::scheme::Scheme;
use solana_address::Address;

/// 32-byte PDA-seed input derived from a scheme's identity: identity bytes
/// themselves when `identity.len() <= 32`, `sha256(identity)` otherwise.
/// Off-chain mirror of `IdentitySeed::default_from` in `vector-common`.
pub fn pda_seed_from_identity(identity: &[u8]) -> [u8; 32] {
    if identity.len() <= 32 {
        let mut out = [0u8; 32];
        out[..identity.len()].copy_from_slice(identity);
        out
    } else {
        Sha256::digest(identity).into()
    }
}

/// Derive the canonical `(vector_pda, bump)` for a scheme + identity.
/// Seeds: `["vector", identity_seed]` (no scheme byte — the program ID is
/// the discriminator).
pub fn find_vector_pda(scheme: &Scheme, identity: &[u8]) -> (Address, u8) {
    debug_assert_eq!(identity.len(), scheme.identity_len);
    let seed_bytes = pda_seed_from_identity(identity);
    let seed_len = identity.len().min(32);
    Address::find_program_address(
        &[VECTOR_PDA_SEED, &seed_bytes[..seed_len]],
        &scheme.program_id,
    )
}
