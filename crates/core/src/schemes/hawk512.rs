//! Hawk-512 (post-quantum) program. Verify-only library; signing is left to
//! the caller. The client identity is `sha256(wire_pubkey)`. Registration is
//! two calls of the same `initialize` instruction (see
//! [`create_initialize_hawk512`]).

use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::{address, Address};
use solana_instruction::Instruction;

use crate::instructions::create_initialize_instruction;
use crate::scheme::Scheme;

/// Hawk-512 wire pubkey (the `initialize` payload).
pub const HAWK512_WIRE_PUBKEY_LEN: usize = 1024;
pub const HAWK512_SIGNATURE_LEN: usize = 555;
/// Hawk-512 prepared pubkey blob.
pub const HAWK512_PREPARED_PUBKEY_LEN: usize = 18464;
/// Hawk's on-chain stored identity: `sha256(wire)[32] || pad[7] ||
/// prepared[18464]`. The 7-byte pad lands `prepared` on an 8-byte account
/// offset (Hawk's zero-copy borrow requires 8-byte alignment).
pub const HAWK512_STORED_IDENTITY_LEN: usize = 32 + 7 + HAWK512_PREPARED_PUBKEY_LEN;

/// Hawk-512 (post-quantum) — client identity is `sha256(wire_pubkey)` (32
/// bytes). Two-call registration: the 18 KB prepared pubkey is too large to
/// allocate/compute in one instruction.
pub const HAWK512: Scheme = Scheme {
    program_id: address!("Ecm48RMiE4qvyw6m4M5DeutpRAN1AF4tis6ijc6Zq3H9"),
    signature_len: HAWK512_SIGNATURE_LEN,
    identity_len: 32,
    stored_identity_len: HAWK512_STORED_IDENTITY_LEN,
};

/// `sha256(wire_pubkey)` — Hawk's client-side identity (PDA seed + digest
/// input). Mirrors the first 32 bytes the on-chain program stores.
pub fn hawk512_identity(wire_pubkey: &[u8; HAWK512_WIRE_PUBKEY_LEN]) -> [u8; 32] {
    Sha256::digest(wire_pubkey).into()
}

/// Hawk-512 registration instruction. Send it **twice** with the same
/// accounts and args: the first call allocates the base account and stores
/// `sha256(wire_pubkey)`; the second (permissionless) call resizes to full
/// and writes the ~18 KB prepared blob. Further calls are idempotent no-ops.
/// Identical to every other scheme's initialize — single-step schemes simply
/// finish in one call.
pub fn create_initialize_hawk512(
    payer: &Address,
    wire_pubkey: &[u8; HAWK512_WIRE_PUBKEY_LEN],
) -> Instruction {
    let identity = hawk512_identity(wire_pubkey);
    create_initialize_instruction(payer, &HAWK512, &identity, wire_pubkey)
}
