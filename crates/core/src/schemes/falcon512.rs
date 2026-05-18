//! Falcon-512 (post-quantum) program. Verify-side library only; signing is
//! left to the caller (pair with `pqcrypto-falcon` or another Falcon
//! signer). The client identity is `sha256(wire_pubkey)`.

use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::{address, Address};
use solana_falcon512::{FALCON_512_PUBKEY_LEN, FALCON_512_SIGNATURE_LEN};
use solana_instruction::Instruction;

use crate::instructions::create_initialize_instruction;
use crate::scheme::Scheme;

pub const FALCON512_WIRE_PUBKEY_LEN: usize = FALCON_512_PUBKEY_LEN;
pub const FALCON512_SIGNATURE_LEN: usize = FALCON_512_SIGNATURE_LEN;
/// Falcon-512 prepared pubkey (`N * 2`, `N = 512`).
pub const FALCON512_PREPARED_PUBKEY_LEN: usize = 1024;
/// Falcon's on-chain stored identity: `sha256(wire_pubkey)[32] || pad[1] ||
/// prepared_pubkey[1024]`. The 1-byte pad lands `prepared` on a 2-byte
/// account offset for the on-chain zero-copy borrow.
pub const FALCON512_STORED_IDENTITY_LEN: usize = 32 + 1 + FALCON512_PREPARED_PUBKEY_LEN;

/// Falcon-512 — the client identity is `sha256(wire_pubkey)` (32 bytes); the
/// account stores that hash plus the 1024-byte prepared pubkey.
pub const FALCON512: Scheme = Scheme {
    program_id: address!("HdkE3dPYgCRZJgLv64mbFmojyCprUim8VRXzK2wR6Qgm"),
    signature_len: FALCON512_SIGNATURE_LEN,
    identity_len: 32,
    stored_identity_len: FALCON512_STORED_IDENTITY_LEN,
};

/// `sha256(wire_pubkey)` — Falcon's client-side identity (PDA seed + the
/// bytes folded into the advance digest). Mirrors the first 32 bytes the
/// on-chain program stores.
pub fn falcon512_identity(wire_pubkey: &[u8; FALCON512_WIRE_PUBKEY_LEN]) -> [u8; 32] {
    Sha256::digest(wire_pubkey).into()
}

/// Initialize a Falcon-512 vector account. `wire_pubkey` is the standard
/// 897-byte Falcon public key; the on-chain program hashes and prepares it.
pub fn create_initialize_falcon512(
    payer: &Address,
    wire_pubkey: &[u8; FALCON512_WIRE_PUBKEY_LEN],
) -> Instruction {
    let identity = falcon512_identity(wire_pubkey);
    create_initialize_instruction(payer, &FALCON512, &identity, wire_pubkey)
}
