//! Hawk-512 (post-quantum) program. Verify-only library; signing is left to
//! the caller. The client identity is `sha256(wire_pubkey)`. Registration is
//! three permissionless ixs (see [`create_initialize_hawk512`],
//! [`create_hawk512_store_wire`], [`create_hawk512_finalize`]).

use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::{address, Address};
use solana_instruction::{AccountMeta, Instruction};

use crate::instructions::create_initialize_instruction;
use crate::scheme::{find_vector_pda, Scheme, INITIALIZE_DISCRIMINATOR};

/// Hawk-512 wire pubkey length.
pub const HAWK512_WIRE_PUBKEY_LEN: usize = 1024;
pub const HAWK512_SIGNATURE_LEN: usize = 555;
/// Hawk-512 prepared pubkey blob.
pub const HAWK512_PREPARED_PUBKEY_LEN: usize = 18464;
/// Hawk's on-chain stored identity: `sha256(wire)[32] || pad[7] ||
/// prepared[18464]`. The 7-byte pad lands `prepared` on an 8-byte account
/// offset (Hawk's zero-copy borrow requires 8-byte alignment).
pub const HAWK512_STORED_IDENTITY_LEN: usize = 32 + 7 + HAWK512_PREPARED_PUBKEY_LEN;

/// Hawk-512 (post-quantum) — client identity is `sha256(wire_pubkey)` (32
/// bytes). Three-call registration: the 18 KB prepared pubkey is too large
/// to allocate or compute in a single instruction, and the 1024-byte wire
/// pubkey can't coexist with the `system_program` meta needed for
/// `CreateAccount`. See [`create_initialize_hawk512`] for the flow.
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

/// Hawk-512 registration is three permissionless ixs, all on discriminator
/// `0` — the on-chain dispatcher selects each handler by ix shape + vector
/// account state (see `programs/hawk512/src/scheme.rs`).
///
/// 1. [`create_initialize_hawk512`] commits the 32-byte `sha256(wire)` and
///    allocates the ~10 KB base account. Carries the `system_program` meta
///    for `CreateAccount`.
/// 2. [`create_hawk512_store_wire`] carries the 1024-byte wire pubkey; the
///    program verifies its hash against the commit and stashes the wire in
///    the account.
/// 3. [`create_hawk512_finalize`] carries no payload; pair it with a
///    `ComputeBudgetProgram::set_compute_unit_limit(600_000)` ix because
///    `prepare_into` draws ~410 k CU (the 200 k per-tx default isn't
///    enough). The on-chain handler resizes the account to ~18.5 KB and
///    runs `prepare_into`. Idempotent.
///
/// The split is forced by the 1232-byte tx ceiling: the wire pubkey can't
/// fit with `system_program`, and `finalize`'s ~410 k-CU `prepare_into`
/// can't fit alongside the wire either.
pub fn create_initialize_hawk512(
    payer: &Address,
    wire_pubkey: &[u8; HAWK512_WIRE_PUBKEY_LEN],
) -> Instruction {
    let identity = hawk512_identity(wire_pubkey);
    create_initialize_instruction(payer, &HAWK512, &identity, &identity)
}

/// Hawk-512 registration step 2 — ship the 1024-byte wire pubkey. The
/// on-chain handler verifies `sha256(payload) == stored hash` (the commit
/// from step 1) before stashing, so an attacker who squatted on init can
/// neither block this nor corrupt the stashed wire.
///
/// Accounts: `[vector_pda]` — no payer, no system_program. The tx-level
/// fee payer signer is enough; trimming the metas is what gets the
/// 1024-byte payload under the 1232-byte ceiling.
pub fn create_hawk512_store_wire(wire_pubkey: &[u8; HAWK512_WIRE_PUBKEY_LEN]) -> Instruction {
    let identity = hawk512_identity(wire_pubkey);
    let (vector, _bump) = find_vector_pda(&HAWK512, &identity);
    let mut data = Vec::with_capacity(1 + HAWK512_WIRE_PUBKEY_LEN);
    data.push(INITIALIZE_DISCRIMINATOR);
    data.extend_from_slice(wire_pubkey);
    Instruction {
        program_id: HAWK512.program_id,
        accounts: vec![AccountMeta::new(vector, false)],
        data,
    }
}

/// Hawk-512 registration step 3 — resize the account to ~18.5 KB and
/// `prepare_into` the stashed wire. Idempotent: re-running on a fully
/// prepared account is a no-op.
///
/// Accounts: `[vector_pda]`. Data: `[0]` (just the discriminator).
/// The finalize tx must include a
/// `ComputeBudgetProgram::set_compute_unit_limit(600_000)` ix because
/// `prepare_into` draws ~410 k CU on the live validator (the per-tx
/// default of 200 k otherwise leaves it short).
pub fn create_hawk512_finalize(wire_pubkey: &[u8; HAWK512_WIRE_PUBKEY_LEN]) -> Instruction {
    let identity = hawk512_identity(wire_pubkey);
    let (vector, _bump) = find_vector_pda(&HAWK512, &identity);
    Instruction {
        program_id: HAWK512.program_id,
        accounts: vec![AccountMeta::new(vector, false)],
        data: vec![INITIALIZE_DISCRIMINATOR],
    }
}
