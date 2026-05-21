//! Vector — Hawk-512 (post-quantum), three-step registration.
//!
//! Hawk-512's prepared pubkey is ~18 KB — too large to allocate or compute
//! inside one instruction, and its 1024-byte wire pubkey can't coexist
//! with the `system_program` meta needed for `CreateAccount` in a single
//! tx. Registration is therefore three permissionless calls of
//! discriminator `0`, disambiguated by ix shape:
//!
//! 1. `initialize` (3 metas: payer + vector + system_program; data = 32-byte
//!    `sha256(wire_pubkey)`). Allocates a ~10 KB base account and stores
//!    the hash commit + 33-byte header. Anyone can call, but the PDA is
//!    bound to the hash — only the matching wire pubkey can complete
//!    registration.
//! 2. `store_wire` (1 meta: vector; data = 1024-byte wire pubkey).
//!    Verifies `sha256(payload) == stored hash` and stashes the wire in
//!    the account. The hash check is the grief-prevention anchor: an
//!    attacker who squatted on step 1 can neither block this step nor
//!    corrupt the stashed wire.
//! 3. `finalize` (1 meta: vector; empty data). Resizes to ~18.5 KB and
//!    runs Hawk's `prepare_into` on the stashed wire (~410 k CU on the
//!    live validator, so the finalize tx ships with a
//!    `ComputeBudgetProgram::set_compute_unit_limit(600_000)` ix).
//!    Idempotent.
//!
//! Discriminators `1`/`2`/`3`/`4` (Advance/Close/Withdraw/Passthrough) are
//! the shared handlers, identical to every other Vector program. `advance`
//! only succeeds once `finalize` has prepared the account.
#![no_std]

use pinocchio::{
    entrypoint, error::ProgramError, nostd_panic_handler, AccountView, Address, ProgramResult,
};
use solana_address::declare_id;
use vector_common::{advance, close, passthrough, withdraw};

mod scheme;
use scheme::{initialize, Hawk512};

entrypoint!(process_instruction);
nostd_panic_handler!();

declare_id!("Ecm48RMiE4qvyw6m4M5DeutpRAN1AF4tis6ijc6Zq3H9");

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (discriminator, rest) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *discriminator {
        // All three registration steps share disc 0; the hawk-specific
        // `initialize` routes them internally by ix shape + vector
        // account state. (Shadows `vector_common::initialize`, which it
        // delegates to for step 1.)
        0 => initialize(program_id, accounts, rest),
        1 => advance::<Hawk512>(program_id, accounts, rest),
        2 => close(program_id, accounts, rest),
        3 => withdraw::<Hawk512>(program_id, accounts, rest),
        4 => passthrough::<Hawk512>(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
