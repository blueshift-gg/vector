//! Vector — Hawk-512 (post-quantum), two-call registration.
//!
//! Hawk-512's prepared pubkey is ~18 KB — too large to allocate or compute
//! inside one instruction. Registration is driven by calling discriminator
//! `0` **twice with the same accounts and arguments**:
//!
//! 1. First call (vector still system-owned) → [`vector_common::initialize`]:
//!    allocates a ~10 KB base account and writes the cheap
//!    `sha256(wire_pubkey)` prefix (the PDA seed + digest identity).
//! 2. Second call (vector now program-owned), permissionless →
//!    [`vector_common::prepare`]: re-supplies the wire pubkey, checks it
//!    against the stored hash, resizes to full, and writes the ~18 KB
//!    prepared blob (~365k CU). Further calls are idempotent no-ops.
//!
//! Only this program carries the create-vs-prepare owner check; the
//! single-step programs use `vector_common::dispatch` with a strict
//! `initialize` and never pay for it. Discriminators `1`/`2`/`3`
//! (Advance/Close/Withdraw) are the shared handlers, identical to every
//! other Vector program. `advance` only succeeds once prepared.
#![no_std]

use pinocchio::{
    entrypoint, error::ProgramError, nostd_panic_handler, AccountView, Address, ProgramResult,
};
use solana_address::declare_id;
use vector_common::{advance, close, initialize, prepare, withdraw};

mod scheme;
use scheme::Hawk512;

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
        // Registration: round one while the vector PDA is still
        // system-owned, round two (`prepare`) once this program owns it.
        // The owner check that distinguishes the two calls lives here, not
        // in the shared single-step `initialize`.
        0 => {
            if accounts
                .get(1)
                .ok_or(ProgramError::NotEnoughAccountKeys)?
                .owned_by(&ID) {
                prepare::<Hawk512>(program_id, accounts, rest)
            } else {
                initialize::<Hawk512>(program_id, accounts, rest)
            }
        }
        1 => advance::<Hawk512>(program_id, accounts, rest),
        2 => close(program_id, accounts, rest),
        3 => withdraw::<Hawk512>(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
