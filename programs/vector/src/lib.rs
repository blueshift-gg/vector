//! Vector — one program for every signing scheme.
//!
//! An account is controlled by a key of some [`scheme::SigningScheme`]. Its
//! owner signs a whole transaction off-chain; [`Advance`] verifies that
//! signature, and [`Passthrough`] then acts for the account.
#![no_std]

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

pub mod instructions;
pub use instructions::*;

pub mod state;

// The schemes, the error codes and the program ID are `vector-signer`'s: the
// clients run the same code offline.
pub use vector_signer::{error, scheme, schemes, ID};

// The tests use this crate as a library.
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::program_entrypoint!(process_instruction);
// Nothing allocates: every buffer is on the stack. An allocation panics.
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::no_allocator!();
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::nostd_panic_handler!();

pub fn process_instruction(
    _program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    match instruction_data.split_first() {
        // Signing: verify the transaction, then act for the account.
        Some((Advance::DISCRIMINATOR, data)) => Advance::try_from((data, accounts))?.process(),
        Some((Passthrough::DISCRIMINATOR, data)) => {
            Passthrough::try_from((data, accounts))?.process()
        }

        // Account lifecycle.
        Some((Initialize::DISCRIMINATOR, data)) => {
            Initialize::try_from((data, accounts))?.process()
        }
        Some((Withdraw::DISCRIMINATOR, data)) => Withdraw::try_from((data, accounts))?.process(),
        Some((Close::DISCRIMINATOR, data)) => Close::try_from((data, accounts))?.process(),
        Some((InitializeNonce::DISCRIMINATOR, data)) => {
            InitializeNonce::try_from((data, accounts))?.process()
        }

        _ => Err(ProgramError::InvalidInstructionData),
    }
}
