//! Vector — one program for every signing scheme.
//!
//! An account is controlled by a key of some [`scheme::SigningScheme`]. Its
//! owner signs a whole transaction off-chain; [`Advance`] verifies that
//! signature, and [`Passthrough`] then acts for the account.
#![no_std]

extern crate alloc;

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use solana_address::declare_id;

pub mod instructions;
pub use instructions::*;

pub mod scheme;
pub mod schemes;
pub mod state;

// The clients use this crate as a library, for its types and constants.
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::entrypoint!(process_instruction);
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::nostd_panic_handler!();

declare_id!("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV");

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
        Some((Expand::DISCRIMINATOR, data)) => Expand::try_from((data, accounts))?.process(),
        Some((Withdraw::DISCRIMINATOR, data)) => Withdraw::try_from((data, accounts))?.process(),
        Some((Close::DISCRIMINATOR, data)) => Close::try_from((data, accounts))?.process(),

        _ => Err(ProgramError::InvalidInstructionData),
    }
}
