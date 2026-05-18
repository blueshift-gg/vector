//! Vector — plain secp256k1 ECDSA.
//!
//! Identity is the 33-byte sec1-compressed public key, verified via standard
//! ECDSA (no recovery) over the advance digest. The instruction set is shared
//! verbatim with every other Vector program via [`vector_common`]; only
//! [`scheme`] differs.
#![no_std]

use pinocchio::{entrypoint, nostd_panic_handler, AccountView, Address, ProgramResult};
use solana_address::declare_id;
use vector_common::dispatch;

mod scheme;
use scheme::Secp256k1Ecdsa;

entrypoint!(process_instruction);
nostd_panic_handler!();

declare_id!("9NCknbW4LpePSZzbZGFk2HHsSH4y4pkmRjEguJo7qqjd");

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    dispatch::<Secp256k1Ecdsa>(program_id, accounts, instruction_data)
}
