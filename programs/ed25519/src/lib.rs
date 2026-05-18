//! Vector — Ed25519.
//!
//! Identity is the 32-byte Ed25519 public key, verified directly over the
//! advance digest. The instruction set is shared verbatim with every other
//! Vector program via [`vector_common`]; only [`scheme`] differs.
#![no_std]

use pinocchio::{entrypoint, nostd_panic_handler, AccountView, Address, ProgramResult};
use solana_address::declare_id;
use vector_common::dispatch;

mod scheme;
use scheme::Ed25519;

entrypoint!(process_instruction);
nostd_panic_handler!();

declare_id!("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV");

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    dispatch::<Ed25519>(program_id, accounts, instruction_data)
}
