//! Vector — secp256k1 EIP-191.
//!
//! Identity is the 20-byte Ethereum address. The digest is wrapped in the
//! EIP-191 "Ethereum Signed Message" envelope, then `ecrecover`'d and
//! keccak-compared. The instruction set is shared verbatim with every other
//! Vector program via [`vector_common`]; only [`scheme`] differs.
#![no_std]

use pinocchio::{entrypoint, nostd_panic_handler, AccountView, Address, ProgramResult};
use solana_address::declare_id;
use vector_common::dispatch;

mod scheme;
use scheme::Secp256k1Eip191;

entrypoint!(process_instruction);
nostd_panic_handler!();

declare_id!("G6okL1MvXx7k5eytY7wRXNupXyYG1QVZW37ygAjMiTTu");

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    dispatch::<Secp256k1Eip191>(program_id, accounts, instruction_data)
}
