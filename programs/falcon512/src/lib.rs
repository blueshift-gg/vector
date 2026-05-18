//! Vector — Falcon-512 (post-quantum).
//!
//! On-chain identity is `sha256(wire_pubkey) || prepared_pubkey`; the leading
//! hash doubles as the PDA seed (derivable off-chain from the standard
//! 897-byte wire pubkey). The instruction set is shared verbatim with every
//! other Vector program via [`vector_common`]; only [`scheme`] differs.
#![no_std]

use pinocchio::{entrypoint, nostd_panic_handler, AccountView, Address, ProgramResult};
use solana_address::declare_id;
use vector_common::dispatch;

mod scheme;
use scheme::Falcon512;

entrypoint!(process_instruction);
nostd_panic_handler!();

declare_id!("HdkE3dPYgCRZJgLv64mbFmojyCprUim8VRXzK2wR6Qgm");

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    dispatch::<Falcon512>(program_id, accounts, instruction_data)
}
