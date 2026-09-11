//! Vector authorization with DKKW25 generalized XMSS over Keccak-256.
#![no_std]

use pinocchio::{entrypoint, nostd_panic_handler, AccountView, Address, ProgramResult};
use solana_address::declare_id;
use vector_common::rotating::dispatch;

mod scheme;
use scheme::Xmss;

entrypoint!(process_instruction);
nostd_panic_handler!();

declare_id!("7qCyy3NJQDMctSDiM4DxNjNR6TyasouyyRTBREhcXdsE");

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    dispatch::<Xmss>(program_id, accounts, instruction_data)
}
