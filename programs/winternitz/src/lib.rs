//! Vector authorization with DKKW25 one-time Winternitz over Keccak-256.
#![no_std]

use pinocchio::{entrypoint, nostd_panic_handler, AccountView, Address, ProgramResult};
use solana_address::declare_id;
use vector_common::rotating::dispatch;

mod scheme;
use scheme::Winternitz;

entrypoint!(process_instruction);
nostd_panic_handler!();

declare_id!("GvCGfvMTr8YZJZkV9KxaGF1Y2EzxUksur8iDwjVwJwGf");

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    dispatch::<Winternitz>(program_id, accounts, instruction_data)
}
