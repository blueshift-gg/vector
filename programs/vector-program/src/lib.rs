#![no_std]
use pinocchio::{
    entrypoint, error::ProgramError, nostd_panic_handler, AccountView, Address, ProgramResult,
};
use solana_address::declare_id;

pub mod helpers;
pub mod instructions;
use crate::instructions::*;
pub mod state;

entrypoint!(process_instruction);
nostd_panic_handler!();

declare_id!("Vector1111111111111111111111111111111111111");

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (discriminator, rest) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    let instruction = VectorInstruction::try_from(discriminator)?;

    match instruction {
        VectorInstruction::InitializeVector => initialize::process(program_id, accounts, rest),
        VectorInstruction::AdvanceVector => advance::process(program_id, accounts, rest),
        VectorInstruction::CloseVector => close::process(program_id, accounts, rest),
    }
}
