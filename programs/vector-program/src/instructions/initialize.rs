use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use solana_address::bytes_are_curve_point;

use crate::state::VectorAccount;

/// Create a new vector account at the canonical PDA for `address`.
///
/// Instruction data: `seed: [u8; 32] || address: [u8; 32]`.
///
/// Accounts:
/// 0. `[signer, writable]` payer
/// 1. `[writable]`         vector PDA
/// 2. `[]`                 system program
pub fn process(
    _program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let [payer, vector, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let (seed, address) = parse_init_data(instruction_data)?;

    // Off-curve "addresss" can never be satisfied by an Ed25519 signature, so
    // the resulting PDA would be unusable.
    if !bytes_are_curve_point(address) {
        return Err(ProgramError::InvalidInstructionData);
    }

    let (expected_pda, bump) = Address::find_program_address(&[b"vector", address], &crate::ID);
    if vector.address() != &expected_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    let bump_arr = [bump];
    let seeds = [
        Seed::from(b"vector"),
        Seed::from(address),
        Seed::from(&bump_arr),
    ];
    let signers = [Signer::from(&seeds)];

    CreateAccount::with_minimum_balance(
        payer,
        vector,
        VectorAccount::LEN as u64,
        &crate::ID,
        None,
    )?
    .invoke_signed(&signers)?;

    let vector_account: &mut VectorAccount = vector.try_into()?;
    vector_account.seed = *seed;
    vector_account.address = *address;
    vector_account.bump = bump;

    Ok(())
}

#[inline(always)]
fn parse_init_data(data: &[u8]) -> Result<(&[u8; 32], &[u8; 32]), ProgramError> {
    let (seed, rest) = data
        .split_first_chunk::<32>()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let (address, rest) = rest
        .split_first_chunk::<32>()
        .ok_or(ProgramError::InvalidInstructionData)?;
    if !rest.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok((seed, address))
}
