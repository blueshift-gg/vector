use core::mem::MaybeUninit;

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::slot_hashes,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use solana_address::bytes_are_curve_point;
use solana_sha256_hasher::hashv;

use crate::state::VectorAccount;

/// Create a new vector account at the canonical PDA for `address`.
///
/// The seed is derived on-chain as `sha256(address || latest_slot_hash)`,
/// ensuring uniqueness even if the same address is re-initialized after close.
///
/// Instruction data: `address: [u8; 32]`.
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

    let address = parse_init_data(instruction_data)?;

    // Off-curve addresses can never be satisfied by an Ed25519 signature, so
    // the resulting PDA would be unusable.
    if !bytes_are_curve_point(address) {
        return Err(ProgramError::InvalidInstructionData);
    }

    let (expected_pda, bump) = Address::find_program_address(&[b"vector", address], &crate::ID);
    if vector.address() != &expected_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    // Derive seed from address + latest slot entry via get_sysvar syscall.
    // Read one entry (40 bytes) at offset 8 (past the entry count header).
    // Entry layout: [u64 slot_height, [u8; 32] slot_hash].
    let mut entry: [MaybeUninit<u8>; 40] = [MaybeUninit::uninit(); 40];
    let entry = unsafe {
        slot_hashes::fetch_into_unchecked(
            &mut *(entry.as_mut_ptr() as *mut [u8; 40]),
            8,
        )?;
        &*(entry.as_ptr() as *const [u8; 40])
    };
    let seed = hashv(&[address, entry]).to_bytes();

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
    vector_account.seed = seed;
    vector_account.address = *address;
    vector_account.bump = bump;

    Ok(())
}

#[inline(always)]
fn parse_init_data(data: &[u8]) -> Result<&[u8; 32], ProgramError> {
    let (address, rest) = data
        .split_first_chunk::<32>()
        .ok_or(ProgramError::InvalidInstructionData)?;
    if !rest.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(address)
}
