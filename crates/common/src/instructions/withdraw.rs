use pinocchio::{
    error::ProgramError, sysvars::rent::Rent, sysvars::Sysvar, AccountView, Address, ProgramResult,
};

use crate::scheme::SigningScheme;
use crate::state::VectorAccount;

/// Move `lamports` from the vector PDA to `receiver`, leaving the PDA with at
/// least its rent-minimum balance so the account survives.
///
/// Same authorisation model as [`close`](super::close): the `is_signer()`
/// gate only passes when reached as a CPI from `passthrough` (which
/// promotes the vector PDA via `invoke_signed`); the sibling `advance`'s
/// digest commits to the passthrough's bytes, so the offchain signature is
/// what authorises the transfer end-to-end.
///
/// Instruction data: `lamports: u64` (little-endian).
///
/// Accounts:
/// 0. `[signer, writable]` vector PDA  (signer flag promoted by Passthrough)
/// 1. `[writable]`         receiver
pub fn process<S: SigningScheme>(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let [vector, receiver] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !vector.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if vector.address() == receiver.address() {
        return Err(ProgramError::InvalidAccountData);
    }

    let amount_bytes: [u8; 8] = instruction_data
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let lamports = u64::from_le_bytes(amount_bytes);

    if !vector.owned_by(program_id) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    // Account length is fixed for a single-scheme program — no header read
    // needed to size the rent floor.
    let rent_min = Rent::get()?.try_minimum_balance(VectorAccount::account_len::<S>())?;

    let new_vector_lamports = vector
        .lamports()
        .checked_sub(lamports)
        .ok_or(ProgramError::InsufficientFunds)?;
    if new_vector_lamports < rent_min {
        return Err(ProgramError::InsufficientFunds);
    }

    let new_receiver_lamports = receiver
        .lamports()
        .checked_add(lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    vector.set_lamports(new_vector_lamports);
    receiver.set_lamports(new_receiver_lamports);

    Ok(())
}
