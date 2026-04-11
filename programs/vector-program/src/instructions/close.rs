use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use crate::helpers::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT};
use crate::state::{VectorAccount, VectorBuffer};

const SIGNATURE_LEN: usize = 64;

/// Verify the `close_vector_signature` and drain the vector PDA's lamports
/// into `close_to`.
///
/// Shares advance's signature scheme: the signer commits to the entire
/// `close_vector_buffer` (instructions sysvar with the 64-byte signature
/// region replaced by `seed || address`), differing only in the
/// discriminator byte (2 vs. 1). The recipient and surrounding instructions
/// are bound to the signature.
///
/// Instruction data (after the discriminator stripped by `lib.rs`):
///
/// ```text
/// [0..64]  close_vector_signature
/// ```
///
/// Accounts:
/// 0. `[writable]` vector PDA
/// 1. `[]`         instructions sysvar
/// 2. `[writable]` close_to
pub fn process(
    _program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    // `VectorBuffer` carves the signature hole at `current_instruction_index`,
    // which is only meaningful at the top level.
    if get_stack_height() != TRANSACTION_LEVEL_STACK_HEIGHT {
        return Err(ProgramError::InvalidInstructionData);
    }

    let [vector, instructions_sysvar, close_to] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Disallow draining the PDA into itself; the runtime balance check would
    // either double-credit or zero the account depending on write order.
    if vector.address() == close_to.address() {
        return Err(ProgramError::InvalidAccountData);
    }

    let (close_vector_signature, rest) = instruction_data
        .split_first_chunk::<SIGNATURE_LEN>()
        .ok_or(ProgramError::InvalidInstructionData)?;
    if !rest.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Scope the borrows so the lamport mutation below isn't blocked.
    {
        let vector_account: VectorAccount = (&*vector).try_into()?;
        let close_vector_buffer: VectorBuffer = (&*instructions_sysvar).try_into()?;
        let _ = vector_account.verify(&close_vector_buffer, close_vector_signature)?;
    }

    // The runtime zeroes data and owner for any account whose lamports hit
    // zero at the instruction boundary.
    let amount = vector.lamports();
    let new_close_to_lamports = close_to
        .lamports()
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    vector.set_lamports(0);
    close_to.set_lamports(new_close_to_lamports);

    Ok(())
}
