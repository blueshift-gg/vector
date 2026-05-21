use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Empty the vector PDA lamports into `receiver`. The runtime zeroes account
/// data and reassigns ownership to System once lamports hit zero at the
/// instruction boundary.
///
/// Top-level invocation is rejected: the `is_signer()` gate only passes
/// when this instruction is reached as a CPI from `passthrough` (which
/// signs as the PDA via `invoke_signed`). Authorisation is therefore
/// inherited from the offchain signature on the sibling `advance`, whose
/// digest commits to the passthrough's bytes. This handler is
/// scheme-independent.
///
/// Instruction data: empty.
///
/// Accounts:
/// 0. `[signer, writable]` vector PDA  (signer flag promoted by Passthrough)
/// 1. `[writable]`         receiver
pub fn process(
    _program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let [vector, receiver] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !vector.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Disallow draining into self.
    if vector.address() == receiver.address() {
        return Err(ProgramError::InvalidAccountData);
    }

    let amount = vector.lamports();
    let new_receiver_lamports = receiver
        .lamports()
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    vector.set_lamports(0);
    receiver.set_lamports(new_receiver_lamports);

    Ok(())
}
