use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use crate::{scheme::SigningScheme, state::VectorAccount};

/// Vector's auth model relies on instructions-sysvar introspection, which is
/// only reliable in a top-level instruction. Reject any CPI invocation of
/// `advance` so a parent program cannot rewrite the sysvar layout the
/// signature was bound to.
#[inline(always)]
pub(crate) fn cpi_guard() -> Result<(), ProgramError> {
    #[cfg(target_os = "solana")]
    {
        /// Stack height of a top-level (non-CPI) instruction.
        const TRANSACTION_LEVEL_STACK_HEIGHT: u64 = 1;

        if unsafe { pinocchio::syscalls::sol_get_stack_height() } == TRANSACTION_LEVEL_STACK_HEIGHT
        {
            Ok(())
        } else {
            Err(ProgramError::IncorrectAuthority)
        }
    }
    #[cfg(not(target_os = "solana"))]
    {
        // Off-chain (host) builds can't trip this gate; treat as pass.
        Ok(())
    }
}

/// Verify the `advance_vector_signature` over the canonical
/// `advance_vector_digest` and install the digest as the next nonce.
/// CPI passthrough lives in the sibling [`crate::passthrough`] handler
/// (disc `4`); a tx that just wants to bump the nonce can call `advance`
/// alone.
///
/// Instruction data (after the discriminator stripped by [`crate::dispatch`]):
///
/// ```text
/// [0..sig_len]  advance_vector_signature  (scheme-defined: 64 / 65 / 555 / 666)
/// ```
///
/// Accounts:
/// 0. `[writable]` vector PDA
/// 1. `[]`         instructions sysvar
pub fn process<S: SigningScheme>(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    cpi_guard()?;

    let [vector, instructions_sysvar] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // `advance_nonce` verifies the sig over a digest that commits to the
    // ENTIRE instructions sysvar buffer (minus the sig bytes), so any
    // sibling `passthrough` ix's data + accounts in the same tx are
    // committed to as part of pre/post. That's what authorises a
    // standalone `passthrough` to run with `vector_pda`'s signer seeds.
    let outcome =
        VectorAccount::advance_nonce::<S>(vector, &*instructions_sysvar, program_id, data)?;
    if !outcome.payload.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(())
}
