use pinocchio::{error::ProgramError, AccountView, Address};

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

/// The message every signer of the executing `Advance` approves.
///
/// `Advance` data is `[discriminator, scheme_1..scheme_n, sig_1..sig_n]` for
/// accounts `[vector_1..vector_n, instructions_sysvar]`. The message is the
/// whole instructions sysvar with `sig_1..sig_n` cut out, so it covers every
/// instruction in the transaction, this one's accounts and scheme bytes
/// included. That is what authorises a sibling `passthrough`.
pub fn message(
    instructions_sysvar: &AccountView,
    signers: usize,
) -> Result<[u8; 32], ProgramError> {
    cpi_guard()?;
    crate::buffer::message(instructions_sysvar, 1 + signers)
}

/// Verify one signer of an `Advance`: take scheme `S`'s signature off the
/// front of `signatures`, check it against `vector`, install the next nonce,
/// and return the signatures that follow.
pub fn process<'a, S: SigningScheme>(
    program_id: &Address,
    vector: &mut AccountView,
    message: &[u8; 32],
    signatures: &'a [u8],
) -> Result<&'a [u8], ProgramError> {
    let (signature, rest) = signatures
        .split_at_checked(S::SIGNATURE_LEN)
        .ok_or(ProgramError::InvalidInstructionData)?;
    VectorAccount::advance_nonce::<S>(vector, program_id, message, signature)?;
    Ok(rest)
}
