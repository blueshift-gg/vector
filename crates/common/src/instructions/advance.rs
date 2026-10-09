use pinocchio::{
    error::ProgramError, sysvars::instructions::INSTRUCTIONS_ID, AccountView, Address,
};
use solana_nostd_sha256::hashv;

use crate::{helpers::read_u16_at, scheme::SigningScheme, state::VectorAccount};

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

/// The message every signer of the executing `Advance` approves: the
/// SHA-256 of the instructions sysvar with the signatures cut out.
///
/// `Advance` data is `[discriminator, scheme_1..scheme_n, sig_1..sig_n]` for
/// accounts `[vector_1..vector_n, instructions_sysvar]`. The signatures are
/// the tail of that data and nothing else is cut, so the message covers
/// every other byte of every instruction in the transaction. That is what
/// authorises a sibling `passthrough`.
pub fn message(sysvar: &AccountView, signers: usize) -> Result<[u8; 32], ProgramError> {
    cpi_guard()?;
    let prefix_len = 1 + signers;
    if sysvar.address() != &INSTRUCTIONS_ID {
        return Err(ProgramError::UnsupportedSysvar);
    }
    let data = sysvar.try_borrow()?;

    // Sysvar layout:
    //   [0..2]                          num_instructions (u16 LE)
    //   [2..2 + 2 * num_instructions]   u16 LE offset per instruction
    //   ...instruction regions...
    //   [len - 2..len]                  current instruction index (u16 LE)
    if data.len() < 6 {
        return Err(ProgramError::InvalidAccountData);
    }
    let num_instructions = read_u16_at(&data, 0)? as usize;
    let current_index = read_u16_at(&data, data.len() - 2)? as usize;
    if current_index >= num_instructions {
        return Err(ProgramError::InvalidAccountData);
    }
    let ix_offset = read_u16_at(&data, 2 + 2 * current_index)? as usize;

    // Instruction region layout:
    //   [0..2]                       num_accounts (u16 LE)
    //   [2..2 + 33 * num_accounts]   metas (1 flag byte + 32 addr each)
    //   [+ 32]                       program id
    //   [+ 2]                        data_len (u16 LE)
    //   [...]                        instruction data
    // Every value is a u16, so none of this overflows.
    let num_accounts = read_u16_at(&data, ix_offset)? as usize;
    let data_len_pos = ix_offset + 2 + 33 * num_accounts + 32;
    let data_len = read_u16_at(&data, data_len_pos)? as usize;
    let data_start = data_len_pos + 2;
    let data_end = data_start + data_len;

    // The cut stays inside the instruction data, before the index footer.
    if prefix_len > data_len || data_end + 2 > data.len() {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(hashv(&[
        &data[..data_start + prefix_len],
        &data[data_end..],
    ]))
}

/// Verify one signer of an `Advance`: take scheme `S`'s signature off the
/// front of `signatures`, check it over `SHA256(message || nonce ||
/// identity)`, install that digest as the account's next nonce, and return
/// the signatures that follow.
pub fn process<'a, S: SigningScheme>(
    program_id: &Address,
    vector: &mut AccountView,
    message: &[u8; 32],
    signatures: &'a [u8],
) -> Result<&'a [u8], ProgramError> {
    let (signature, rest) = signatures
        .split_at_checked(S::SIGNATURE_LEN)
        .ok_or(ProgramError::InvalidInstructionData)?;
    if !vector.owned_by(program_id) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let mut data = vector.try_borrow_mut()?;
    VectorAccount::check_scheme::<S>(&data)?;
    let identity = data
        .get(VectorAccount::HEADER_LEN..VectorAccount::HEADER_LEN + S::IDENTITY_LEN)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let digest = hashv(&[message, &data[..32], S::digest_identity(identity)]);
    S::verify(identity, &digest, signature)?;
    data[..32].copy_from_slice(&digest);
    Ok(rest)
}
