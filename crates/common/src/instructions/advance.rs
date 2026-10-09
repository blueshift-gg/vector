use pinocchio::{error::ProgramError, sysvars::instructions::INSTRUCTIONS_ID, AccountView};
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
/// `Advance` data is `[discriminator, sig_1..sig_n]` for accounts
/// `[vector_1..vector_n, instructions_sysvar]`. The signatures are everything
/// after the discriminator and nothing else is cut, so the message covers
/// every other byte of every instruction in the transaction. That is what
/// authorises a sibling `passthrough`.
pub fn message(sysvar: &AccountView) -> Result<[u8; 32], ProgramError> {
    cpi_guard()?;
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

    // The cut starts after the discriminator and ends before the index footer.
    if data_len == 0 || data_end + 2 > data.len() {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(hashv(&[&data[..data_start + 1], &data[data_end..]]))
}

/// Verify one signer of an `Advance`: take scheme `S`'s signature off the
/// front of `signatures`, check it over `SHA256(message || nonce ||
/// address)`, install that digest as the account's next nonce, and return
/// the signatures that follow. `S` is the scheme in `vector`'s header.
pub fn process<'a, S: SigningScheme>(
    vector: &mut AccountView,
    message: &[u8; 32],
    signatures: &'a [u8],
) -> Result<&'a [u8], ProgramError> {
    let (signature, rest) = signatures
        .split_at_checked(S::SIGNATURE_LEN)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let address = vector.address().to_bytes();
    let mut data = vector.try_borrow_mut()?;
    let identity = data
        .get(VectorAccount::HEADER_LEN..VectorAccount::HEADER_LEN + S::IDENTITY_LEN)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let digest = hashv(&[message, &data[..32], &address]);
    S::verify(identity, &digest, signature)?;
    data[..32].copy_from_slice(&digest);
    Ok(rest)
}
