use pinocchio::{error::ProgramError, sysvars::instructions::INSTRUCTIONS_ID, AccountView};
use solana_nostd_sha256::hashv;

use crate::helpers::read_u16_at;

/// What every signer of the executing instruction approves: the SHA-256 of
/// the instructions sysvar with the signatures cut out.
///
/// The signatures are the tail of the executing instruction's data, after
/// its first `prefix_len` bytes. Nothing else is cut, so the message covers
/// every other byte of every instruction in the transaction.
pub fn message(sysvar: &AccountView, prefix_len: usize) -> Result<[u8; 32], ProgramError> {
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
