use pinocchio::{error::ProgramError, sysvars::instructions::INSTRUCTIONS_ID, AccountView};

use crate::helpers::read_u16_at;

const DISCRIMINATOR_LEN: usize = 1;

/// The pre/post slices of the instructions sysvar bracketing the executing
/// instruction's signature region. `pre || sig || post` reconstructs the
/// entire sysvar; carving out `sig` is what lets the signature embed itself
/// in the buffer it signs.
pub struct VectorBuffer<'a> {
    pub pre: &'a [u8],
    pub post: &'a [u8],
}

impl<'a> VectorBuffer<'a> {
    /// Construct a `VectorBuffer` from the instructions sysvar, carving out
    /// `sig_len` bytes (scheme-dependent) after the discriminator.
    pub fn from_instructions_sysvar(
        account: &'a AccountView,
        sig_len: usize,
    ) -> Result<Self, ProgramError> {
        if account.address() != &INSTRUCTIONS_ID {
            return Err(ProgramError::UnsupportedSysvar);
        }

        // Leak the borrow so the slice can live for `'a`. The sysvar is
        // read-only.
        core::mem::forget(account.try_borrow()?);

        // SAFETY: the leaked borrow keeps the data immutable for `'a`.
        let data: &'a [u8] =
            unsafe { core::slice::from_raw_parts(account.data_ptr(), account.data_len()) };

        // Sysvar layout:
        //   [0..2]                          num_instructions (u16 LE)
        //   [2..2 + 2 * num_instructions]   u16 LE offset per instruction
        //   ...instruction regions...
        //   [len - 2..len]                  current instruction index (u16 LE)
        if data.len() < 6 {
            return Err(ProgramError::InvalidAccountData);
        }

        let num_instructions = read_u16_at(data, 0)? as usize;
        let current_index = read_u16_at(data, data.len() - 2)? as usize;
        if current_index >= num_instructions {
            return Err(ProgramError::InvalidAccountData);
        }

        let ix_offset_pos = current_index
            .checked_mul(2)
            .and_then(|n| n.checked_add(2))
            .ok_or(ProgramError::InvalidAccountData)?;
        let ix_offset = read_u16_at(data, ix_offset_pos)? as usize;

        // Instruction region layout:
        //   [0..2]                       num_accounts (u16 LE)
        //   [2..2 + 33 * num_accounts]   metas (1 flag byte + 32 addr each)
        //   [+ 32]                       program id
        //   [+ 2]                        data_len (u16 LE)
        //   [...]                        instruction data (disc byte first)
        let num_accounts = read_u16_at(data, ix_offset)? as usize;

        let metas_len = num_accounts
            .checked_mul(33)
            .ok_or(ProgramError::InvalidAccountData)?;
        let disc_pos = ix_offset
            .checked_add(2)
            .and_then(|n| n.checked_add(metas_len))
            .and_then(|n| n.checked_add(32))
            .and_then(|n| n.checked_add(2))
            .ok_or(ProgramError::InvalidAccountData)?;

        let sig_start = disc_pos
            .checked_add(DISCRIMINATOR_LEN)
            .ok_or(ProgramError::InvalidAccountData)?;
        let sig_end = sig_start
            .checked_add(sig_len)
            .ok_or(ProgramError::InvalidAccountData)?;

        // Bounds-check the signature region and the trailing index footer.
        if sig_end
            .checked_add(2)
            .ok_or(ProgramError::InvalidAccountData)?
            > data.len()
        {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(VectorBuffer {
            pre: &data[..sig_start],
            post: &data[sig_end..],
        })
    }
}
