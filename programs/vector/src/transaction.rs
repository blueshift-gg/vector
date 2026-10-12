//! The transaction being executed, as the runtime describes it in the
//! instructions sysvar. This is what a vector account's owner signs.

use pinocchio::{error::ProgramError, sysvars::instructions::INSTRUCTIONS_ID, AccountView};

/// The sysvar describes the transaction's top-level instructions, so an
/// instruction that reads it must be one of them. Called from inside another
/// instruction, it would be reading its caller's place in the list.
#[inline(always)]
pub fn top_level_only() -> Result<(), ProgramError> {
    #[cfg(target_os = "solana")]
    {
        /// Stack height of a top-level (non-CPI) instruction.
        const TRANSACTION_LEVEL_STACK_HEIGHT: u64 = 1;

        if unsafe { pinocchio::syscalls::sol_get_stack_height() } != TRANSACTION_LEVEL_STACK_HEIGHT
        {
            return Err(ProgramError::IncorrectAuthority);
        }
    }
    Ok(())
}

/// The account is the instructions sysvar.
pub fn check_instructions_sysvar(account: &AccountView) -> Result<(), ProgramError> {
    if account.address() != &INSTRUCTIONS_ID {
        return Err(ProgramError::UnsupportedSysvar);
    }
    Ok(())
}

/// The instructions sysvar's data:
///
/// ```text
/// [0..2]                          num_instructions (u16 LE)
/// [2..2 + 2 * num_instructions]   offset of each instruction (u16 LE)
/// ...instructions...
/// [len - 2..len]                  index of the executing instruction (u16 LE)
/// ```
pub struct Transaction<'a> {
    data: &'a [u8],
}

/// One instruction in it:
///
/// ```text
/// [0..2]                       num_accounts (u16 LE)
/// [2..2 + 33 * num_accounts]   accounts: flags (1 byte), address (32 bytes)
/// [+ 32]                       program id
/// [+ 2]                        data_len (u16 LE)
/// [...]                        data
/// ```
pub struct Instruction<'a> {
    /// Each account's flags byte followed by its address.
    pub accounts: &'a [[u8; 33]],
    pub program_id: &'a [u8; 32],
    pub data: &'a [u8],
    /// Where `data` starts in the sysvar.
    pub data_offset: usize,
}

impl<'a> Transaction<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Index of the instruction being executed.
    pub fn current_index(&self) -> Result<usize, ProgramError> {
        let footer = self
            .data
            .len()
            .checked_sub(2)
            .ok_or(ProgramError::InvalidAccountData)?;
        self.read_u16(footer)
    }

    pub fn instruction(&self, index: usize) -> Result<Instruction<'a>, ProgramError> {
        // Every value below is a u16, so none of this overflows.
        let offset = self.read_u16(2 + 2 * index)?;
        let accounts_end = offset + 2 + 33 * self.read_u16(offset)?;
        let data_offset = accounts_end + 32 + 2;
        let data_len = self.read_u16(accounts_end + 32)?;

        let slice = |start, end| {
            self.data
                .get(start..end)
                .ok_or(ProgramError::InvalidAccountData)
        };
        Ok(Instruction {
            accounts: slice(offset + 2, accounts_end)?.as_chunks().0,
            program_id: slice(accounts_end, accounts_end + 32)?
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
            data: slice(data_offset, data_offset + data_len)?,
            data_offset,
        })
    }

    fn read_u16(&self, offset: usize) -> Result<usize, ProgramError> {
        let bytes = self
            .data
            .get(offset..offset + 2)
            .ok_or(ProgramError::InvalidAccountData)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
    }
}
