use pinocchio::{
    account::MAX_PERMITTED_DATA_INCREASE, error::ProgramError, AccountView, ProgramResult, Resize,
};

use crate::state::VectorAccount;

/// # Expand
///
/// Grow an account that was too big to create in one instruction, and fill
/// in what fits now. Only ML-DSA-44 has it. An instruction can grow an
/// account by 10,240 bytes, so it takes two of these after `Initialize`.
///
/// Permissionless: what is written depends only on the key already stored.
///
/// > Grow the account by one step, up to its full length
/// > Let the scheme fill in the new bytes
///
/// Accounts:
///
/// 1. vector:      [mut]
///
/// Parameters: None
///
/// Account Checks:
/// - Vector: owned by the program, of a scheme that expands, not complete
pub struct Expand<'a> {
    vector: &'a mut AccountView,
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Expand<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        let [vector] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        if !data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }

        Ok(Self { vector })
    }
}

impl<'a> Expand<'a> {
    pub const DISCRIMINATOR: &'a u8 = &5;

    pub fn process(&mut self) -> ProgramResult {
        let scheme = VectorAccount::scheme(self.vector)?;

        let old_len = self.vector.data_len();
        let new_len = VectorAccount::len(scheme).min(old_len + MAX_PERMITTED_DATA_INCREASE);
        self.vector.resize(new_len)?;

        let mut data = self.vector.try_borrow_mut()?;
        let (_, identity) = VectorAccount::split(&mut data)?;
        scheme.expand(identity, old_len.saturating_sub(VectorAccount::HEADER_LEN))
    }
}
