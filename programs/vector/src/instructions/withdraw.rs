use pinocchio::{
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult,
};

use crate::state::VectorAccount;

/// # Withdraw
///
/// Send lamports from the account to the receiver, leaving enough for the
/// account to stay rent-exempt.
///
/// It only runs inside a `Passthrough`, which is what makes the account a
/// signer. The owner's signature on the `Advance` covers it.
///
/// Accounts:
///
/// 1. vector:      [signer, mut]
/// 2. receiver:    [mut]
///
/// Parameters:
///
/// - lamports: u64
///
/// Account Checks:
/// - Vector: signer, owned by the program, not the receiver
pub struct Withdraw<'a> {
    vector: &'a mut AccountView,
    receiver: &'a mut AccountView,
    lamports: u64,
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Withdraw<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        let [vector, receiver] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Account Checks
        if !vector.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if vector.address() == receiver.address() {
            return Err(ProgramError::InvalidAccountData);
        }

        let lamports = u64::from_le_bytes(
            data.try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );

        Ok(Self {
            vector,
            receiver,
            lamports,
        })
    }
}

impl<'a> Withdraw<'a> {
    pub const DISCRIMINATOR: &'a u8 = &3;

    pub fn process(&mut self) -> ProgramResult {
        let scheme = VectorAccount::scheme(self.vector)?;
        let rent = Rent::get()?.try_minimum_balance(VectorAccount::len(scheme))?;

        let remaining = self
            .vector
            .lamports()
            .checked_sub(self.lamports)
            .filter(|remaining| *remaining >= rent)
            .ok_or(ProgramError::InsufficientFunds)?;
        let received = self
            .receiver
            .lamports()
            .checked_add(self.lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        self.vector.set_lamports(remaining);
        self.receiver.set_lamports(received);

        Ok(())
    }
}
