use pinocchio::{error::ProgramError, AccountView, ProgramResult};

/// # Withdraw
///
/// Send lamports from the account to the receiver. The runtime refuses to
/// leave it with less than rent-exemption but more than nothing.
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
/// - Vector: signer
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

        // Account Checks: the runtime refuses to debit an account the
        // program does not own, or to change the lamports an instruction
        // holds in total, so a receiver that is the vector fails.
        if !vector.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
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
        let remaining = self
            .vector
            .lamports()
            .checked_sub(self.lamports)
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
