use pinocchio::{error::ProgramError, AccountView, ProgramResult};

/// # Close
///
/// Send all of the account's lamports to the receiver. The runtime removes
/// an account with no lamports at the end of the transaction.
///
/// It only runs inside a `Passthrough`, which is what makes the account a
/// signer. The owner's signature on the `Advance` covers it.
///
/// Accounts:
///
/// 1. vector:      [signer, mut]
/// 2. receiver:    [mut]
///
/// Parameters: None
///
/// Account Checks:
/// - Vector: signer, owned by the program, not the receiver
pub struct Close<'a> {
    vector: &'a mut AccountView,
    receiver: &'a mut AccountView,
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Close<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        let [vector, receiver] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Account Checks
        if !vector.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if !vector.owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        if vector.address() == receiver.address() {
            return Err(ProgramError::InvalidAccountData);
        }

        if !data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }

        Ok(Self { vector, receiver })
    }
}

impl<'a> Close<'a> {
    pub const DISCRIMINATOR: &'a u8 = &2;

    pub fn process(&mut self) -> ProgramResult {
        let lamports = self
            .receiver
            .lamports()
            .checked_add(self.vector.lamports())
            .ok_or(ProgramError::ArithmeticOverflow)?;
        self.vector.set_lamports(0);
        self.receiver.set_lamports(lamports);

        Ok(())
    }
}
