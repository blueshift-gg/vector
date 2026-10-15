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
/// - Vector: signer
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

        // Account Checks: the runtime refuses to debit an account the
        // program does not own, or to change the lamports an instruction
        // holds in total, so a receiver that is the vector fails.
        if !vector.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        if !data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }

        Ok(Self { vector, receiver })
    }
}

impl<'a> Close<'a> {
    pub const DISCRIMINATOR: &'a u8 = &4;

    pub fn process(&mut self) -> ProgramResult {
        // Every lamport there is fits a u64.
        let lamports = self.receiver.lamports() + self.vector.lamports();
        self.vector.set_lamports(0);
        self.receiver.set_lamports(lamports);

        Ok(())
    }
}
