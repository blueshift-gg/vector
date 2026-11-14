use pinocchio::{error::ProgramError, AccountView, ProgramResult};

use pinocchio::sysvars::{clock::Clock, Sysvar};

use crate::{
    error::VectorError,
    state::{NonceAccount, VectorAccount},
};

/// # Close
///
/// Send all of an account's lamports to the receiver: the vector's, or with
/// a nonce account listed, that nonce account's. The runtime removes an
/// account with no lamports at the end of the transaction.
///
/// It only runs inside a `Passthrough`, which is what makes the vector a
/// signer. The owner's signature on the `Advance` covers it.
///
/// Accounts:
///
/// 1. vector:      [signer, mut]
/// 2. receiver:    [mut]
/// 3. nonce:       [mut] optional, a nonce account of the vector
///
/// Parameters: None
///
/// Account Checks:
/// - Vector: signer, and a complete vector account of the program. Closing
///   the vector itself needs a slot after the one it was created in
/// - Nonce: a nonce account of the vector, past the slot it was created in
pub struct Close<'a> {
    account: &'a mut AccountView,
    receiver: &'a mut AccountView,
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Close<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        let (vector, receiver, nonce) = match accounts {
            [vector, receiver] => (vector, receiver, None),
            [vector, receiver, nonce] => (vector, receiver, Some(nonce)),
            _ => return Err(ProgramError::NotEnoughAccountKeys),
        };

        // Account Checks: the runtime refuses to debit an account the
        // program does not own, or to change the lamports an instruction
        // holds in total, so a receiver that is the closed account fails.
        if !vector.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        if !data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }

        // Only a vector account closes as a vector: a nonce account's own
        // keypair can sign here too, and it is not one.
        let (_, header) = VectorAccount::load(vector)?;
        let slot = Clock::get()?.slot;

        let account = match nonce {
            // The runtime refuses to debit an account the program does not
            // own, so only the vector's own nonce accounts close.
            Some(nonce) => {
                NonceAccount::borrow(nonce, &vector.address().to_bytes(), slot)?;
                nonce
            }
            // An account closed and created again in the slot it was created
            // in would start from a nonce it held before.
            None if header.created() >= slot => return Err(VectorError::FreshVector.into()),
            None => vector,
        };
        Ok(Self { account, receiver })
    }
}

impl<'a> Close<'a> {
    pub const DISCRIMINATOR: &'a u8 = &4;

    pub fn process(&mut self) -> ProgramResult {
        let lamports = self
            .receiver
            .lamports()
            .checked_add(self.account.lamports())
            .ok_or(ProgramError::ArithmeticOverflow)?;
        self.account.set_lamports(0);
        self.receiver.set_lamports(lamports);

        Ok(())
    }
}
