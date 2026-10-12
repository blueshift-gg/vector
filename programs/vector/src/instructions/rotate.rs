use pinocchio::{error::ProgramError, AccountView, ProgramResult};

use crate::state::VectorAccount;

/// # Rotate
///
/// Replace the account's key. Only schemes with a replaceable key have it
/// (Winternitz, XMSS); the address and the nonce do not change.
///
/// It only runs inside a `Passthrough`, which is what makes the account a
/// signer. The current key's signature on the `Advance` covers the new key.
///
/// Accounts:
///
/// 1. vector:      [signer, mut]
///
/// Parameters:
///
/// - key: the new public key, as `Initialize` takes it
///
/// Account Checks:
/// - Vector: signer, owned by the program, of a scheme that can rotate
pub struct Rotate<'a> {
    vector: &'a mut AccountView,
    key: &'a [u8],
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Rotate<'a> {
    type Error = ProgramError;

    fn try_from((key, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        let [vector] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Account Checks
        if !vector.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        Ok(Self { vector, key })
    }
}

impl<'a> Rotate<'a> {
    pub const DISCRIMINATOR: &'a u8 = &5;

    pub fn process(&mut self) -> ProgramResult {
        let scheme = VectorAccount::scheme(self.vector)?;
        let mut data = self.vector.try_borrow_mut()?;
        let (_, identity) = VectorAccount::split(&mut data)?;

        scheme.rotate(self.key, identity)
    }
}
