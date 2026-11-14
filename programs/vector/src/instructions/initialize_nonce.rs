use pinocchio::{error::ProgramError, AccountView, ProgramResult};

use crate::{
    error::VectorError,
    state::{NonceAccount, NonceAccountExt as _, VectorAccount, VectorAccountExt as _},
};

/// # InitializeNonce
///
/// Make an account a nonce account of a vector: one more nonce its key can
/// sign over, so its transactions need not wait on one another. As with the
/// System program's nonce accounts, the caller creates the account first,
/// assigned to this program and `NonceAccount::LEN` bytes long. The nonce account signs, as
/// it does that `CreateAccount`, so no one can initialize it in between.
/// Anyone can, for any vector: only the vector's key can advance it, from
/// the next slot, and close it.
///
/// > Write `nonce = SHA256("nonce" || address || latest slot hash)`, the
/// >   vector, and the slot
///
/// Accounts:
///
/// 1. nonce:   [signer, mut]
/// 2. vector:
///
/// Parameters: None
///
/// Account Checks:
/// - Nonce: signer, owned by the program, `NonceAccount::LEN` bytes, not
///   initialized
/// - Vector: a vector account, of a scheme whose key does not rotate
pub struct InitializeNonce<'a> {
    nonce: &'a mut AccountView,
    vector: [u8; 32],
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for InitializeNonce<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        let [nonce, vector] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        if !data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }

        // Account Checks: a vector account is the program's and never
        // `NonceAccount::LEN` bytes, so it is not a nonce account.
        if !nonce.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if !NonceAccount::is(nonce) {
            return Err(ProgramError::InvalidAccountData);
        }
        // The vector's address is derived from its scheme, so this holds for
        // as long as the address does.
        if VectorAccount::load(vector)?.0.next_key_len != 0 {
            return Err(VectorError::KeyRotates.into());
        }

        Ok(Self {
            nonce,
            vector: vector.address().to_bytes(),
        })
    }
}

impl<'a> InitializeNonce<'a> {
    pub const DISCRIMINATOR: &'a u8 = &vector_signer::INITIALIZE_NONCE_DISCRIMINATOR;

    pub fn process(&mut self) -> ProgramResult {
        let new = NonceAccount::create(&self.nonce.address().to_bytes(), self.vector)?;
        let mut account = NonceAccount::load(self.nonce)?;
        // A vector address is never zero, so a zero one is a new account.
        if account.vector != [0; 32] {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
        *account = new;
        Ok(())
    }
}
