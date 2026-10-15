use pinocchio::error::ProgramError;
use solana_winternitz::{winternitz::Signature, VerifyingKey};

use crate::{
    error::VectorError,
    scheme::{write, SigningScheme},
};

/// DKKW25 Winternitz. A key signs once, so every `Advance` replaces it.
#[repr(C)]
pub struct Winternitz {
    /// The key that signs next.
    public_key: VerifyingKey,
}

unsafe impl SigningScheme for Winternitz {
    const ID: u8 = 6;
    type Key = VerifyingKey;
    type Signature = Signature;
    type NextKey = VerifyingKey;

    fn initialize(key: &VerifyingKey, identity: &mut [u8]) -> Result<(), ProgramError> {
        write(identity, key.as_bytes())
    }

    /// The same key again would sign a second time.
    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &Signature,
        next_key: &VerifyingKey,
    ) -> Result<(), ProgramError> {
        self.public_key
            .verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)?;
        if *next_key == self.public_key {
            return Err(VectorError::KeyReused.into());
        }
        self.public_key = *next_key;
        Ok(())
    }
}
