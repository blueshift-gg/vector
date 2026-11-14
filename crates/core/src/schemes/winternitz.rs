//! DKKW25 one-time Winternitz. Sign through `solana_winternitz::SigningKey`:
//! each key permits one signing attempt, including failed salt sampling.

use pinocchio::error::ProgramError;
use solana_winternitz::{Signature, VerifyingKey};

use solana_nostd_sha256::hash;

use crate::{
    error::VectorError,
    scheme::{write, Scheme, SigningScheme, SIGNED_LEN},
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

    #[inline]
    fn initialize(key: &VerifyingKey, identity: &mut [u8]) -> Result<(), ProgramError> {
        write(identity, key.as_bytes())
    }

    /// The same key again would sign a second time.
    #[inline]
    fn advance(
        &mut self,
        signed: &[u8; SIGNED_LEN],
        signature: &Signature,
        next_key: &VerifyingKey,
    ) -> Result<(), ProgramError> {
        self.public_key
            .verify(&hash(signed), signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)?;
        if *next_key == self.public_key {
            return Err(VectorError::KeyReused.into());
        }
        self.public_key = *next_key;
        Ok(())
    }
}

/// The first key is the permanent identity. The account stores the key that
/// signs next, which changes as it rotates.
pub const WINTERNITZ: Scheme = Scheme::of::<Winternitz>();

#[cfg(feature = "client")]
pub use client::*;

#[cfg(feature = "client")]
mod client {
    #[allow(unused_imports)]
    use super::*;

    use solana_address::Address;
    use solana_instruction::Instruction;

    use crate::instructions::create_initialize_instruction;

    /// Initialize a stable account with its first signing key.
    pub fn create_initialize_winternitz(
        payer: &Address,
        public_key: &[u8; WINTERNITZ.identity_len],
    ) -> Instruction {
        create_initialize_instruction(payer, &WINTERNITZ, public_key)
    }
}
