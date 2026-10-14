use pinocchio::error::ProgramError;
use solana_winternitz::{winternitz, VerifyingKey, PUBLIC_KEY_LEN};

use crate::scheme::SigningScheme;

/// DKKW25 Winternitz. A key signs once, so every `Advance` replaces it.
#[repr(C)]
pub struct Winternitz {
    /// The key that signs next.
    public_key: [u8; PUBLIC_KEY_LEN],
}

unsafe impl SigningScheme for Winternitz {
    const SIGNATURE_LEN: usize = winternitz::SIGNATURE_LEN;
    const NEXT_KEY_LEN: usize = PUBLIC_KEY_LEN;

    fn initialize(key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        let public_key: &[u8; PUBLIC_KEY_LEN] = key
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        identity.copy_from_slice(public_key);
        Ok(())
    }

    /// The same key again would sign a second time.
    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &[u8],
        next_key: &[u8],
    ) -> Result<(), ProgramError> {
        let signature = winternitz::Signature::ref_from_bytes(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        VerifyingKey::ref_from_bytes(&self.public_key)
            .map_err(|_| ProgramError::InvalidAccountData)?
            .verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)?;

        let next_key: [u8; PUBLIC_KEY_LEN] = next_key
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if next_key == self.public_key {
            return Err(ProgramError::InvalidInstructionData);
        }
        self.public_key = next_key;
        Ok(())
    }
}
