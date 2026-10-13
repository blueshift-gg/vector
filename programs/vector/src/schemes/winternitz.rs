use pinocchio::error::ProgramError;
use solana_winternitz::{winternitz, VerifyingKey, PUBLIC_KEY_LEN};

use crate::scheme::SigningScheme;

/// DKKW25 Winternitz. A key signs once: `Advance` erases it, and the
/// `Passthrough` that must follow stores the next one.
#[repr(C)]
pub struct Winternitz {
    /// The key that signs next, or zeros once it has signed.
    public_key: [u8; PUBLIC_KEY_LEN],
}

unsafe impl SigningScheme for Winternitz {
    fn initialize(key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        let public_key: &[u8; PUBLIC_KEY_LEN] = key
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        identity.copy_from_slice(public_key);
        Ok(())
    }

    fn signature_len(&self) -> usize {
        winternitz::SIGNATURE_LEN
    }

    fn advance(&mut self, digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        let signature = winternitz::Signature::ref_from_bytes(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        VerifyingKey::ref_from_bytes(&self.public_key)
            .map_err(|_| ProgramError::InvalidAccountData)?
            .verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)?;
        self.public_key = [0; PUBLIC_KEY_LEN];
        Ok(())
    }

    fn spent(&self) -> bool {
        self.public_key == [0; PUBLIC_KEY_LEN]
    }

    /// The data starts with the key that signs next. The owner signed the
    /// whole transaction, this key included.
    fn passthrough<'a>(&mut self, data: &'a [u8]) -> Result<&'a [u8], ProgramError> {
        let (public_key, instructions) = data
            .split_first_chunk()
            .ok_or(ProgramError::InvalidInstructionData)?;
        self.public_key = *public_key;
        Ok(instructions)
    }
}
