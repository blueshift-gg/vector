use pinocchio::error::ProgramError;
use solana_winternitz::{xmss, VerifyingKey, PUBLIC_KEY_LEN};

use crate::scheme::SigningScheme;

/// DKKW25 XMSS. A key signs as many times as its tree has leaves, so a
/// `Passthrough` may keep it or replace it.
#[repr(C)]
pub struct Xmss {
    public_key: [u8; PUBLIC_KEY_LEN],
}

unsafe impl SigningScheme for Xmss {
    fn initialize(key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        let public_key: &[u8; PUBLIC_KEY_LEN] = key
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        identity.copy_from_slice(public_key);
        Ok(())
    }

    fn signature_len(&self) -> usize {
        xmss::SIGNATURE_LEN
    }

    fn advance(&self, digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        let signature = xmss::Signature::ref_from_bytes(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        VerifyingKey::ref_from_bytes(&self.public_key)
            .map_err(|_| ProgramError::InvalidAccountData)?
            .verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }

    /// The data starts with `0` to keep the key, or `1` and the key that
    /// signs next. The owner signed the whole transaction, the key included.
    fn passthrough<'a>(&mut self, data: &'a [u8]) -> Result<&'a [u8], ProgramError> {
        match data.split_first() {
            Some((0, instructions)) => Ok(instructions),
            Some((1, data)) => {
                let (public_key, instructions) = data
                    .split_first_chunk()
                    .ok_or(ProgramError::InvalidInstructionData)?;
                self.public_key = *public_key;
                Ok(instructions)
            }
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}
