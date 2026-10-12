use brine_ed25519::{hasher::FastSha512, verify};
use pinocchio::error::ProgramError;
use solana_address::{bytes_are_curve_point, Address};

use crate::scheme::SigningScheme;

/// Ed25519. A signature is the 64-byte `(R, s)`.
#[repr(C)]
pub struct Ed25519 {
    public_key: [u8; 32],
}

unsafe impl SigningScheme for Ed25519 {
    fn initialize(key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        let public_key: &[u8; 32] = key
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if !bytes_are_curve_point(public_key) {
            return Err(ProgramError::InvalidInstructionData);
        }
        identity.copy_from_slice(public_key);
        Ok(())
    }

    fn signature_len(&self) -> usize {
        64
    }

    fn advance(&self, digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        let signature: &[u8; 64] = signature
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        verify::<FastSha512>(
            &Address::new_from_array(self.public_key),
            signature,
            &[digest],
        )
        .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}
