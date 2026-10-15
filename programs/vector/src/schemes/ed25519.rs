use brine_ed25519::{hasher::FastSha512, verify};
use pinocchio::error::ProgramError;
use solana_address::{bytes_are_curve_point, Address};

use crate::scheme::SigningScheme;

/// Ed25519. A signature is the 64-byte `(R, s)`.
#[repr(C)]
pub struct Ed25519 {
    public_key: Address,
}

unsafe impl SigningScheme for Ed25519 {
    const ID: u8 = 1;
    type Key = Address;
    type Signature = [u8; 64];
    type NextKey = [u8; 0];

    fn initialize(key: &Address, identity: &mut [u8]) -> Result<(), ProgramError> {
        if !bytes_are_curve_point(key) {
            return Err(ProgramError::InvalidInstructionData);
        }
        identity.copy_from_slice(key.as_ref());
        Ok(())
    }

    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &[u8; 64],
        _next_key: &[u8; 0],
    ) -> Result<(), ProgramError> {
        verify::<FastSha512>(&self.public_key, signature, &[digest])
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}
