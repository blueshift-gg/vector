use pinocchio::error::ProgramError;
use solana_secp256k1::{CompressedPoint, Secp256k1Point};
use solana_secp256k1_ecdsa::{hash::Secp256k1EcdsaHash, Secp256k1EcdsaSignature};

use crate::scheme::SigningScheme;

/// Plain secp256k1 ECDSA, with no recovery. A signature is the 64-byte
/// `(r, s)`.
#[repr(C)]
pub struct Secp256k1 {
    /// sec1-compressed: `0x02` or `0x03`, then the x coordinate.
    public_key: [u8; CompressedPoint::SIZE],
}

unsafe impl SigningScheme for Secp256k1 {
    const SIGNATURE_LEN: usize = 64;

    fn initialize(key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        let public_key: &[u8; CompressedPoint::SIZE] = key
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if public_key[0] != 0x02 && public_key[0] != 0x03 {
            return Err(ProgramError::InvalidInstructionData);
        }
        identity.copy_from_slice(public_key);
        Ok(())
    }

    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &[u8],
        _next_key: &[u8],
    ) -> Result<(), ProgramError> {
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        Secp256k1EcdsaSignature(signature)
            .verify::<PreHashed, CompressedPoint>(digest, CompressedPoint(self.public_key))
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}

/// The message handed to the verifier is already the digest to verify.
struct PreHashed;

impl Secp256k1EcdsaHash for PreHashed {
    #[inline(always)]
    fn hash(message: &[u8]) -> [u8; 32] {
        message.try_into().expect("digest must be 32 bytes")
    }
}
