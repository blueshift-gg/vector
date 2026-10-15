use pinocchio::error::ProgramError;
use solana_secp256k1::{CompressedPoint, Secp256k1Point};
use solana_secp256k1_ecdsa::{hash::Secp256k1EcdsaHash, Secp256k1EcdsaSignature};

use crate::scheme::{write, SigningScheme};

/// Plain secp256k1 ECDSA, with no recovery. A signature is the 64-byte
/// `(r, s)`.
#[repr(C)]
pub struct Secp256k1 {
    /// sec1-compressed: `0x02` or `0x03`, then the x coordinate.
    public_key: [u8; CompressedPoint::SIZE],
}

unsafe impl SigningScheme for Secp256k1 {
    const ID: u8 = 3;
    type Key = [u8; CompressedPoint::SIZE];
    type Signature = [u8; 64];
    type NextKey = [u8; 0];

    fn initialize(key: &Self::Key, identity: &mut [u8]) -> Result<(), ProgramError> {
        if key[0] != 0x02 && key[0] != 0x03 {
            return Err(ProgramError::InvalidInstructionData);
        }
        write(identity, key)
    }

    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &[u8; 64],
        _next_key: &[u8; 0],
    ) -> Result<(), ProgramError> {
        Secp256k1EcdsaSignature(*signature)
            .verify::<PreHashed, CompressedPoint>(digest, CompressedPoint(self.public_key))
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}

/// The message handed to the verifier is already the digest to verify.
struct PreHashed;

impl Secp256k1EcdsaHash for PreHashed {
    /// The message is always the 32-byte digest. Anything else would hash to
    /// zeros, which no signature verifies over.
    #[inline(always)]
    fn hash(message: &[u8]) -> [u8; 32] {
        message.first_chunk().copied().unwrap_or_default()
    }
}
