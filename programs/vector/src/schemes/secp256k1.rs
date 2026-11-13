use pinocchio::error::ProgramError;
use solana_secp256k1::{CompressedPoint, Secp256k1Point, UncompressedPoint};
use solana_secp256k1_ecdsa::{hash::sha256::Sha256, Secp256k1EcdsaSignature};

use crate::scheme::{write, SigningScheme, SIGNED_LEN};

/// Plain secp256k1 ECDSA, with no recovery, over the SHA-256 of `"vector:" ||
/// digest`. A signature is the 64-byte `(r, s)`.
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
        // The prefix, then that the x coordinate is on the curve: a key that
        // is not could never sign, and would hold the account for good.
        let point = CompressedPoint::try_from_sec1_bytes(key)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        UncompressedPoint::try_from(point).map_err(|_| ProgramError::InvalidInstructionData)?;
        write(identity, key)
    }

    fn advance(
        &mut self,
        signed: &[u8; SIGNED_LEN],
        signature: &[u8; 64],
        _next_key: &[u8; 0],
    ) -> Result<(), ProgramError> {
        Secp256k1EcdsaSignature(*signature)
            .verify::<Sha256, CompressedPoint>(signed, CompressedPoint(self.public_key))
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}
