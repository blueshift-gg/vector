use crate::scheme::SigningScheme;
use pinocchio::error::ProgramError;
use solana_secp256k1::{CompressedPoint, Secp256k1Point};
use solana_secp256k1_ecdsa::{hash::Secp256k1EcdsaHash, Secp256k1EcdsaSignature};

const COMPRESSED_PUBKEY_LEN: usize = CompressedPoint::SIZE;

/// Plain secp256k1 ECDSA. Identity is the 33-byte sec1-compressed pubkey;
/// signatures are 64 bytes `(r, s)` verified via standard ECDSA (no
/// recovery).
pub struct Secp256k1Ecdsa;

impl Secp256k1Ecdsa {
    pub const ID: u8 = 3;
}

impl SigningScheme for Secp256k1Ecdsa {
    fn id(&self) -> u8 {
        Self::ID
    }

    fn signature_len(&self) -> usize {
        64
    }
    fn identity_len(&self) -> usize {
        COMPRESSED_PUBKEY_LEN
    }
    fn key_len(&self) -> usize {
        COMPRESSED_PUBKEY_LEN
    }

    fn initialize(&self, key: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        if key.len() != COMPRESSED_PUBKEY_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        // sec1 compressed pubkey: `0x02` (even y) or `0x03` (odd y) || x[32].
        if key[0] != 0x02 && key[0] != 0x03 {
            return Err(ProgramError::InvalidInstructionData);
        }
        identity_out.copy_from_slice(key);
        Ok(())
    }

    fn advance(
        &self,
        identity: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ProgramError> {
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let pubkey_bytes: [u8; COMPRESSED_PUBKEY_LEN] = identity
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;

        let sig = Secp256k1EcdsaSignature(sig_bytes);
        let pubkey = CompressedPoint(pubkey_bytes);
        sig.verify::<PreHashedDigest, CompressedPoint>(digest, pubkey)
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}

/// Pass-through hasher: the message handed to `verify` is already the 32-byte
/// SHA-256 digest the client signed, so no further hashing is needed.
struct PreHashedDigest;

impl Secp256k1EcdsaHash for PreHashedDigest {
    #[inline(always)]
    fn hash(message: &[u8]) -> [u8; 32] {
        // Caller guarantees `message` is the 32-byte digest.
        message.try_into().expect("digest must be 32 bytes")
    }
}
