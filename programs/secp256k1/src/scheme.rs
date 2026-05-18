use pinocchio::error::ProgramError;
use solana_secp256k1::{CompressedPoint, Secp256k1Point};
use solana_secp256k1_ecdsa::{hash::Secp256k1EcdsaHash, Secp256k1EcdsaSignature};
use vector_common::SigningScheme;

const COMPRESSED_PUBKEY_LEN: usize = CompressedPoint::SIZE;

/// Plain secp256k1 ECDSA. Identity is the 33-byte sec1-compressed pubkey;
/// signatures are 64 bytes `(r, s)` verified via standard ECDSA (no
/// recovery).
pub struct Secp256k1Ecdsa;

impl SigningScheme for Secp256k1Ecdsa {
    const SIGNATURE_LEN: usize = 64;
    const IDENTITY_LEN: usize = COMPRESSED_PUBKEY_LEN;
    const INIT_PAYLOAD_LEN: usize = COMPRESSED_PUBKEY_LEN;

    fn populate_identity(payload: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        if payload.len() != COMPRESSED_PUBKEY_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        // sec1 compressed pubkey: `0x02` (even y) or `0x03` (odd y) || x[32].
        if payload[0] != 0x02 && payload[0] != 0x03 {
            return Err(ProgramError::InvalidInstructionData);
        }
        identity_out.copy_from_slice(payload);
        Ok(())
    }

    fn verify(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
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
