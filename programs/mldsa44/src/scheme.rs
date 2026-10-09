use pinocchio::error::ProgramError;
use solana_ml_dsa::ml_dsa_44::{
    PreparedVerifyingKey, Signature, VerifyingKey, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
use vector_common::{IdentitySeed, SigningScheme, VectorAccount};

// SHAKE128/256, as specified by FIPS 204.
type PreparedKey = PreparedVerifyingKey<false>;

// The three-byte pad aligns prepared coefficients after the 33-byte header.
const PREPARED: usize = PUBLIC_KEY_LEN + 3;
const IDENTITY_LEN: usize = PREPARED + PreparedKey::BYTE_LEN;
const _: () = assert!((VectorAccount::HEADER_LEN + PREPARED).is_multiple_of(4));

/// ML-DSA-44 with an empty FIPS 204 context and the public key as identity.
pub struct MlDsa44;

impl MlDsa44 {
    pub const PREFIX_LEN: usize = PREPARED;

    /// Prepare rows that fit after growth but did not fit at `from`.
    /// The public key is immutable; account length records preparation progress.
    pub fn fill(identity: &mut [u8], from: usize) -> Result<(), ProgramError> {
        let len = identity.len();
        let (head, prepared) = identity
            .split_at_mut_checked(PREPARED)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        let pk = VerifyingKey::<false>::ref_from_bytes(&head[..PUBLIC_KEY_LEN])
            .map_err(|_| ProgramError::InvalidAccountData)?;
        for i in 0..PreparedKey::PUBLIC_KEY_HASH_OFFSET / PreparedKey::ROW_BYTE_LEN {
            let end = (i + 1) * PreparedKey::ROW_BYTE_LEN;
            if PREPARED + end > from && PREPARED + end <= len {
                let row = PreparedKey::borrow_row_mut(
                    &mut prepared[end - PreparedKey::ROW_BYTE_LEN..end],
                )
                .map_err(|_| ProgramError::InvalidAccountData)?;
                pk.prepare_row_into(i, row)
                    .map_err(|_| ProgramError::InvalidAccountData)?;
            }
        }
        if len == IDENTITY_LEN {
            prepared[PreparedKey::PUBLIC_KEY_HASH_OFFSET..].copy_from_slice(&pk.public_key_hash());
        }
        Ok(())
    }
}

impl SigningScheme for MlDsa44 {
    const SIGNATURE_LEN: usize = SIGNATURE_LEN;
    const IDENTITY_LEN: usize = IDENTITY_LEN;
    const INIT_PAYLOAD_LEN: usize = PUBLIC_KEY_LEN;

    fn populate_identity(payload: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        let public_key = VerifyingKey::<false>::ref_from_bytes(payload)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if identity_out.len() < PREPARED {
            return Err(ProgramError::AccountDataTooSmall);
        }
        identity_out[..PUBLIC_KEY_LEN].copy_from_slice(public_key.as_bytes());
        identity_out[PUBLIC_KEY_LEN..PREPARED].fill(0);
        Self::fill(identity_out, 0)
    }

    fn digest_identity(identity: &[u8]) -> &[u8] {
        &identity[..PUBLIC_KEY_LEN]
    }

    fn pda_seed_from_identity(identity: &[u8]) -> IdentitySeed {
        IdentitySeed::from_hash(&identity[..PUBLIC_KEY_LEN])
    }

    fn verify(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        let key = PreparedKey::ref_from_bytes(&identity[PREPARED..])
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let signature = Signature::ref_from_bytes(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        key.verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}
