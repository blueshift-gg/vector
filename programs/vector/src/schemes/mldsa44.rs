use core::mem::{offset_of, size_of};

use pinocchio::error::ProgramError;
use solana_ml_dsa::ml_dsa_44::{
    PreparedVerifyingKey, Signature, VerifyingKey, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};

use crate::{scheme::SigningScheme, state::VectorAccount};

// SHAKE128/256, as specified by FIPS 204.
type PreparedKey = PreparedVerifyingKey<false>;

/// ML-DSA-44 (FIPS 204) with an empty context.
///
/// The account is too big to create in one instruction, so it is created
/// short and `Expand` grows it. The prepared key is filled in row by row as
/// the account becomes long enough to hold each row.
#[repr(C)]
pub struct MlDsa44 {
    public_key: [u8; PUBLIC_KEY_LEN],
    _pad: [u8; 2],
    /// The key's matrix expanded, so that verifying does not redo it.
    prepared: [u8; PreparedKey::BYTE_LEN],
}

const PREPARED: usize = offset_of!(MlDsa44, prepared);

/// The prepared key is read in place, as 32-bit coefficients, so it must sit
/// at a multiple of 4 in the account. Account data is 8-byte aligned.
const _: () = assert!((VectorAccount::HEADER_LEN + PREPARED).is_multiple_of(4));

unsafe impl SigningScheme for MlDsa44 {
    fn initialize(key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        let public_key = VerifyingKey::<false>::ref_from_bytes(key)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let head = identity
            .get_mut(..PREPARED)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        head[..PUBLIC_KEY_LEN].copy_from_slice(public_key.as_bytes());
        head[PUBLIC_KEY_LEN..].fill(0);
        prepare_rows(identity, 0)
    }

    /// Fails once the account is complete.
    fn expand(identity: &mut [u8], from: usize) -> Result<(), ProgramError> {
        if from >= size_of::<Self>() {
            return Err(ProgramError::InvalidAccountData);
        }
        prepare_rows(identity, from)
    }

    fn signature_len(&self) -> usize {
        SIGNATURE_LEN
    }

    fn advance(&self, digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        let signature = Signature::ref_from_bytes(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        PreparedKey::ref_from_bytes(&self.prepared)
            .map_err(|_| ProgramError::InvalidAccountData)?
            .verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}

/// Prepare the rows that fit in `identity` now and did not fit when it was
/// `from` bytes long. The last row completes the key with its hash.
fn prepare_rows(identity: &mut [u8], from: usize) -> Result<(), ProgramError> {
    let len = identity.len();
    let (head, prepared) = identity
        .split_at_mut_checked(PREPARED)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let public_key = VerifyingKey::<false>::ref_from_bytes(&head[..PUBLIC_KEY_LEN])
        .map_err(|_| ProgramError::InvalidAccountData)?;

    for i in 0..PreparedKey::PUBLIC_KEY_HASH_OFFSET / PreparedKey::ROW_BYTE_LEN {
        let end = (i + 1) * PreparedKey::ROW_BYTE_LEN;
        if PREPARED + end > from && PREPARED + end <= len {
            let row =
                PreparedKey::borrow_row_mut(&mut prepared[end - PreparedKey::ROW_BYTE_LEN..end])
                    .map_err(|_| ProgramError::InvalidAccountData)?;
            public_key
                .prepare_row_into(i, row)
                .map_err(|_| ProgramError::InvalidAccountData)?;
        }
    }
    if len == size_of::<MlDsa44>() {
        prepared[PreparedKey::PUBLIC_KEY_HASH_OFFSET..]
            .copy_from_slice(&public_key.public_key_hash());
    }
    Ok(())
}
