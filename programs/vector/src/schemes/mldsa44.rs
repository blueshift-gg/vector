use core::mem::{offset_of, size_of};

use pinocchio::error::ProgramError;
use solana_ml_dsa::ml_dsa_44::{PreparedVerifyingKey, Signature, VerifyingKey};

use crate::{
    scheme::{write, SigningScheme},
    state::VectorAccount,
};

// SHAKE128/256, as specified by FIPS 204.
type PreparedKey = PreparedVerifyingKey<false>;

/// ML-DSA-44 (FIPS 204) with an empty context.
///
/// The account is too big to create in one instruction, so it is created
/// short and later `Initialize` calls grow it. The prepared key is filled in row by row as
/// the account becomes long enough to hold each row.
#[repr(C)]
pub struct MlDsa44 {
    public_key: VerifyingKey<false>,
    /// The key's matrix expanded, so that verifying does not redo it.
    prepared: [u8; PreparedKey::BYTE_LEN],
}

const PREPARED: usize = offset_of!(MlDsa44, prepared);

/// The prepared key is read in place, as 32-bit coefficients, so it must sit
/// at a multiple of 4 in the account. Account data is 8-byte aligned.
const _: () = assert!((VectorAccount::HEADER_LEN + PREPARED).is_multiple_of(4));

unsafe impl SigningScheme for MlDsa44 {
    const ID: u8 = 5;
    type Key = VerifyingKey<false>;
    type Signature = Signature;
    type NextKey = [u8; 0];

    fn initialize(key: &VerifyingKey<false>, identity: &mut [u8]) -> Result<(), ProgramError> {
        write(identity, key.as_bytes())?;
        prepare_rows(identity, 0)
    }

    fn grow(identity: &mut [u8], from: usize) -> Result<(), ProgramError> {
        prepare_rows(identity, from)
    }

    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &Signature,
        _next_key: &[u8; 0],
    ) -> Result<(), ProgramError> {
        PreparedKey::ref_from_bytes(&self.prepared)
            .map_err(|_| ProgramError::InvalidAccountData)?
            .verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}

/// Prepare the rows that fit in `identity` now and did not fit when it was
/// `from` bytes long. The last row completes the key with its hash.
fn prepare_rows(identity: &mut [u8], from: usize) -> Result<(), ProgramError> {
    let complete = identity.len() == size_of::<MlDsa44>();
    let (public_key, prepared) = identity
        .split_at_mut_checked(PREPARED)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let public_key = VerifyingKey::<false>::ref_from_bytes(public_key)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Whole rows only: one that does not fit yet waits for the next call.
    let rows = PreparedKey::PUBLIC_KEY_HASH_OFFSET / PreparedKey::ROW_BYTE_LEN;
    let done = from.saturating_sub(PREPARED) / PreparedKey::ROW_BYTE_LEN;
    for (i, row) in (0..rows)
        .zip(prepared.as_chunks_mut::<{ PreparedKey::ROW_BYTE_LEN }>().0)
        .skip(done)
    {
        let row = PreparedKey::borrow_row_mut(row).map_err(|_| ProgramError::InvalidAccountData)?;
        public_key
            .prepare_row_into(i, row)
            .map_err(|_| ProgramError::InvalidAccountData)?;
    }
    if complete {
        let hash = prepared
            .get_mut(PreparedKey::PUBLIC_KEY_HASH_OFFSET..)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        write(hash, &public_key.public_key_hash())?;
    }
    Ok(())
}
