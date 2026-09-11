//! Key rotation with a fixed account identity: `sha256(initial_payload) || key`.

use alloc::vec;
use core::marker::PhantomData;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use solana_nostd_sha256::hash;

use crate::{IdentitySeed, SigningScheme, VectorAccount};

struct Rotating<S>(PhantomData<S>);

impl<S: SigningScheme> SigningScheme for Rotating<S> {
    const SIGNATURE_LEN: usize = S::SIGNATURE_LEN;
    const IDENTITY_LEN: usize = 32 + S::IDENTITY_LEN;
    const INIT_PAYLOAD_LEN: usize = S::INIT_PAYLOAD_LEN;

    fn populate_identity(payload: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        identity[..32].copy_from_slice(&hash(payload));
        S::populate_identity(payload, &mut identity[32..])
    }

    fn digest_identity(identity: &[u8]) -> &[u8] {
        &identity[..32]
    }

    fn pda_seed_from_identity(identity: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&identity[..32])
    }

    fn pda_seed_from_payload(payload: &[u8]) -> IdentitySeed {
        IdentitySeed::from_hash(payload)
    }

    fn verify(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        S::verify(&identity[32..], digest, signature)
    }
}

/// Dispatch the shared instructions with a stable identity, plus `5: Rotate`.
/// Rotate carries a new init payload and is authorized through Passthrough,
/// like Withdraw: the current key signs the entire transaction, including
/// the replacement key. Only the stored key changes; seeds and nonce remain.
pub fn dispatch<S: SigningScheme>(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let Some((&5, payload)) = instruction_data.split_first() else {
        return crate::dispatch::<Rotating<S>>(program_id, accounts, instruction_data);
    };
    let [vector] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !vector.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !vector.owned_by(program_id) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if payload.len() != S::INIT_PAYLOAD_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut data = vector.try_borrow_mut()?;
    if data.len() != VectorAccount::account_len::<Rotating<S>>() {
        return Err(ProgramError::InvalidAccountData);
    }
    let current = &mut data[VectorAccount::HEADER_LEN + 32..];
    let mut next = vec![0; S::IDENTITY_LEN];
    S::populate_identity(payload, &mut next)?;
    if current == next {
        return Err(ProgramError::InvalidInstructionData);
    }
    current.copy_from_slice(&next);
    Ok(())
}
