//! Key rotation with a fixed account identity: `sha256(initial_payload) || key`.

use core::marker::PhantomData;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use solana_nostd_sha256::hash;

use crate::{IdentitySeed, SigningScheme, VectorAccount};

const ROTATE_DISCRIMINATOR: u8 = 5;

/// `S` with a key that can be replaced, and the `Rotate` instruction that
/// replaces it.
pub struct Rotating<S>(PhantomData<S>);

impl<S: SigningScheme> SigningScheme for Rotating<S> {
    const ID: u8 = S::ID;
    const SIGNATURE_LEN: usize = S::SIGNATURE_LEN;
    const IDENTITY_LEN: usize = 32 + S::IDENTITY_LEN;
    const INIT_PAYLOAD_LEN: usize = S::INIT_PAYLOAD_LEN;

    fn populate_identity(payload: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        identity[..32].copy_from_slice(&hash(payload));
        S::populate_identity(payload, &mut identity[32..])
    }

    fn pda_seed_from_identity(identity: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&identity[..32])
    }

    fn pda_seed_from_payload(payload: &[u8]) -> IdentitySeed {
        IdentitySeed::from_hash(payload)
    }

    /// `5: Rotate` carries a new init payload and is authorized through
    /// Passthrough, like Withdraw: the current key signs the entire
    /// transaction, including the replacement key. Only the stored key
    /// changes; seeds and nonce remain. Rotation is optional; callers manage
    /// key freshness and signing capacity.
    fn process_other(
        discriminator: u8,
        accounts: &mut [AccountView],
        payload: &[u8],
    ) -> ProgramResult {
        let [vector] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        if discriminator != ROTATE_DISCRIMINATOR || payload.len() != S::INIT_PAYLOAD_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        if !vector.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        let mut data = vector.try_borrow_mut()?;
        if data.len() != VectorAccount::account_len::<Self>() {
            return Err(ProgramError::InvalidAccountData);
        }
        S::populate_identity(payload, &mut data[VectorAccount::HEADER_LEN + 32..])
    }

    fn verify(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        S::verify(&identity[32..], digest, signature)
    }
}
