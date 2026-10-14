use core::mem::offset_of;

use pinocchio::error::ProgramError;
use solana_falcon512::{
    Falcon512PreparedPubkey, Falcon512Pubkey, Falcon512Signature, FALCON_512_PREPARED_PUBKEY_LEN,
    FALCON_512_SIGNATURE_LEN,
};

use crate::{scheme::SigningScheme, state::VectorAccount};

/// Falcon-512. The key is given in its 897-byte wire form; a signature is
/// the compressed form, zero-padded to 666 bytes.
#[repr(C)]
pub struct Falcon512 {
    /// The key with its NTT done, so that verifying does not redo it.
    prepared: [u8; FALCON_512_PREPARED_PUBKEY_LEN],
}

/// The prepared key is read in place, as 16-bit coefficients, so it must sit
/// at an even offset in the account. Account data is 8-byte aligned.
const _: () =
    assert!((VectorAccount::HEADER_LEN + offset_of!(Falcon512, prepared)).is_multiple_of(2));

unsafe impl SigningScheme for Falcon512 {
    const SIGNATURE_LEN: usize = FALCON_512_SIGNATURE_LEN;

    fn initialize(key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        let prepared = Falcon512Pubkey::try_from_slice(key)
            .and_then(|key| key.try_prepare_pubkey())
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        identity.copy_from_slice(prepared.as_bytes());
        Ok(())
    }

    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &[u8],
        _next_key: &[u8],
    ) -> Result<(), ProgramError> {
        let prepared = Falcon512PreparedPubkey::try_from_slice(&self.prepared)
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let signature = Falcon512Signature::try_from_slice(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if signature.verify_with_prepared(digest, prepared) {
            Ok(())
        } else {
            Err(ProgramError::MissingRequiredSignature)
        }
    }
}
