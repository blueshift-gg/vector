use pinocchio::error::ProgramError;
use solana_winternitz::{winternitz, VerifyingKey, PUBLIC_KEY_LEN};
use vector_common::SigningScheme;

/// DKKW25 Winternitz verification for the shared rotation adapter.
pub struct Winternitz;

impl SigningScheme for Winternitz {
    const SIGNATURE_LEN: usize = winternitz::SIGNATURE_LEN;
    const IDENTITY_LEN: usize = PUBLIC_KEY_LEN;
    const INIT_PAYLOAD_LEN: usize = PUBLIC_KEY_LEN;

    fn populate_identity(payload: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        let public_key: &[u8; PUBLIC_KEY_LEN] = payload
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        identity_out.copy_from_slice(public_key);
        Ok(())
    }

    fn verify(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        let public_key =
            VerifyingKey::ref_from_bytes(identity).map_err(|_| ProgramError::InvalidAccountData)?;
        let signature = winternitz::Signature::ref_from_bytes(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        public_key
            .verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}
