use crate::scheme::SigningScheme;
use pinocchio::error::ProgramError;
use solana_winternitz::{winternitz, VerifyingKey, PUBLIC_KEY_LEN};

/// DKKW25 Winternitz verification. The lookup wraps it in `Rotating`.
pub struct Winternitz;

impl Winternitz {
    pub const ID: u8 = 6;
}

impl SigningScheme for Winternitz {
    fn id(&self) -> u8 {
        Self::ID
    }

    fn signature_len(&self) -> usize {
        winternitz::SIGNATURE_LEN
    }
    fn identity_len(&self) -> usize {
        PUBLIC_KEY_LEN
    }
    fn init_payload_len(&self) -> usize {
        PUBLIC_KEY_LEN
    }

    fn populate_identity(
        &self,
        payload: &[u8],
        identity_out: &mut [u8],
    ) -> Result<(), ProgramError> {
        let public_key: &[u8; PUBLIC_KEY_LEN] = payload
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        identity_out.copy_from_slice(public_key);
        Ok(())
    }

    fn verify(
        &self,
        identity: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ProgramError> {
        let public_key =
            VerifyingKey::ref_from_bytes(identity).map_err(|_| ProgramError::InvalidAccountData)?;
        let signature = winternitz::Signature::ref_from_bytes(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        public_key
            .verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}
