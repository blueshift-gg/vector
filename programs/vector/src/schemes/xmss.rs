use crate::scheme::SigningScheme;
use pinocchio::error::ProgramError;
use solana_winternitz::{xmss, VerifyingKey, PUBLIC_KEY_LEN};

/// DKKW25 XMSS verification. The lookup wraps it in `Rotating`.
pub struct Xmss;

impl Xmss {
    pub const ID: u8 = 7;
}

impl SigningScheme for Xmss {
    fn id(&self) -> u8 {
        Self::ID
    }

    fn signature_len(&self) -> usize {
        xmss::SIGNATURE_LEN
    }
    fn identity_len(&self) -> usize {
        PUBLIC_KEY_LEN
    }
    fn key_len(&self) -> usize {
        PUBLIC_KEY_LEN
    }

    fn initialize(&self, key: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        let public_key: &[u8; PUBLIC_KEY_LEN] = key
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        identity_out.copy_from_slice(public_key);
        Ok(())
    }

    fn advance(
        &self,
        identity: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ProgramError> {
        let public_key =
            VerifyingKey::ref_from_bytes(identity).map_err(|_| ProgramError::InvalidAccountData)?;
        let signature = xmss::Signature::ref_from_bytes(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        public_key
            .verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}
