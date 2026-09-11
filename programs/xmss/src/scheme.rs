use pinocchio::error::ProgramError;
use solana_winternitz::{xmss, PublicKey, PUBLIC_KEY_LENGTH};
use vector_common::SigningScheme;

/// The 41-byte public key is both the stored identity and digest input.
pub struct Xmss;

impl SigningScheme for Xmss {
    const SIGNATURE_LEN: usize = xmss::SIGNATURE_LENGTH;
    const IDENTITY_LEN: usize = PUBLIC_KEY_LENGTH;
    const INIT_PAYLOAD_LEN: usize = PUBLIC_KEY_LENGTH;

    fn populate_identity(payload: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        let public_key: &[u8; PUBLIC_KEY_LENGTH] = payload
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        identity_out.copy_from_slice(public_key);
        Ok(())
    }

    fn verify(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        let public_key = PublicKey(
            identity
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        );
        let signature = xmss::Signature(
            signature
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );
        signature
            .verify(&public_key, digest)
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}
