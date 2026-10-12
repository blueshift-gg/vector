use pinocchio::error::ProgramError;
use solana_nostd_sha256::hash;

use crate::scheme::{IdentitySeed, SigningScheme};

/// `S` with a key that can be replaced. The identity is
/// `sha256(first_key) || current_key`: the hash names the account for good,
/// and `Rotate` replaces the key after it.
pub struct Rotating<S>(pub S);

impl<S: SigningScheme> SigningScheme for Rotating<S> {
    fn id(&self) -> u8 {
        self.0.id()
    }

    fn signature_len(&self) -> usize {
        self.0.signature_len()
    }

    fn identity_len(&self) -> usize {
        32 + self.0.identity_len()
    }

    fn init_payload_len(&self) -> usize {
        self.0.init_payload_len()
    }

    fn populate_identity(&self, payload: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        identity[..32].copy_from_slice(&hash(payload));
        self.0.populate_identity(payload, &mut identity[32..])
    }

    fn pda_seed_from_identity(&self, identity: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&identity[..32])
    }

    fn pda_seed_from_payload(&self, payload: &[u8]) -> IdentitySeed {
        IdentitySeed::from_hash(payload)
    }

    fn verify(
        &self,
        identity: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ProgramError> {
        self.0.verify(&identity[32..], digest, signature)
    }

    /// Only the stored key changes; the seed and the nonce stay. Callers
    /// manage key freshness and signing capacity.
    fn rotate(&self, payload: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        if payload.len() != self.init_payload_len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        if identity.len() != self.identity_len() {
            return Err(ProgramError::InvalidAccountData);
        }
        self.0.populate_identity(payload, &mut identity[32..])
    }
}
