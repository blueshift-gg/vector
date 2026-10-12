use pinocchio::error::ProgramError;
use solana_nostd_sha256::hash;

use crate::scheme::{IdentitySeed, SigningScheme};

/// `S` with a key that is replaced as the account is used. The identity is
/// `sha256(first_key) || current_key`: the hash names the account for good,
/// and every `Passthrough` sets the key that signs next.
pub struct Rotating<S>(pub S);

impl<S: SigningScheme> SigningScheme for Rotating<S> {
    fn id(&self) -> u8 {
        self.0.id()
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn identity_len(&self) -> usize {
        32 + self.0.identity_len()
    }

    fn signature_len(&self) -> usize {
        self.0.signature_len()
    }

    fn seed_from_key(&self, key: &[u8]) -> IdentitySeed {
        IdentitySeed::from_hash(key)
    }

    fn seed_from_identity(&self, identity: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&identity[..32])
    }

    fn initialize(&self, key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        identity[..32].copy_from_slice(&hash(key));
        self.0.initialize(key, &mut identity[32..])
    }

    fn advance(
        &self,
        identity: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ProgramError> {
        self.0.advance(&identity[32..], digest, signature)
    }

    /// The data starts with the key that signs next. The owner signed the
    /// whole transaction, this key included. To keep the current key, pass
    /// it again: the program does not track which keys were used.
    fn passthrough<'a>(
        &self,
        identity: &mut [u8],
        data: &'a [u8],
    ) -> Result<&'a [u8], ProgramError> {
        let (key, instructions) = data
            .split_at_checked(self.key_len())
            .ok_or(ProgramError::InvalidInstructionData)?;
        self.0.initialize(key, &mut identity[32..])?;
        Ok(instructions)
    }
}
