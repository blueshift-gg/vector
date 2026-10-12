use pinocchio::error::ProgramError;
use solana_nostd_sha256::hash;

use crate::scheme::{IdentitySeed, SigningScheme};

/// `S` with a key that is replaced as the account is used. The identity is
/// `sha256(first_key) || current_key`: the hash names the account for good,
/// and a `Passthrough` sets the key that signs next.
pub struct Rotating<S> {
    pub scheme: S,
    /// A key that signs once must be replaced by every `Passthrough`. One
    /// that signs many times may be kept.
    pub every_time: bool,
}

impl<S: SigningScheme> SigningScheme for Rotating<S> {
    fn id(&self) -> u8 {
        self.scheme.id()
    }

    fn key_len(&self) -> usize {
        self.scheme.key_len()
    }

    fn identity_len(&self) -> usize {
        32 + self.scheme.identity_len()
    }

    fn signature_len(&self) -> usize {
        self.scheme.signature_len()
    }

    fn seed_from_key(&self, key: &[u8]) -> IdentitySeed {
        IdentitySeed::from_hash(key)
    }

    fn seed_from_identity(&self, identity: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&identity[..32])
    }

    fn initialize(&self, key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        identity[..32].copy_from_slice(&hash(key));
        self.scheme.initialize(key, &mut identity[32..])
    }

    fn advance(
        &self,
        identity: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ProgramError> {
        self.scheme.advance(&identity[32..], digest, signature)
    }

    /// The data starts with the key that signs next. The owner signed the
    /// whole transaction, this key included. When the key may be kept, a
    /// byte comes first: `0` to keep it, `1` followed by the next key. The
    /// program does not track which keys were used.
    fn passthrough<'a>(
        &self,
        identity: &mut [u8],
        mut data: &'a [u8],
    ) -> Result<&'a [u8], ProgramError> {
        if !self.every_time {
            match data.split_first() {
                Some((0, instructions)) => return Ok(instructions),
                Some((1, next_key)) => data = next_key,
                _ => return Err(ProgramError::InvalidInstructionData),
            }
        }
        let (key, instructions) = data
            .split_at_checked(self.key_len())
            .ok_or(ProgramError::InvalidInstructionData)?;
        self.scheme.initialize(key, &mut identity[32..])?;
        Ok(instructions)
    }
}
