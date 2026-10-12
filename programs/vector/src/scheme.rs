//! The contract a signing scheme satisfies. Everything else in the program
//! is the same for every scheme and only reaches a scheme through this.

use pinocchio::error::ProgramError;
use solana_nostd_sha256::hash;

/// One signing scheme: its sizes, and its part in each instruction.
/// Implementations live in [`crate::schemes`], one file each. An instruction
/// does what is the same for every scheme and calls these for the rest.
pub trait SigningScheme {
    /// Identifies the scheme: the second header field of every account and
    /// a PDA seed. Never zero: an account anyone assigns to the program has
    /// zeroed data, and must not read as an account of some scheme.
    fn id(&self) -> u8;

    /// Length of the key `Initialize` takes.
    fn key_len(&self) -> usize;

    /// Length of the identity bytes the account stores after its header.
    /// Usually `key_len`, the key as given; Falcon-512 and ML-DSA-44 store a
    /// prepared form, Winternitz and XMSS a hash and the current key.
    fn identity_len(&self) -> usize;

    /// Length of a signature in `Advance` data.
    fn signature_len(&self) -> usize;

    /// The PDA seed, from the key `Initialize` takes. Default: the key itself
    /// when it is at most 32 bytes, else its SHA-256.
    fn seed_from_key(&self, key: &[u8]) -> IdentitySeed {
        IdentitySeed::default_from(key)
    }

    /// The same PDA seed, from the stored identity.
    fn seed_from_identity(&self, identity: &[u8]) -> IdentitySeed {
        IdentitySeed::default_from(identity)
    }

    /// `Initialize`: validate the key and write the identity bytes. The
    /// buffer is shorter than `identity_len` when the account could not be
    /// created at full size; [`expand`](Self::expand) then finishes the job.
    fn initialize(&self, key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError>;

    /// `Expand`: the account grew, and `identity` was `from` bytes long
    /// before. Fill in what fits now. Default: the scheme's account is
    /// created whole, so there is nothing to expand.
    fn expand(&self, _identity: &mut [u8], _from: usize) -> Result<(), ProgramError> {
        Err(ProgramError::InvalidInstructionData)
    }

    /// `Advance`: verify `signature` over `digest` against the identity.
    fn advance(
        &self,
        identity: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ProgramError>;

    /// `Passthrough`: take what the scheme needs off the front of the data
    /// and return the instructions after it. Default: nothing.
    fn passthrough<'a>(
        &self,
        _identity: &mut [u8],
        data: &'a [u8],
    ) -> Result<&'a [u8], ProgramError> {
        Ok(data)
    }
}

/// PDA-seed buffer — variable length up to 32 bytes (Solana's per-seed cap).
///
/// Holds the bytes and the real length so callers can pass
/// `&self.bytes[..self.len]` to `Seed::from`.
pub struct IdentitySeed {
    bytes: [u8; 32],
    len: usize,
}

impl IdentitySeed {
    /// Copy up to 32 bytes verbatim.
    pub fn copy_from(src: &[u8]) -> Self {
        let len = src.len().min(32);
        let mut bytes = [0u8; 32];
        bytes[..len].copy_from_slice(&src[..len]);
        Self { bytes, len }
    }

    /// `sha256(input)` — the seed for identities longer than 32 bytes.
    pub fn from_hash(input: &[u8]) -> Self {
        Self {
            bytes: hash(input),
            len: 32,
        }
    }

    /// Default rule: identity bytes themselves when `<= 32`, else `sha256`.
    pub fn default_from(input: &[u8]) -> Self {
        if input.len() <= 32 {
            Self::copy_from(input)
        } else {
            Self::from_hash(input)
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
