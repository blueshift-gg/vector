//! The contract a signing scheme satisfies. Everything else in the program
//! is the same for every scheme and only reaches a scheme through this.

use pinocchio::error::ProgramError;
use solana_nostd_sha256::hash;

/// One signing scheme: what it stores as the signer's identity and how it
/// verifies. Implementations live in [`crate::schemes`], one file each.
pub trait SigningScheme {
    /// Identifies the scheme: the second header field of every account and
    /// a PDA seed. Never zero: an account anyone assigns to the program has
    /// zeroed data, and must not read as an account of some scheme.
    fn id(&self) -> u8;

    /// Length of a signature in `Advance` data.
    fn signature_len(&self) -> usize;

    /// Length of the identity bytes the account stores after its header.
    fn identity_len(&self) -> usize;

    /// Length of the `Initialize` payload. Usually `identity_len` (the key
    /// is stored as given); Falcon-512 and ML-DSA-44 store a prepared form.
    fn init_payload_len(&self) -> usize;

    /// Validate the `Initialize` payload and write the identity bytes. The
    /// buffer is shorter than `identity_len` when the account could not be
    /// created at full size; [`expand`](Self::expand) then finishes the job.
    fn populate_identity(&self, payload: &[u8], identity: &mut [u8]) -> Result<(), ProgramError>;

    /// The PDA seed, from the stored identity. Default: the identity itself
    /// when it is at most 32 bytes, else its SHA-256.
    fn pda_seed_from_identity(&self, identity: &[u8]) -> IdentitySeed {
        IdentitySeed::default_from(identity)
    }

    /// The PDA seed, from the `Initialize` payload. Must agree with
    /// [`pda_seed_from_identity`](Self::pda_seed_from_identity).
    fn pda_seed_from_payload(&self, payload: &[u8]) -> IdentitySeed {
        IdentitySeed::default_from(payload)
    }

    /// Verify `signature` over `digest` against the stored `identity`.
    fn verify(
        &self,
        identity: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ProgramError>;

    /// `Expand`: the account grew, and `identity` was `from` bytes long
    /// before. Fill in what fits now. Only schemes whose account is too big
    /// to create in one instruction have this.
    fn expand(&self, _identity: &mut [u8], _from: usize) -> Result<(), ProgramError> {
        Err(ProgramError::InvalidInstructionData)
    }

    /// `Rotate`: replace the key in `identity` with the one in `payload`.
    /// Only schemes with a replaceable key have this.
    fn rotate(&self, _payload: &[u8], _identity: &mut [u8]) -> Result<(), ProgramError> {
        Err(ProgramError::InvalidInstructionData)
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
