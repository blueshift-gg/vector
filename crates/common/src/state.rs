use pinocchio::{cpi::Seed, error::ProgramError};

use crate::scheme::{IdentitySeed, SigningScheme};

/// The fixed-size header every vector account starts with.
///
/// ```text
/// nonce:  [u8; 32]  // offset  0 — current state nonce
/// scheme: u8        // offset 32 — `SigningScheme::ID`
/// bump:   u8        // offset 33 — PDA bump seed
/// ```
///
/// The scheme's identity bytes follow at offset
/// [`HEADER_LEN`](Self::HEADER_LEN); length is `S::IDENTITY_LEN`.
pub struct VectorAccount;

impl VectorAccount {
    /// Length of the fixed-size header preceding the identity bytes.
    pub const HEADER_LEN: usize = 34;

    /// Total account length for scheme `S`: `HEADER_LEN + S::IDENTITY_LEN`.
    #[inline]
    pub fn account_len<S: SigningScheme>() -> usize {
        Self::HEADER_LEN + S::IDENTITY_LEN
    }

    /// The account is one scheme `S` created. Every handler that reads the
    /// identity through `S` calls this first: the bytes after the header
    /// mean something else under any other scheme.
    pub fn check_scheme<S: SigningScheme>(data: &[u8]) -> Result<(), ProgramError> {
        match data.get(32) {
            Some(&scheme) if scheme == S::ID => Ok(()),
            Some(_) => Err(ProgramError::InvalidAccountData),
            None => Err(ProgramError::AccountDataTooSmall),
        }
    }
}

/// Build the four PDA signer seeds for a vector account:
/// `["vector", &[scheme], identity-or-hash, &[bump]]`.
pub fn signer_seeds<'a>(
    scheme: &'a [u8; 1],
    identity_seed: &'a IdentitySeed,
    bump: &'a [u8; 1],
) -> [Seed<'a>; 4] {
    [
        Seed::from(b"vector"),
        Seed::from(&scheme[..]),
        Seed::from(identity_seed.as_slice()),
        Seed::from(&bump[..]),
    ]
}
