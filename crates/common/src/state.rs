use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address};

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

    /// The scheme of a vector account, from its header. The program picks
    /// the [`SigningScheme`] from this, never from what a caller says, so the
    /// bytes after the header are always read as the scheme that wrote them.
    pub fn scheme(account: &AccountView, program_id: &Address) -> Result<u8, ProgramError> {
        if !account.owned_by(program_id) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        account
            .try_borrow()?
            .get(32)
            .copied()
            .ok_or(ProgramError::AccountDataTooSmall)
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
