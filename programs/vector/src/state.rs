//! The vector account: a fixed header, then the scheme's identity bytes.

use core::mem::{offset_of, size_of};

use pinocchio::{cpi::Seed, error::ProgramError, AccountView};

use crate::{
    constants::VECTOR_SEED,
    scheme::{IdentitySeed, SigningScheme},
    schemes,
};

/// The header every vector account starts with.
///
/// ```text
/// nonce:  [u8; 32]  // offset  0 — what the next signature must be made over
/// scheme: u8        // offset 32 — `SigningScheme::id`
/// bump:   u8        // offset 33 — PDA bump seed
/// ```
#[repr(C)]
pub struct VectorAccount {
    pub nonce: [u8; 32],
    pub scheme: u8,
    pub bump: u8,
}

impl VectorAccount {
    /// Length of the header. The identity bytes follow it.
    pub const HEADER_LEN: usize = size_of::<Self>();

    /// The scheme of a vector account, from its header. The program takes
    /// the scheme from here and never from the caller, so the identity bytes
    /// are always read as the scheme that wrote them.
    pub fn scheme(account: &AccountView) -> Result<&'static dyn SigningScheme, ProgramError> {
        if !account.owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        let id = *account
            .try_borrow()?
            .get(offset_of!(Self, scheme))
            .ok_or(ProgramError::AccountDataTooSmall)?;
        schemes::scheme(id).map_err(|_| ProgramError::InvalidAccountData)
    }

    /// Split account data into the header and the identity bytes after it.
    pub fn split(data: &mut [u8]) -> Result<(&mut Self, &mut [u8]), ProgramError> {
        let (header, identity) = data
            .split_at_mut_checked(Self::HEADER_LEN)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        // SAFETY: `header` is `HEADER_LEN` bytes, and `Self` is `repr(C)` with
        // alignment 1 and no invalid bit patterns.
        Ok((
            unsafe { &mut *header.as_mut_ptr().cast::<Self>() },
            identity,
        ))
    }

    /// Length of a complete account of `scheme`.
    pub fn len(scheme: &dyn SigningScheme) -> usize {
        Self::HEADER_LEN + scheme.identity_len()
    }
}

/// The seeds a vector account signs with.
pub fn signer_seeds<'a>(
    scheme: &'a [u8; 1],
    identity_seed: &'a IdentitySeed,
    bump: &'a [u8; 1],
) -> [Seed<'a>; 4] {
    [
        Seed::from(VECTOR_SEED),
        Seed::from(&scheme[..]),
        Seed::from(identity_seed.as_slice()),
        Seed::from(&bump[..]),
    ]
}
