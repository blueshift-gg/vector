//! The vector account: a fixed header, then the scheme's identity.

use core::mem::{offset_of, size_of};

use pinocchio::{account::RefMut, error::ProgramError, AccountView};

use crate::{
    scheme::{Scheme, SigningScheme},
    schemes,
};

/// First seed of every vector account's address:
/// `["vector", [scheme], seed, [bump]]`.
pub const VECTOR_SEED: &[u8] = b"vector";

/// The header every vector account starts with.
///
/// ```text
/// nonce:  [u8; 32]  // offset  0 — what the next signature must be made over
/// seed:   [u8; 32]  // offset 32 — sha256 of the key it was created with
/// scheme: u8        // offset 64 — the scheme of the identity that follows
/// bump:   u8        // offset 65 — PDA bump seed
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorAccount {
    pub nonce: [u8; 32],
    pub seed: [u8; 32],
    pub scheme: u8,
    pub bump: u8,
}

impl VectorAccount {
    /// Length of the header. The identity follows it.
    pub const HEADER_LEN: usize = size_of::<Self>();

    /// Borrow the data of an account the program owns.
    pub fn borrow(account: &mut AccountView) -> Result<RefMut<'_, [u8]>, ProgramError> {
        if !account.owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        account.try_borrow_mut()
    }

    /// The scheme of an account, from its header. The program takes the
    /// scheme from here and never from the caller, so the identity is always
    /// read as the scheme that wrote it.
    pub fn scheme(data: &[u8]) -> Result<&'static dyn Scheme, ProgramError> {
        let id = *data
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
        // alignment 1, no padding and no invalid bit patterns.
        Ok((
            unsafe { &mut *header.as_mut_ptr().cast::<Self>() },
            identity,
        ))
    }

    /// View a complete account's data as its header and its identity.
    pub fn load(data: &mut [u8]) -> Result<(&mut Self, &mut dyn SigningScheme), ProgramError> {
        let scheme = Self::scheme(data)?;
        let (header, identity) = Self::split(data)?;
        Ok((header, scheme.load(identity)?))
    }
}
