//! The vector account: a fixed header, then the scheme's identity.

use core::mem::size_of;

use pinocchio::{account::RefMut, error::ProgramError, AccountView};

use crate::{
    scheme::{cast, cast_mut, Scheme},
    schemes,
};

/// First seed of every vector account's address:
/// `["vector", [scheme], seed, [bump]]`.
pub const VECTOR_SEED: &[u8] = b"vector";

/// The header every vector account starts with. It is plain bytes: `repr(C)`
/// with alignment 1, no padding and no invalid bit patterns.
///
/// ```text
/// nonce:  [u8; 32]  // offset  0 — what the next signature must be made over
/// seed:   [u8; 32]  // offset 32 — sha256 of the key it was created with
/// scheme:  u8       // offset 64 — the scheme of the identity that follows
/// bump:    u8       // offset 65 — PDA bump seed
/// system_bump: u8   // offset 66 — bump of the account's system PDA
/// _pad:    u8       // offset 67
/// ```
///
/// The system PDA, `[vector address, system_bump]`, belongs to the System
/// program: `Passthrough` can sign as it, for what only a system account can
/// do.
///
/// The pad keeps the identity at a multiple of 4 in the account: Falcon-512
/// and ML-DSA-44 read their prepared key in place.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorAccount {
    pub nonce: [u8; 32],
    pub seed: [u8; 32],
    pub scheme: u8,
    pub bump: u8,
    pub system_bump: u8,
    _pad: u8,
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
    pub fn scheme(data: &[u8]) -> Result<&'static Scheme, ProgramError> {
        schemes::scheme(Self::header(data)?.scheme).map_err(|_| ProgramError::InvalidAccountData)
    }

    /// The header at the start of account data.
    pub fn header(data: &[u8]) -> Result<&Self, ProgramError> {
        let header = data
            .get(..Self::HEADER_LEN)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        // SAFETY: the header is plain bytes.
        unsafe { cast(header) }.ok_or(ProgramError::AccountDataTooSmall)
    }

    /// Split account data into the header and the identity bytes after it.
    pub fn split(data: &mut [u8]) -> Result<(&mut Self, &mut [u8]), ProgramError> {
        let (header, identity) = data
            .split_at_mut_checked(Self::HEADER_LEN)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        // SAFETY: the header is plain bytes.
        let header = unsafe { cast_mut(header) }.ok_or(ProgramError::AccountDataTooSmall)?;
        Ok((header, identity))
    }
}
