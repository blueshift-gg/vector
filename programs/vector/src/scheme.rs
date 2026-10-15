//! The contract a signing scheme satisfies. Everything else in the program
//! is the same for every scheme and only reaches a scheme through this.

use core::mem::{align_of, size_of};

use pinocchio::{error::ProgramError, ProgramResult};
use solana_nostd_sha256::hashv;

use crate::state::VectorAccount;

/// One signing scheme, implemented by the identity it stores in an account:
/// a struct holding the signer's key in whatever form the scheme verifies
/// against. Implementations live in [`crate::schemes`], one file each.
///
/// Every length is the size of a type, so it is a constant everywhere.
///
/// # Safety
///
/// `Self`, `Key`, `Signature` and `NextKey` are read in place from bytes.
/// Each must have alignment 1, no padding and no invalid bit patterns: a
/// byte array, or a `repr(C)` or `repr(transparent)` struct of them.
pub unsafe trait SigningScheme: Sized {
    /// The scheme byte: in the account header, and a seed of its address.
    const ID: u8;

    /// The key `Initialize` takes, which names the account for good.
    type Key;

    /// A signature in `Advance` data.
    type Signature;

    /// The key `Advance` carries for the account to sign with next: `[u8; 0]`
    /// for a scheme whose key never changes.
    type NextKey;

    /// `Initialize`: validate `key` and write the identity. The buffer is
    /// shorter than `Self` when the account could not be created at full
    /// size; [`grow`](Self::grow) then finishes the job.
    fn initialize(key: &Self::Key, identity: &mut [u8]) -> Result<(), ProgramError>;

    /// A later `Initialize`: the account grew, and `identity` was `from`
    /// bytes long before. Fill in what fits now. Default: the scheme's
    /// account is created whole, so it never grows.
    fn grow(_identity: &mut [u8], _from: usize) -> Result<(), ProgramError> {
        Err(ProgramError::InvalidInstructionData)
    }

    /// `Advance`: verify `signature` over `digest`, then take `next_key`,
    /// which the digest covers.
    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &Self::Signature,
        next_key: &Self::NextKey,
    ) -> Result<(), ProgramError>;
}

/// One account's part of `Advance`, for its scheme: take its next key and
/// signature off the front of `data`, verify the signature over
/// `SHA256(message || nonce || address || next_key)`, and move `nonce` to that
/// digest.
pub type Advance = fn(
    identity: &mut [u8],
    nonce: &mut [u8; 32],
    message: &[u8; 32],
    address: &[u8; 32],
    data: &mut &[u8],
) -> ProgramResult;

/// A [`SigningScheme`] as the program picks it, by the byte in an account's
/// header: its lengths, and its operations on bytes.
#[derive(Clone, Copy, Debug)]
pub struct Scheme {
    /// [`SigningScheme::ID`].
    pub id: u8,
    /// Length of [`SigningScheme::Key`]: the identity a client names the
    /// account by.
    pub identity_len: usize,
    /// Bytes the account stores after its header: the size of the scheme.
    pub stored_identity_len: usize,
    /// Length of [`SigningScheme::Signature`].
    pub signature_len: usize,
    /// Length of [`SigningScheme::NextKey`].
    pub next_key_len: usize,
    /// [`SigningScheme::initialize`], on the key's bytes.
    pub initialize: fn(&[u8], &mut [u8]) -> ProgramResult,
    /// [`SigningScheme::grow`].
    pub grow: fn(&mut [u8], usize) -> ProgramResult,
    /// [`SigningScheme::advance`], with the digest it verifies.
    pub advance: Advance,
}

impl Scheme {
    pub const fn of<T: SigningScheme>() -> Self {
        Self {
            id: T::ID,
            identity_len: size_of::<T::Key>(),
            stored_identity_len: size_of::<T>(),
            signature_len: size_of::<T::Signature>(),
            next_key_len: size_of::<T::NextKey>(),
            initialize: initialize::<T>,
            grow: T::grow,
            advance: advance::<T>,
        }
    }

    /// The account's whole length: the header, then the stored identity.
    pub const fn account_len(&self) -> usize {
        VectorAccount::HEADER_LEN + self.stored_identity_len
    }
}

fn initialize<T: SigningScheme>(key: &[u8], identity: &mut [u8]) -> ProgramResult {
    // SAFETY: `SigningScheme` promises `Key` is plain bytes.
    let key = unsafe { cast(key) }.ok_or(ProgramError::InvalidInstructionData)?;
    T::initialize(key, identity)
}

fn advance<T: SigningScheme>(
    identity: &mut [u8],
    nonce: &mut [u8; 32],
    message: &[u8; 32],
    address: &[u8; 32],
    data: &mut &[u8],
) -> ProgramResult {
    // SAFETY, each cast: `SigningScheme` promises these types are plain
    // bytes.
    let identity = unsafe { cast_mut::<T>(identity) }.ok_or(ProgramError::AccountDataTooSmall)?;
    let next_key = take(data, size_of::<T::NextKey>())?;
    let signature = take(data, size_of::<T::Signature>())?;

    let digest = hashv(&[message, nonce, address, next_key]);
    identity.advance(
        &digest,
        unsafe { cast(signature) }.ok_or(ProgramError::InvalidInstructionData)?,
        unsafe { cast(next_key) }.ok_or(ProgramError::InvalidInstructionData)?,
    )?;
    *nonce = digest;
    Ok(())
}

/// Take the next `len` bytes off the front of `data`.
fn take<'a>(data: &mut &'a [u8], len: usize) -> Result<&'a [u8], ProgramError> {
    let (bytes, rest) = data
        .split_at_checked(len)
        .ok_or(ProgramError::InvalidInstructionData)?;
    *data = rest;
    Ok(bytes)
}

/// `bytes` as a `U`, if they are exactly as long.
///
/// # Safety
///
/// Every bit pattern of `U`'s size must be a `U`.
unsafe fn cast<U>(bytes: &[u8]) -> Option<&U> {
    const { assert!(align_of::<U>() == 1) };
    // SAFETY: the length is `U`'s, its alignment is 1, and the caller
    // promises the bits are a `U`.
    (bytes.len() == size_of::<U>()).then(|| unsafe { &*bytes.as_ptr().cast::<U>() })
}

/// [`cast`], mutably.
///
/// # Safety
///
/// As [`cast`].
unsafe fn cast_mut<U>(bytes: &mut [u8]) -> Option<&mut U> {
    const { assert!(align_of::<U>() == 1) };
    // SAFETY: as in `cast`.
    (bytes.len() == size_of::<U>()).then(|| unsafe { &mut *bytes.as_mut_ptr().cast::<U>() })
}
