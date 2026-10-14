//! The contract a signing scheme satisfies. Everything else in the program
//! is the same for every scheme and only reaches a scheme through this.

use core::{
    marker::PhantomData,
    mem::{align_of, size_of},
};

use pinocchio::error::ProgramError;

/// One signing scheme, implemented by the identity it stores in an account:
/// a struct holding the signer's key in whatever form the scheme verifies
/// against. Implementations live in [`crate::schemes`], one file each.
///
/// # Safety
///
/// The account's identity bytes are read as `Self` in place. `Self` must be
/// `repr(C)` and made only of byte arrays, so it has alignment 1, no padding
/// and no invalid bit patterns.
pub unsafe trait SigningScheme {
    /// Length of a signature in `Advance` data.
    const SIGNATURE_LEN: usize;

    /// Length of the key `Advance` carries for the account to sign with
    /// next. Default: none, the key never changes.
    const NEXT_KEY_LEN: usize = 0;

    /// `Initialize`: validate `key` and write the identity. The buffer is
    /// shorter than `Self` when the account could not be created at full
    /// size; [`grow`](Self::grow) then finishes the job.
    fn initialize(key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError>;

    /// A later `Initialize`: the account grew, and `identity` was `from`
    /// bytes long before. Fill in what fits now. Default: the scheme's
    /// account is created whole, so it never grows.
    fn grow(_identity: &mut [u8], _from: usize) -> Result<(), ProgramError> {
        Err(ProgramError::InvalidInstructionData)
    }

    /// `Advance`: verify `signature` over `digest`, then take `next_key`,
    /// [`NEXT_KEY_LEN`](Self::NEXT_KEY_LEN) bytes the signature covers.
    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &[u8],
        next_key: &[u8],
    ) -> Result<(), ProgramError>;
}

/// A scheme picked by the byte in an account's header: what the program
/// needs of a [`SigningScheme`] without knowing which one it is.
pub trait Scheme {
    /// Length of the identity, the bytes after the account's header.
    fn identity_len(&self) -> usize;

    /// [`SigningScheme::SIGNATURE_LEN`].
    fn signature_len(&self) -> usize;

    /// [`SigningScheme::NEXT_KEY_LEN`].
    fn next_key_len(&self) -> usize;

    /// [`SigningScheme::initialize`].
    fn initialize(&self, key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError>;

    /// [`SigningScheme::grow`].
    fn grow(&self, identity: &mut [u8], from: usize) -> Result<(), ProgramError>;

    /// [`SigningScheme::advance`], on a complete account's identity bytes.
    fn advance(
        &self,
        identity: &mut [u8],
        digest: &[u8; 32],
        signature: &[u8],
        next_key: &[u8],
    ) -> Result<(), ProgramError>;
}

/// Every [`SigningScheme`] is a [`Scheme`] through its type.
impl<T: SigningScheme> Scheme for PhantomData<T> {
    fn identity_len(&self) -> usize {
        size_of::<T>()
    }

    fn signature_len(&self) -> usize {
        T::SIGNATURE_LEN
    }

    fn next_key_len(&self) -> usize {
        T::NEXT_KEY_LEN
    }

    fn initialize(&self, key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        T::initialize(key, identity)
    }

    fn grow(&self, identity: &mut [u8], from: usize) -> Result<(), ProgramError> {
        T::grow(identity, from)
    }

    fn advance(
        &self,
        identity: &mut [u8],
        digest: &[u8; 32],
        signature: &[u8],
        next_key: &[u8],
    ) -> Result<(), ProgramError> {
        const { assert!(align_of::<T>() == 1) };
        if identity.len() != size_of::<T>() {
            return Err(ProgramError::AccountDataTooSmall);
        }
        // SAFETY: the length is `T`'s, and `SigningScheme` promises `T` has
        // alignment 1, no padding and no invalid bit patterns.
        let identity = unsafe { &mut *identity.as_mut_ptr().cast::<T>() };
        identity.advance(digest, signature, next_key)
    }
}
