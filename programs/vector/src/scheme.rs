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
    /// `Initialize`: validate `key` and write the identity. The buffer is
    /// shorter than `Self` when the account could not be created at full
    /// size; [`grow`](Self::grow) then finishes the job.
    fn initialize(key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError>
    where
        Self: Sized;

    /// A later `Initialize`: the account grew, and `identity` was `from`
    /// bytes long before. Fill in what fits now. Default: the scheme's
    /// account is created whole, so it never grows.
    fn grow(_identity: &mut [u8], _from: usize) -> Result<(), ProgramError>
    where
        Self: Sized,
    {
        Err(ProgramError::InvalidInstructionData)
    }

    /// Length of a signature in `Advance` data.
    fn signature_len(&self) -> usize;

    /// `Advance`: verify `signature` over `digest`. A scheme whose key signs
    /// a limited number of times records the use here.
    fn advance(&mut self, digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError>;

    /// The key cannot sign again. `Advance` then requires a `Passthrough`
    /// later in the transaction, which is where the next key comes from.
    /// Default: the key signs any number of times.
    fn spent(&self) -> bool {
        false
    }

    /// `Passthrough`: take what the scheme needs off the front of the data
    /// and return the instructions after it. Default: nothing.
    fn passthrough<'a>(&mut self, data: &'a [u8]) -> Result<&'a [u8], ProgramError> {
        Ok(data)
    }
}

/// A scheme before there is an identity of it to call: what `Initialize`
/// needs, and how to read an identity back.
pub trait Scheme {
    /// Length of the identity, the bytes after the account's header.
    fn identity_len(&self) -> usize;

    /// [`SigningScheme::initialize`].
    fn initialize(&self, key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError>;

    /// [`SigningScheme::grow`].
    fn grow(&self, identity: &mut [u8], from: usize) -> Result<(), ProgramError>;

    /// View a complete account's identity bytes as the scheme's identity.
    fn load<'a>(&self, identity: &'a mut [u8]) -> Result<&'a mut dyn SigningScheme, ProgramError>;
}

/// Every [`SigningScheme`] is a [`Scheme`] through its type.
impl<T: SigningScheme + 'static> Scheme for PhantomData<T> {
    fn identity_len(&self) -> usize {
        size_of::<T>()
    }

    fn initialize(&self, key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        T::initialize(key, identity)
    }

    fn grow(&self, identity: &mut [u8], from: usize) -> Result<(), ProgramError> {
        T::grow(identity, from)
    }

    fn load<'a>(&self, identity: &'a mut [u8]) -> Result<&'a mut dyn SigningScheme, ProgramError> {
        const { assert!(align_of::<T>() == 1) };
        if identity.len() != size_of::<T>() {
            return Err(ProgramError::AccountDataTooSmall);
        }
        // SAFETY: the length is `T`'s, and `SigningScheme` promises `T` has
        // alignment 1, no padding and no invalid bit patterns.
        Ok(unsafe { &mut *identity.as_mut_ptr().cast::<T>() })
    }
}
