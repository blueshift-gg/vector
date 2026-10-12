//! One file per signing scheme, each a [`SigningScheme`](crate::scheme::SigningScheme)
//! impl on the identity it stores.

use core::marker::PhantomData;

use pinocchio::error::ProgramError;

use crate::scheme::Scheme;

pub mod ed25519;
pub mod eip191;
pub mod falcon512;
pub mod mldsa44;
pub mod secp256k1;
pub mod winternitz;
pub mod xmss;

/// Every scheme the program serves, by the byte in the account header.
/// Zero is not one: an account anyone assigns to the program has zeroed
/// data, and must not read as an account of some scheme.
pub fn scheme(id: u8) -> Result<&'static dyn Scheme, ProgramError> {
    Ok(match id {
        1 => &PhantomData::<ed25519::Ed25519>,
        2 => &PhantomData::<eip191::Eip191>,
        3 => &PhantomData::<secp256k1::Secp256k1>,
        4 => &PhantomData::<falcon512::Falcon512>,
        5 => &PhantomData::<mldsa44::MlDsa44>,
        6 => &PhantomData::<winternitz::Winternitz>,
        7 => &PhantomData::<xmss::Xmss>,
        _ => return Err(ProgramError::InvalidInstructionData),
    })
}
