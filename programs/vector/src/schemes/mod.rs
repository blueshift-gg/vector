//! One file per signing scheme, each a [`SigningScheme`] impl on the
//! identity it stores.

use pinocchio::error::ProgramError;

use crate::scheme::{Scheme, SigningScheme};

pub mod ed25519;
pub mod eip191;
pub mod falcon512;
pub mod mldsa44;
pub mod secp256k1;
pub mod winternitz;
pub mod xmss;

use self::{
    ed25519::Ed25519, eip191::Eip191, falcon512::Falcon512, mldsa44::MlDsa44, secp256k1::Secp256k1,
    winternitz::Winternitz, xmss::Xmss,
};

/// Every scheme the program serves, by the byte in the account header. A
/// byte two schemes claimed would be an unreachable pattern. Zero is not
/// one: an account anyone assigns to the program has zeroed data, and must
/// not read as an account of some scheme.
pub fn scheme(id: u8) -> Result<&'static Scheme, ProgramError> {
    Ok(match id {
        Ed25519::ID => &const { Scheme::of::<Ed25519>() },
        Eip191::ID => &const { Scheme::of::<Eip191>() },
        Secp256k1::ID => &const { Scheme::of::<Secp256k1>() },
        Falcon512::ID => &const { Scheme::of::<Falcon512>() },
        MlDsa44::ID => &const { Scheme::of::<MlDsa44>() },
        Winternitz::ID => &const { Scheme::of::<Winternitz>() },
        Xmss::ID => &const { Scheme::of::<Xmss>() },
        _ => return Err(ProgramError::InvalidInstructionData),
    })
}
