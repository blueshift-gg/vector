//! One file per signing scheme, each a [`SigningScheme`] impl.

use pinocchio::error::ProgramError;

use crate::scheme::SigningScheme;

pub mod ed25519;
pub mod eip191;
pub mod falcon512;
pub mod mldsa44;
pub mod rotating;
pub mod secp256k1;
pub mod winternitz;
pub mod xmss;

use ed25519::Ed25519;
use eip191::Secp256k1Eip191;
use falcon512::Falcon512;
use mldsa44::MlDsa44;
use rotating::Rotating;
use secp256k1::Secp256k1Ecdsa;
use winternitz::Winternitz;
use xmss::Xmss;

/// Every scheme the program serves, by [`SigningScheme::id`].
pub fn scheme(id: u8) -> Result<&'static dyn SigningScheme, ProgramError> {
    Ok(match id {
        Ed25519::ID => &Ed25519,
        Secp256k1Eip191::ID => &Secp256k1Eip191,
        Secp256k1Ecdsa::ID => &Secp256k1Ecdsa,
        Falcon512::ID => &Falcon512,
        MlDsa44::ID => &MlDsa44,
        Winternitz::ID => &Rotating(Winternitz),
        Xmss::ID => &Rotating(Xmss),
        _ => return Err(ProgramError::InvalidInstructionData),
    })
}
