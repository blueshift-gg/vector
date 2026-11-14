//! One module per signing scheme: the identity it stores and how it
//! verifies (a [`SigningScheme`](crate::scheme::SigningScheme) impl, as the
//! program runs it), its `Scheme` constant, and with the `client` feature an
//! `initialize` builder and a signer where this crate has one.
//!
//! The program is built without LTO (it is also a library, and with LTO it
//! inlines past its 4 KiB stack frame), so nothing inlines across this crate
//! and the program unless marked `#[inline]`. The schemes' small methods and
//! the header readers are, as they were when they lived in the program.
//! Falcon-512's and ML-DSA-44's verification are not: inlined here, they
//! would instantiate a second copy of SHAKE's Keccak-p (78 KB) in this crate.

use pinocchio::error::ProgramError;

use crate::{
    scheme::{Scheme, SigningScheme},
    state::NonceAccount,
};

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

// `Advance` tells a nonce account from a vector account by its length.
const _: () = {
    let schemes = [
        Scheme::of::<Ed25519>(),
        Scheme::of::<Eip191>(),
        Scheme::of::<Secp256k1>(),
        Scheme::of::<Falcon512>(),
        Scheme::of::<MlDsa44>(),
        Scheme::of::<Winternitz>(),
        Scheme::of::<Xmss>(),
    ];
    let mut i = 0;
    while i < schemes.len() {
        assert!(schemes[i].account_len != NonceAccount::LEN);
        i += 1;
    }
};

/// Every scheme the program serves, by the byte in the account header. A
/// byte two schemes claimed would be an unreachable pattern. Zero is not
/// one: an account anyone assigns to the program has zeroed data, and must
/// not read as an account of some scheme.
#[inline]
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
