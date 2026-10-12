//! One module per signing scheme: its `Scheme` constant, an `initialize`
//! builder, and a signer where this crate has one.

pub mod ed25519;
pub mod eip191;
pub mod falcon512;
pub mod mldsa44;
pub mod secp256k1;
pub mod winternitz;
pub mod xmss;
