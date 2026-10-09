//! One module per signing scheme. Each is a [`vector_common::SigningScheme`]
//! impl; the program routes to it by [`ID`](vector_common::SigningScheme::ID).

pub mod ed25519;
pub mod eip191;
pub mod falcon512;
pub mod mldsa44;
pub mod secp256k1;
pub mod winternitz;
pub mod xmss;
