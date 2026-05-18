//! One module per Vector program. Each owns its `Scheme`/program-ID
//! constant, identity derivation, an `initialize` builder, and (where a
//! Rust signer exists) a `sign_advance_instruction_*` helper.
//!
//! Falcon-512 and Hawk-512 are verify-only on-chain; their signing is left
//! to the caller (pair with an external signer and feed the wire-format
//! signature to [`crate::instructions::create_advance_instruction`]).

pub mod ed25519;
pub mod eip191;
pub mod falcon512;
pub mod hawk512;
pub mod secp256k1;
