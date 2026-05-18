//! Off-chain helpers for constructing Vector program instructions and
//! computing the digests the on-chain programs verify.
//!
//! Each signing scheme is its own on-chain program with its own program ID.
//! There is no on-chain scheme discriminator: the program ID identifies the
//! scheme, the account header is `nonce[32] || bump[1]` (33 bytes), and PDA
//! seeds are `["vector", identity_seed]`. A [`Scheme`] bundles what a client
//! needs to talk to a given program: its program ID, wire signature length,
//! and identity/stored-identity lengths.
//!
//! # Layout
//!
//! - [`scheme`] — the [`Scheme`] descriptor, [`VectorAccount`] header mirror,
//!   and canonical PDA derivation ([`find_vector_pda`]).
//! - [`instructions`] — generic builders ([`create_initialize_instruction`],
//!   [`create_advance_instruction`], close/withdraw sub-instructions).
//! - [`digest`] — [`advance_vector_digest`], the value clients sign.
//! - [`schemes`] — one module per program (`ed25519`, `eip191`, `falcon512`,
//!   `hawk512`, `secp256k1`): its `Scheme`/program-ID const, identity
//!   derivation, an `initialize` builder, and a signer where one exists.
//!
//! Everything is re-exported flat at the crate root, so either style works:
//!
//! ```ignore
//! use vector_core::{ED25519, sign_advance_instruction_ed25519};      // flat
//! use vector_core::schemes::ed25519;                                 // structured
//! ```

pub mod digest;
pub mod instructions;
pub mod scheme;
pub mod schemes;

// Flat re-exports — the ergonomic surface. Names are unique across modules,
// so a glob per module can't collide.
pub use digest::*;
pub use instructions::*;
pub use scheme::*;
pub use schemes::{
    ed25519::*, eip191::*, falcon512::*, hawk512::*, secp256k1::*,
};
