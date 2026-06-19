#![forbid(unsafe_code)]
#![deny(missing_docs)]
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
//! - [`protocol`] — protocol primitives: digest, encoding constants,
//!   [`VectorAccount`] header mirror, and PDA derivation ([`find_vector_pda`]).
//! - [`scheme`] — the [`Scheme`] descriptor.
//! - [`instructions`] — generic builders ([`create_initialize_instruction`],
//!   [`create_advance_instruction`], [`create_passthrough_instruction`],
//!   close/withdraw sub-instructions).
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

pub mod artifact_serde;
pub mod branching;
pub mod inspect;
pub mod instructions;
pub mod protocol;
pub mod scheme;
pub mod schemes;
pub mod vector;

// Flat re-exports — the ergonomic surface. Names are unique across modules,
// so a glob per module can't collide.
pub use artifact_serde::*;
pub use branching::*;
pub use inspect::*;
pub use instructions::*;
pub use protocol::*;
pub use scheme::*;
#[cfg(feature = "ed25519")]
pub use schemes::ed25519::*;
#[cfg(feature = "eip191")]
pub use schemes::eip191::*;
#[cfg(feature = "falcon512")]
pub use schemes::falcon512::*;
#[cfg(feature = "hawk512")]
pub use schemes::hawk512::*;
#[cfg(feature = "secp256k1")]
pub use schemes::secp256k1::*;
pub use vector::*;
