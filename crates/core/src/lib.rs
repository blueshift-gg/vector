//! Off-chain helpers for constructing Vector program instructions and
//! computing the digests the on-chain program verifies.
//!
//! One on-chain program, [`PROGRAM_ID`], serves every signing scheme. An
//! account is named by its scheme and its identity, the key it was created
//! with: the PDA seeds are `["vector", &[scheme], sha256(identity)]`. A
//! [`Scheme`] bundles what a client needs to use one scheme: its scheme
//! byte and the lengths of its signature, identity and stored identity.
//!
//! This crate depends on the program crate, so the program ID, the account
//! header and the discriminators are the program's own.
//!
//! # Layout
//!
//! - [`scheme`] — the [`Scheme`] descriptor, the [`VectorAccount`] header,
//!   and canonical PDA derivation ([`find_vector_pda`]).
//! - [`instructions`] — generic builders ([`create_initialize_instruction`],
//!   [`create_advance_instruction`], [`create_passthrough_instruction`],
//!   close/withdraw sub-instructions).
//! - [`digest`] — [`advance_vector_digest`], the value clients sign.
//! - [`verify`] — per-scheme offline verification of `advance` signatures
//!   ([`verify_advance_signature_ed25519`] and friends), returning the
//!   digest (= next nonce) on success.
//! - [`schemes`] — one module per scheme (`ed25519`, `eip191`, `falcon512`,
//!   `mldsa44`, `secp256k1`, `winternitz`, `xmss`): its `Scheme` const, an
//!   `initialize` builder, and a signer where one exists.
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
pub mod verify;

// Flat re-exports — the ergonomic surface. Names are unique across modules,
// so a glob per module can't collide.
pub use digest::*;
pub use instructions::*;
pub use scheme::*;
pub use schemes::{
    ed25519::*, eip191::*, falcon512::*, mldsa44::*, secp256k1::*, winternitz::*, xmss::*,
};
pub use verify::*;
