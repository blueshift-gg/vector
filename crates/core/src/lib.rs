//! Off-chain helpers for constructing Vector program instructions and
//! computing the digests the on-chain programs verify.
//!
//! One on-chain program, [`PROGRAM_ID`], serves every signing scheme. A
//! scheme byte says which: it is the second byte of every instruction, the
//! account header is `nonce[32] || scheme[1] || bump[1]` (34 bytes), and PDA
//! seeds are `["vector", &[scheme], identity_seed]`. A [`Scheme`] bundles
//! what a client needs to use one: its scheme byte, wire signature length,
//! and identity/stored-identity lengths.
//!
//! # Layout
//!
//! - [`scheme`] — the [`Scheme`] descriptor, [`VectorAccount`] header mirror,
//!   and canonical PDA derivation ([`find_vector_pda`]).
//! - [`instructions`] — generic builders ([`create_initialize_instruction`],
//!   [`create_advance_instruction`], [`create_passthrough_instruction`],
//!   close/withdraw sub-instructions).
//! - [`digest`] — [`advance_vector_digest`], the value clients sign.
//! - [`verify`] — per-scheme offline verification of `advance` signatures
//!   ([`verify_advance_signature_ed25519`] and friends), returning the
//!   digest (= next nonce) on success.
//! - [`schemes`] — one module per program (`ed25519`, `eip191`, `falcon512`,
//!   `mldsa44`, `secp256k1`, `winternitz`, `xmss`): its `Scheme`/program-ID const, identity derivation, an
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
