//! The Vector program's signing schemes, account layout and instruction
//! format, and the client side: building instructions, computing the
//! digests the program verifies, signing, and checking a signature offline.
//!
//! One on-chain program, [`PROGRAM_ID`], serves every signing scheme. An
//! account is named by its scheme and its identity, the key it was created
//! with: the PDA seeds are `["vector", &[scheme], sha256(identity)]`. A
//! [`Scheme`] bundles what a client needs to use one scheme: its scheme
//! byte and the lengths of its signature, identity and stored identity.
//!
//! The program builds on this crate, without its default `client` feature
//! and `no_std`: the schemes here are the code the program runs, so the
//! program ID, the account header, the discriminators and every scheme's
//! verification are the program's own, offline too.
//!
//! # Layout
//!
//! - [`scheme`] — the [`SigningScheme`](scheme::SigningScheme) contract, the
//!   [`Scheme`] descriptor, and what a key signs ([`signed`]).
//! - [`schemes`] — one module per scheme (`ed25519`, `eip191`, `falcon512`,
//!   `mldsa44`, `secp256k1`, `winternitz`, `xmss`): the identity it stores,
//!   how it verifies, its `Scheme` const, and with `client` an `initialize`
//!   builder and a signer where one exists.
//! - [`state`] — the [`VectorAccount`] header and the [`NonceAccount`].
//! - [`error`] — [`VectorError`], the program's own error codes.
//!
//! With the `client` feature (on by default):
//!
//! - [`address`] — canonical PDA derivation ([`find_vector_pda`]).
//! - [`instructions`] — generic builders ([`create_initialize_instruction`],
//!   [`create_advance_instruction`], [`create_passthrough_instruction`],
//!   close/withdraw sub-instructions).
//! - [`digest`] — [`advance_vector_digest`], the value clients sign.
//! - [`verify`] — [`verify_advance_signature`], the offline check of an
//!   `advance` signature, with the program's own scheme code. It returns
//!   the digest, the account's next nonce.
//!
//! Everything is re-exported flat at the crate root, so either style works:
//!
//! ```ignore
//! use vector_signer::{ED25519, sign_advance_instruction_ed25519};      // flat
//! use vector_signer::schemes::ed25519;                                 // structured
//! ```
#![cfg_attr(not(feature = "client"), no_std)]

pub mod error;
pub mod scheme;
pub mod schemes;
pub mod state;

#[cfg(feature = "client")]
pub mod address;
#[cfg(feature = "client")]
pub mod digest;
#[cfg(feature = "client")]
pub mod instructions;
#[cfg(feature = "client")]
pub mod verify;

solana_address::declare_id!("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV");

/// The Vector program: one program for every signing scheme.
pub use ID as PROGRAM_ID;

/// Each instruction's first byte.
pub const ADVANCE_DISCRIMINATOR: u8 = 0;
pub const PASSTHROUGH_DISCRIMINATOR: u8 = 1;
pub const INITIALIZE_DISCRIMINATOR: u8 = 2;
pub const WITHDRAW_DISCRIMINATOR: u8 = 3;
pub const CLOSE_DISCRIMINATOR: u8 = 4;
pub const INITIALIZE_NONCE_DISCRIMINATOR: u8 = 5;

// Flat re-exports — the ergonomic surface. Names are unique across modules,
// so a glob per module can't collide.
pub use error::VectorError;
pub use scheme::{signed, Scheme, NEVER_EXPIRES, SIGNED_LEN, SIGNED_PREFIX, VALID_UNTIL_LEN};
pub use schemes::{
    ed25519::*, eip191::*, falcon512::*, mldsa44::*, secp256k1::*, winternitz::*, xmss::*,
};
pub use state::{NonceAccount, VectorAccount, NONCE_TAG};

#[cfg(feature = "client")]
pub use address::*;
#[cfg(feature = "client")]
pub use digest::*;
#[cfg(feature = "client")]
pub use instructions::*;
#[cfg(feature = "client")]
pub use verify::*;
