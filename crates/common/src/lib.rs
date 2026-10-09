//! Shared on-chain logic for the Vector program.
//!
//! The program is one binary serving every signing scheme. A scheme is one
//! [`SigningScheme`] impl: how big its signature is, what it stores as the
//! signer's identity, and how it verifies. Everything else — account
//! creation, nonce advancement, CPI passthrough, close/withdraw — is the
//! shared handlers here ([`initialize`], [`advance`], [`close`],
//! [`withdraw`], [`passthrough`]), generic over the scheme.
//!
//! [`SigningScheme::ID`] says which scheme an instruction or an account is
//! for:
//!
//! * Instruction data starts `discriminator[1] || scheme[1]`.
//! * Account header is `nonce[32] || scheme[1] || bump[1]` (34 bytes); the
//!   scheme's identity bytes follow at offset [`VectorAccount::HEADER_LEN`].
//! * PDA seeds are `["vector", &[scheme], identity_seed, &[bump]]`, where
//!   `identity_seed` is the identity itself when `IDENTITY_LEN <= 32`, else
//!   `sha256(identity)`.
//!
//! Every handler that reads an account's identity checks that the account's
//! scheme is the instruction's.
#![no_std]

extern crate alloc;

mod buffer;
mod helpers;
mod instructions;
pub mod rotating;
mod scheme;
mod state;

pub use scheme::{IdentitySeed, SigningScheme};
pub use state::{signer_seeds, AdvanceOutcome, VectorAccount};

/// Shared instruction handlers. Each is a plain function a program routes to
/// from its own discriminator match; `close` is scheme-independent, the rest
/// are generic over the program's [`SigningScheme`].
pub use instructions::{
    advance::process as advance, close::process as close, initialize::process as initialize,
    passthrough::process as passthrough, withdraw::process as withdraw,
};

use instructions::VectorInstruction;
use pinocchio::{AccountView, Address, ProgramResult};

/// Canonical discriminator router, used verbatim by every scheme: `0`
/// Initialize, `1` Advance, `2` Close, `3` Withdraw, `4` Passthrough — where
/// `Initialize` is a strict create. The program has already read the
/// discriminator and the scheme byte that follows it, and chosen `S` from
/// the latter; `data` is what comes after both.
#[inline(always)]
pub fn dispatch<S: SigningScheme>(
    program_id: &Address,
    accounts: &mut [AccountView],
    discriminator: u8,
    data: &[u8],
) -> ProgramResult {
    match VectorInstruction::try_from(&discriminator)? {
        VectorInstruction::Initialize => initialize::<S>(program_id, accounts, data),
        VectorInstruction::Advance => advance::<S>(program_id, accounts, data),
        VectorInstruction::Close => close(program_id, accounts, data),
        VectorInstruction::Withdraw => withdraw::<S>(program_id, accounts, data),
        VectorInstruction::Passthrough => passthrough::<S>(program_id, accounts, data),
    }
}
