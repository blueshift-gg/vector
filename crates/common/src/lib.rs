//! Shared on-chain logic for the per-scheme Vector programs.
//!
//! Every Vector program (Ed25519, EIP-191, Falcon-512, secp256k1-ECDSA,
//! Hawk-512) is a thin shell: it picks one [`SigningScheme`] and routes a
//! discriminator to the shared instruction handlers exposed here
//! ([`initialize`], [`advance`], [`close`], [`withdraw`], and the two-step
//! [`prepare`]). The handlers are the single source of truth; only signature
//! verification (the program's `SigningScheme` impl) and the dispatch table
//! vary per program.
//!
//! Single-step schemes use the canonical [`dispatch`] router verbatim.
//! Hawk-512 writes its own dispatch so its discriminator `0` can route to
//! [`initialize`] (round one) or [`prepare`] (round two) by account owner —
//! that owner check then lives only in Hawk, not in every program's
//! `initialize`.
//!
//! Because each scheme ships as its own program with its own program ID, the
//! account layout carries no scheme discriminator:
//!
//! * Account header is `nonce[32] || bump[1]` (33 bytes); the scheme's
//!   identity bytes follow at offset [`VectorAccount::HEADER_LEN`].
//! * PDA seeds are `["vector", identity_seed, &[bump]]`, where `identity_seed`
//!   is the identity itself when `IDENTITY_LEN <= 32`, else `sha256(identity)`.
#![no_std]

extern crate alloc;

mod buffer;
mod helpers;
mod instructions;
mod scheme;
mod state;

pub use scheme::{IdentitySeed, SigningScheme};
pub use state::{signer_seeds, VectorAccount};

/// Shared instruction handlers. Each is a plain function a program routes to
/// from its own discriminator match; `close` is scheme-independent, the rest
/// are generic over the program's [`SigningScheme`].
pub use instructions::{
    advance::process as advance, close::process as close,
    initialize::process as initialize, prepare::process as prepare,
    withdraw::process as withdraw,
};

use instructions::VectorInstruction;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Canonical discriminator router for single-step schemes
/// (Ed25519/EIP-191/Falcon-512/secp256k1): `0` Initialize, `1` Advance,
/// `2` Close, `3` Withdraw — where `Initialize` is a strict create.
///
/// Hawk-512 does NOT use this; it writes its own match so discriminator `0`
/// can dispatch to [`initialize`] vs [`prepare`] on the account's owner.
#[inline(always)]
pub fn dispatch<S: SigningScheme>(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (discriminator, rest) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match VectorInstruction::try_from(discriminator)? {
        VectorInstruction::InitializeVector => initialize::<S>(program_id, accounts, rest),
        VectorInstruction::AdvanceVector => advance::<S>(program_id, accounts, rest),
        VectorInstruction::CloseVector => close(program_id, accounts, rest),
        VectorInstruction::WithdrawVector => withdraw::<S>(program_id, accounts, rest),
    }
}
