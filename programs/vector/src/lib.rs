//! Vector — one program for every signing scheme.
//!
//! Instruction data starts `discriminator[1] || scheme[1]`. The scheme byte
//! picks a [`SigningScheme`] impl from [`schemes`]; the discriminator picks
//! one of the instructions shared through [`vector_common`], or one of the
//! two that only some schemes have: `Rotate` (`5`, Winternitz and XMSS) and
//! `Expand` (`6`, ML-DSA-44).
//!
//! `Advance` (`1`) takes one scheme byte per signer: see [`advance`].
#![no_std]

use pinocchio::{
    account::MAX_PERMITTED_DATA_INCREASE, entrypoint, error::ProgramError, nostd_panic_handler,
    AccountView, Address, ProgramResult, Resize,
};
use solana_address::declare_id;
use vector_common::{
    advance_message, dispatch, rotating, rotating::Rotating, SigningScheme, VectorAccount,
    ADVANCE_DISCRIMINATOR,
};

pub mod schemes;
use schemes::{
    ed25519::Ed25519, eip191::Secp256k1Eip191, falcon512::Falcon512, mldsa44::MlDsa44,
    secp256k1::Secp256k1Ecdsa, winternitz::Winternitz, xmss::Xmss,
};

entrypoint!(process_instruction);
nostd_panic_handler!();

declare_id!("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV");

/// `6`, after the shared `0..=4` and the rotating schemes' `5`.
const EXPAND_DISCRIMINATOR: u8 = 6;

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if let [ADVANCE_DISCRIMINATOR, data @ ..] = instruction_data {
        return advance(program_id, accounts, data);
    }
    let [discriminator, scheme, data @ ..] = instruction_data else {
        return Err(ProgramError::InvalidInstructionData);
    };
    let discriminator = *discriminator;
    match *scheme {
        Ed25519::ID => dispatch::<Ed25519>(program_id, accounts, discriminator, data),
        Secp256k1Eip191::ID => {
            dispatch::<Secp256k1Eip191>(program_id, accounts, discriminator, data)
        }
        Secp256k1Ecdsa::ID => dispatch::<Secp256k1Ecdsa>(program_id, accounts, discriminator, data),
        Falcon512::ID => dispatch::<Falcon512>(program_id, accounts, discriminator, data),
        MlDsa44::ID if discriminator == EXPAND_DISCRIMINATOR && data.is_empty() => {
            expand(program_id, accounts)
        }
        MlDsa44::ID => dispatch::<MlDsa44>(program_id, accounts, discriminator, data),
        Winternitz::ID => {
            rotating::dispatch::<Winternitz>(program_id, accounts, discriminator, data)
        }
        Xmss::ID => rotating::dispatch::<Xmss>(program_id, accounts, discriminator, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Verify one signature per account and install each account's next nonce.
/// Every signer signs the same message: the whole transaction with the
/// signatures cut out. `Advance` runs no CPI — pair it with `Passthrough`.
///
/// Instruction data, after the discriminator:
///
/// ```text
/// scheme_1 .. scheme_n   one byte per signer
/// sig_1 .. sig_n         each of its scheme's length
/// ```
///
/// Accounts:
/// 0..n. `[writable]` vector PDAs, one per signer
/// n.    `[]`         instructions sysvar
fn advance(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [vectors @ .., instructions_sysvar] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if vectors.is_empty() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (schemes, mut signatures) = data
        .split_at_checked(vectors.len())
        .ok_or(ProgramError::InvalidInstructionData)?;
    let message = advance_message(instructions_sysvar, schemes.len())?;

    use vector_common::advance as verify;
    for (vector, scheme) in vectors.iter_mut().zip(schemes) {
        signatures = match *scheme {
            Ed25519::ID => verify::<Ed25519>(program_id, vector, &message, signatures),
            Secp256k1Eip191::ID => {
                verify::<Secp256k1Eip191>(program_id, vector, &message, signatures)
            }
            Secp256k1Ecdsa::ID => {
                verify::<Secp256k1Ecdsa>(program_id, vector, &message, signatures)
            }
            Falcon512::ID => verify::<Falcon512>(program_id, vector, &message, signatures),
            MlDsa44::ID => verify::<MlDsa44>(program_id, vector, &message, signatures),
            Winternitz::ID => {
                verify::<Rotating<Winternitz>>(program_id, vector, &message, signatures)
            }
            Xmss::ID => verify::<Rotating<Xmss>>(program_id, vector, &message, signatures),
            _ => Err(ProgramError::InvalidInstructionData),
        }?;
    }
    // The cut-out tail must be signatures and nothing else.
    if !signatures.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(())
}

/// Grow an ML-DSA-44 account by one runtime step and fill the prepared rows
/// that now fit. Permissionless: the content is a function of the stored
/// key. Fails once the account is complete.
///
/// Accounts:
/// 0. `[writable]` vector PDA
fn expand(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [vector] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !vector.owned_by(program_id) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    VectorAccount::check_scheme::<MlDsa44>(&vector.try_borrow()?)?;
    let full = VectorAccount::account_len::<MlDsa44>();
    let old = vector.data_len();
    if old < VectorAccount::HEADER_LEN + MlDsa44::PREFIX_LEN || old >= full {
        return Err(ProgramError::InvalidAccountData);
    }
    vector.resize(full.min(old + MAX_PERMITTED_DATA_INCREASE))?;
    let mut data = vector.try_borrow_mut()?;
    let (_, identity) = data.split_at_mut(VectorAccount::HEADER_LEN);
    MlDsa44::fill(identity, old - VectorAccount::HEADER_LEN)
}
